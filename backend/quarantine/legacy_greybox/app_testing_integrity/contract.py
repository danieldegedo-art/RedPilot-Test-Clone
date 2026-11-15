"""Customer-declared AUTHORIZATION contract for the Oracle Engine.

The Oracle Engine is not a passive scanner: to test payment integrity it CREATES
payments, issues refunds and sends unsigned/forged-status webhook events. That is
only acceptable inside an environment the customer has explicitly authorised for
exactly this. The contract is how that authorisation becomes a machine-checked
precondition instead of an assumption -- and it is the ONLY way the module ever
sends a request: no contract, no traffic (the module then only reports what it
could not test).

What is validated (all violations are collected, not just the first):
  * ``vocabulary``            must be a supported one (today: ``reference``, the route/field
                              vocabulary of tests/verification_infrastructure/entitlement_target.py)
  * ``vocabulary_confirmed``  must be exactly ``true``: the customer confirms the target implements that route/field
                              vocabulary and that calling those routes with synthetic data is safe. A GUESS must
                              never be allowed to fire mutating requests at an authorised-but-unconfirmed target
  * ``environment``           sandbox | staging. ``production`` is refused outright: these oracles
                              write to the target and forge events; no attestation makes that safe
  * ``authorized_by`` / ``scope_reference``   non-empty (who authorised, under which ticket/scope)
  * ``attested_synthetic_data`` must be exactly ``true``: every identity, tenant and payment the
                              engine creates is synthetic; no real customer data is touched
  * ``allowed_hosts``         valid host allowlist; the run's target host must be inside it
  * ``webhook_secret``        optional SANDBOX signing secret, only with ``webhook_secret_is_sandbox: true``
  * no live-mode credential (``sk_live_...``) anywhere in the document -- fingerprints are reported, never values

Stdlib-only (plus the local redaction/scope helpers).
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from app.testing.redaction import find_live_credentials
from app.testing.scope_guard import ScopePolicy

SUPPORTED_VOCABULARIES: tuple[str, ...] = ("reference",)
ALLOWED_ENVIRONMENTS: tuple[str, ...] = ("sandbox", "staging")


class ContractError(ValueError):
    """The contract is invalid; ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = list(errors)


@dataclass(frozen=True)
class IntegrityContract:
    vocabulary: str
    environment: str
    authorized_by: str
    scope_reference: str
    attested_synthetic_data: bool
    allowed_hosts: tuple[str, ...]
    vocabulary_confirmed: bool = True
    expected_gated: bool | None = None
    webhook_secret: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "IntegrityContract":
        if not isinstance(raw, dict):
            raise ContractError(["the integrity contract must be a JSON object"])
        if "__load_error__" in raw:
            raise ContractError([str(raw["__load_error__"])])
        errors: list[str] = []

        vocabulary = raw.get("vocabulary")
        if vocabulary not in SUPPORTED_VOCABULARIES:
            errors.append(f"vocabulary must be one of {list(SUPPORTED_VOCABULARIES)}, got {vocabulary!r}")

        if raw.get("vocabulary_confirmed") is not True:
            errors.append("vocabulary_confirmed must be exactly true: confirm the target implements the declared route/field vocabulary and that calling those routes with synthetic data is safe")

        environment = raw.get("environment")
        if environment == "production":
            errors.append("environment 'production' is never permitted: the oracles create payments, issue refunds and send unsigned events")
        elif environment not in ALLOWED_ENVIRONMENTS:
            errors.append(f"environment must be one of {list(ALLOWED_ENVIRONMENTS)}, got {environment!r}")

        for key in ("authorized_by", "scope_reference"):
            value = raw.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{key} must be a non-empty string (who authorised this test, under which scope/ticket)")

        if raw.get("attested_synthetic_data") is not True:
            errors.append("attested_synthetic_data must be exactly true: every identity, tenant and payment the engine creates is synthetic")

        hosts = raw.get("allowed_hosts")
        parsed_hosts: tuple[str, ...] = ()
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) for h in hosts):
            errors.append("allowed_hosts must be a non-empty list of host strings")
        else:
            try:
                ScopePolicy(allowed_hosts=tuple(hosts))
                parsed_hosts = tuple(hosts)
            except ValueError as exc:
                errors.append(f"allowed_hosts invalid: {exc}")

        expected_gated = raw.get("expected_gated")
        if expected_gated is not None and not isinstance(expected_gated, bool):
            errors.append("expected_gated must be true, false or null")

        secret = raw.get("webhook_secret")
        if secret is not None:
            if not isinstance(secret, str) or not secret.strip():
                errors.append("webhook_secret must be a non-empty string when present")
            if raw.get("webhook_secret_is_sandbox") is not True:
                errors.append("webhook_secret requires webhook_secret_is_sandbox: true (only a SANDBOX/test-mode signing secret may ever be declared)")

        live = find_live_credentials(raw)
        if live:
            errors.append(f"live-mode API credential detected (fingerprint {', '.join(live)}): remove it; only sandbox credentials are permitted")

        if errors:
            raise ContractError(errors)
        return cls(
            vocabulary=str(vocabulary), environment=str(environment), authorized_by=str(raw["authorized_by"]).strip(),
            scope_reference=str(raw["scope_reference"]).strip(), attested_synthetic_data=True, allowed_hosts=parsed_hosts,
            vocabulary_confirmed=True, expected_gated=expected_gated, webhook_secret=secret,
        )

    def permits_host(self, base_url: str) -> bool:
        return ScopePolicy(allowed_hosts=self.allowed_hosts).host_allowed(base_url)

    def to_public_dict(self) -> dict[str, Any]:
        """Safe to persist/export: the sandbox secret is reduced to a boolean."""
        return {
            "vocabulary": self.vocabulary, "environment": self.environment, "authorized_by": self.authorized_by,
            "scope_reference": self.scope_reference, "attested_synthetic_data": self.attested_synthetic_data,
            "allowed_hosts": list(self.allowed_hosts), "vocabulary_confirmed": self.vocabulary_confirmed, "expected_gated": self.expected_gated,
            "webhook_secret_declared": self.webhook_secret is not None,
        }

    def fingerprint(self) -> str:
        """Stable identity of THIS contract (secret excluded) for experiment memory / regression keys."""
        canonical = json.dumps({**self.to_public_dict(), "allowed_hosts": sorted(self.allowed_hosts)}, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
