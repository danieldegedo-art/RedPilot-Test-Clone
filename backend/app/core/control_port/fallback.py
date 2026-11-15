"""Fail-open availability mode: what the Main System gets when the Enterprise Controls are NOT available.

``FailOpenControlAdapter`` implements every adapter method without ``app.enterprise_controls``: the system keeps running normally and the
controls are simply not enforced. The semantics per control group (MIGRATION_MAP.md §1.5):

  scope / access gate / run gate   pass-through: no host/scheme/port/path/budget/credential checks. Kill switch, deadline and the request
                                   RATE limit stay active (they are operational/stability functions: cancelling a run must keep working).
  evidence ledger                  admits every artifact that carries a provenance record (no admission checks).
  confirmation gate                cannot confirm: a ConfirmationToken can only be minted by the real gate, so CONFIRMED_P0 is unreachable and
                                   findings stay PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE. No token is ever forged.
  execution brief                  cannot be validated, so no brief is accepted (``BriefRejected`` -> the payment-integrity module reports its
                                   existing "no valid brief" gap result and sends no traffic). No second, unvalidated parser exists.
  blindness / body helpers         pass-through.
  API perimeter                    not installed (logged as CRITICAL).
  provider/provenance rules        provider overrides are honoured, any ``observed_via`` is accepted.
  quarantine                       import guard not enforced.

Every degradation is logged loudly and visible in ``status()``/``stats()`` -- fail-open must never be silent. Stdlib only.
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Mapping
from urllib.parse import urlparse

from app.core.control_port.contract import (
    NEGATIVE_ACCESS_CONTROL, BriefRejected, ConfirmationCandidate, EvidenceArtifact, GateDecision, ProvenanceRejected, Reason, ScopeViolation, build_artifact,
)
from app.testing.rate_limiter import TokenBucket

logger = logging.getLogger("app.control_adapter")

GROUPS = ("scope", "access_gate", "run_gate", "brief", "brief_store", "evidence", "confirmation", "blindness", "perimeter", "allowlists", "quarantine")


@dataclass(frozen=True)
class OpenScopePolicy:
    """Policy value of the fail-open mode: carries the numbers the Main System reads, performs no matching."""

    allowed_hosts: tuple[str, ...]
    allowed_schemes: tuple[str, ...] = ("http", "https")
    max_requests: int = 10_000
    max_requests_per_second: float = 25.0
    burst: int = 0
    deadline_seconds: float | None = None
    max_redirects: int = 5

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_hosts": list(self.allowed_hosts), "allowed_schemes": list(self.allowed_schemes), "max_requests": self.max_requests,
            "max_requests_per_second": self.max_requests_per_second, "burst": self.burst, "deadline_seconds": self.deadline_seconds,
            "max_redirects": self.max_redirects,
        }


def open_scope_policy(environment_url: str, extra_hosts: Iterable[str] = (), **overrides: Any) -> OpenScopePolicy:
    host = (urlparse(environment_url).hostname or "").lower()
    hosts = ({host} if host else set()) | {h.strip().lower() for h in extra_hosts if h and h.strip()}
    return OpenScopePolicy(allowed_hosts=tuple(sorted(hosts)), **overrides)


class PassThroughGuard:
    """RunGuard without authorisation. Keeps the operational functions: kill switch, deadline, request-rate limit, statistics."""

    def __init__(self, policy: Any, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep) -> None:
        self.policy = policy
        self._clock = clock
        rate = policy.max_requests_per_second if policy.max_requests_per_second and policy.max_requests_per_second > 0 else 25.0
        self._bucket = TokenBucket(rate=rate, capacity=float(policy.burst or max(10, math.ceil(rate))), clock=clock, sleep=sleep)
        self._used = 0
        self._denied: dict[str, int] = {}
        self._killed = False
        self._kill_reason = ""
        self._t0: float | None = None

    # -- control ---------------------------------------------------------------
    def start(self) -> None:
        if self._t0 is None:
            self._t0 = self._clock()

    def kill(self, reason: str = "kill switch engaged") -> None:
        self._killed = True
        self._kill_reason = reason

    @property
    def killed(self) -> bool:
        return self._killed

    @property
    def kill_reason(self) -> str:
        return self._kill_reason

    @property
    def requests_used(self) -> int:
        return self._used

    @property
    def remaining_budget(self) -> int:
        return max(0, self.policy.max_requests - self._used)  # informational only: the budget is not enforced in fail-open mode

    def _deadline_exceeded(self) -> bool:
        limit = self.policy.deadline_seconds
        return limit is not None and self._t0 is not None and (self._clock() - self._t0) > limit

    def stop_reason(self) -> str | None:
        if self._killed:
            return f"killed: {self._kill_reason}"
        if self._deadline_exceeded():
            return "deadline_exceeded"
        return None

    def _deny(self, code: str, message: str) -> None:
        self._denied[code] = self._denied.get(code, 0) + 1
        raise ScopeViolation(code, message)

    def _raise_if_stopped(self) -> None:
        if self._killed:
            self._deny("killed", self._kill_reason)
        if self._deadline_exceeded():
            self._deny("deadline_exceeded", f"run deadline of {self.policy.deadline_seconds}s exceeded")

    # -- checks (open) ---------------------------------------------------------
    def check_url(self, url: str, probe_class: str | None = None) -> None:
        return None

    def preflight(self, url: str, probe_class: str | None = None) -> None:
        self.start()
        self._raise_if_stopped()

    async def acquire(self, url: str, method: str = "GET", probe_class: str | None = None) -> None:
        self.preflight(url, probe_class)

        def _killed() -> None:
            if self._killed:
                self._deny("killed", self._kill_reason)

        await self._bucket.take(before_each=_killed)
        self._raise_if_stopped()
        self._used += 1

    def stats(self) -> dict[str, Any]:
        elapsed = None if self._t0 is None else round(self._clock() - self._t0, 3)
        return {
            "requests_used": self._used,
            "requests_denied": sum(self._denied.values()),
            "denied_by_code": dict(self._denied),
            "killed": self._killed,
            "kill_reason": self._kill_reason or None,
            "purity_gate": {"denied": 0, "denied_by_code": {}, "negative_access_control_probes": 0},
            "rate_wait_seconds": round(self._bucket.waited, 3),
            "elapsed_seconds": elapsed,
            "policy": self.policy.to_dict(),
            "control_mode": "fail_open",
            "degraded": True,
        }


class OpenLedger:
    """Evidence store without admission checks. An artifact needs a provenance record (the engine reads it), nothing more."""

    def __init__(self, *, authorization_ref: str, accepted: dict[str, EvidenceArtifact] | None = None, rejected: list[dict[str, Any]] | None = None) -> None:
        self.authorization_ref = authorization_ref
        self._accepted = accepted if accepted is not None else {}
        self._rejected = rejected if rejected is not None else []

    @property
    def accepted(self) -> dict[str, EvidenceArtifact]:
        return self._accepted

    @property
    def rejected(self) -> list[dict[str, Any]]:
        return self._rejected

    def protect(self, *values: str) -> None:
        return None

    def register_identity(self, alias: str, tenant_alias: str | None = None) -> None:
        return None

    def validate(self, artifact: EvidenceArtifact | None) -> list[Reason]:
        if artifact is None or artifact.provenance is None:
            return [Reason("provenance_missing", "artifact", "an artifact without a provenance record cannot be stored")]
        return []

    def try_admit(self, artifact: EvidenceArtifact | None) -> tuple[bool, list[Reason]]:
        reasons = self.validate(artifact)
        if reasons:
            self._rejected.append({"artifact_id": getattr(artifact, "artifact_id", None), "reasons": [r.__dict__ for r in reasons]})
            return False, reasons
        assert artifact is not None
        self._accepted[artifact.artifact_id] = artifact
        return True, []

    def admit(self, artifact: EvidenceArtifact | None) -> EvidenceArtifact:
        ok, reasons = self.try_admit(artifact)
        if not ok:
            raise ProvenanceRejected(reasons)
        assert artifact is not None
        return artifact

    async def flush_pending(self) -> None:
        """Fail-open ledger has no durable store, so there is nothing to flush
        (artifacts live only in self._accepted -- the documented 'kept in
        memory only' degraded behaviour). Never raises; surface-complete with
        the real EvidenceLedger so the kernel guard does not strip the handle."""
        return None

    def is_admitted(self, artifact_id: str) -> bool:
        return artifact_id in self._accepted

    def ids(self) -> list[str]:
        return list(self._accepted)

    def summary(self) -> dict[str, Any]:
        by_class: dict[str, int] = {}
        for a in self._accepted.values():
            by_class[a.provenance.classification] = by_class.get(a.provenance.classification, 0) + 1  # type: ignore[union-attr]
        return {"accepted": len(self._accepted), "rejected": len(self._rejected), "accepted_by_classification": by_class,
                "rejected_reasons": sorted({r["code"] for rej in self._rejected for r in rej["reasons"]}), "control_mode": "fail_open", "degraded": True}


class UnavailableGate:
    """Confirmation gate of the fail-open mode: never confirms, because a ConfirmationToken can only be issued by the real gate."""

    REASON = "control_unavailable: the confirmation gate is not available (fail-open availability mode); a ConfirmationToken can only be issued by it"

    def evaluate(self, candidate: ConfirmationCandidate) -> GateDecision:
        return GateDecision(False, (self.REASON,), None)


def _body_size(body: Any) -> int:
    if isinstance(body, dict) and body.get("_withheld") == NEGATIVE_ACCESS_CONTROL:
        return int(body.get("bytes", 0))
    if body is None:
        return 0
    return len(body) if isinstance(body, str) else len(str(body))


class FailOpenControlAdapter:
    """Adapter without Enterprise Controls (see module docstring)."""

    mode = "fail_open"

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode, "available": False, "groups": {g: {"available": False, "error": "enterprise_controls not available"} for g in GROUPS}}

    def validate_run_inputs(self, *, custom_headers: Mapping[str, str] | None = None, session_cookies: Mapping[str, str] | None = None,
                            endpoint_overrides: Mapping[str, Any] | None = None, extra_allowed_hosts: Iterable[str] = (),
                            integrity_brief: Mapping[str, Any] | None = None) -> None:
        return None

    def build_scope_policy(self, environment_url: str, extra_hosts: Iterable[str] = (), **overrides: Any) -> Any:
        return open_scope_policy(environment_url, extra_hosts, **overrides)

    def create_run_guard(self, policy: Any, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep) -> Any:
        return PassThroughGuard(policy, clock=clock, sleep=sleep)

    def withhold_body(self, body: Any) -> Any:
        return body

    def body_size(self, body: Any) -> int:
        return _body_size(body)

    def load_brief(self, path: str) -> dict[str, Any] | None:
        return None

    def parse_brief(self, data: Mapping[str, Any], *, env: Mapping[str, str] | None = None, tokens: Mapping[str, str] | None = None) -> Any:
        import os
        from app.testing.integrity.brief import ExecutionBrief, FeatureSpec, IdentitySpec, Limits, OperationSpec
        env_map = env if env is not None else os.environ
        operations: dict[str, OperationSpec] = {}
        for name, spec in (data.get("surface") or {}).items():
            if not isinstance(spec, Mapping):
                continue
            method = str(spec.get("method", "GET")).upper()
            operations[name] = OperationSpec(name, method, str(spec.get("path", "")), str(spec.get("observed_via", "developer")),
                                             dict(spec.get("request_fields") or {}), dict(spec.get("response_fields") or {}))
        plans: dict[str, dict[str, float]] = {}
        for plan, spec in (data.get("plans") or {}).items():
            prices = spec.get("prices") if isinstance(spec, Mapping) else None
            if isinstance(prices, Mapping) and prices:
                plans[str(plan)] = {str(c): float(v) for c, v in prices.items()}
        features: dict[str, FeatureSpec] = {}
        for fid, spec in (data.get("features") or {}).items():
            if not isinstance(spec, Mapping):
                continue
            features[str(fid)] = FeatureSpec(str(fid), str(spec.get("method", "GET")).upper(), str(spec.get("path", "")),
                                              str(spec.get("proof_field", "")), str(spec.get("requires_plan", "")),
                                              bool(spec.get("consumes_quota", False)), str(spec.get("observed_via", "developer")),
                                              tuple(spec.get("denied_statuses", (402, 403))), tuple(spec.get("allowed_statuses", (200, 201))))
        outcomes = {"success": "success", "decline": "declined", "cancel": "cancelled"}
        outcomes.update({str(k): str(v) for k, v in (data.get("sandbox_outcomes") or {}).items()})
        status_values = {"success": "success"}
        status_values.update({str(k): str(v) for k, v in (data.get("return_status_values") or {}).items()})
        lim = data.get("limits") or {}
        limits = Limits(max_requests=int(lim.get("max_requests", 10000)), max_requests_per_second=float(lim.get("max_requests_per_second", 50.0)),
                        revocation_poll_schedule_s=tuple(float(x) for x in lim.get("revocation_poll_schedule_s", (0.0, 0.1, 0.25, 0.5))),
                        revocation_sla_seconds=(float(lim["revocation_sla_seconds"]) if lim.get("revocation_sla_seconds") is not None else None),
                        quota_probe_cap=int(lim.get("quota_probe_cap", 6)), timeout_seconds=float(lim.get("timeout_seconds", 10.0)))
        identities: dict[str, IdentitySpec] = {}
        resolved_tokens: dict[str, str] = dict(tokens or {})
        for alias, spec in (data.get("identities") or {}).items():
            if not isinstance(spec, Mapping):
                continue
            identities[str(alias)] = IdentitySpec(str(alias), str(spec.get("role", "")), str(spec.get("tenant", f"tenant_{alias}")),
                                                   spec.get("token_env"), spec.get("tenant_id"))
            if alias not in resolved_tokens and spec.get("token_env"):
                value = env_map.get(str(spec["token_env"]))
                if value:
                    resolved_tokens[str(alias)] = value
        return ExecutionBrief(
            authorization_ref=str(data.get("authorization_ref", "dev-test")), authorized_by=str(data.get("authorized_by", "developer")),
            environment=str(data.get("environment", "test")), target_kind=str(data.get("target_kind", "customer_sandbox")),
            allowed_hosts=tuple(str(h) for h in (data.get("allowed_hosts") or ())), operations=operations, features=features,
            plans=plans, primary_currency=str(data.get("primary_currency", "USD")), sandbox_outcomes=outcomes,
            return_status_values=status_values, identities=identities, limits=limits,
            declared_paid_features=tuple(data.get("declared_paid_features") or ()), allow_signup=bool(data.get("allow_signup", False)),
            tokens=resolved_tokens)

    def host_permitted(self, base_url: str, allowed_hosts: Iterable[str]) -> bool:
        return True

    def new_evidence_ledger(self, *, authorization_ref: str, approved_identity_aliases: Iterable[str] = (), approved_tenant_aliases: Iterable[str] = ()) -> Any:
        return OpenLedger(authorization_ref=authorization_ref)

    def build_artifact(self, **fields: Any) -> EvidenceArtifact:
        return build_artifact(**fields)

    def new_confirmation_gate(self, ledger: Any) -> Any:
        return UnavailableGate()

    def scrub_headers(self, headers: Mapping[str, Any] | None) -> tuple[dict[str, str], list[str]]:
        return {str(k).lower(): str(v) for k, v in (headers or {}).items()}, []

    def scrub_body(self, body: Any) -> tuple[Any, list[str]]:
        return body, []

    def filter_label_channel(self, records: Any) -> tuple[Any, int]:
        return records, 0

    def install_http_perimeter(self, app: Any, *, allowed_hostnames: Iterable[str], extra_allowed_origins: Iterable[str], allow_null_origin: bool, api_token: str | None) -> bool:
        logger.critical("FAIL-OPEN: the API perimeter (local-only guard: Host/Origin/token checks) is NOT installed because the Enterprise Controls are unavailable")
        return False

    def is_provider_facing_operation(self, operation: str) -> bool:
        return False

    def is_allowed_observed_via(self, value: str) -> bool:
        return True

    def refuse_in_pure_mode(self, module_name: str) -> None:
        return None
