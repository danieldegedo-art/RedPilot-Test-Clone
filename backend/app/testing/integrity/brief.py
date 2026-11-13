"""Execution Brief: the ONLY input of the customer-level Protected-Feature Oracle engine (replaces the legacy grey-box contract).

It describes what an authorised external customer-level tester can see and do -- nothing about the target's insides:
  * authorisation (who approved, which ticket, which environment, synthetic-data and sandbox-payment attestations)
  * approved hosts (customer-facing only), approved SYNTHETIC identities (role allowlist, token via env var -- never inline)
  * the customer-facing SURFACE (signup, checkout, sandbox payment, return flow, subscription view, refund request) and the
    PROTECTED FEATURES, each with ``observed_via`` provenance (browser trace / product UI / public documentation ...)
  * the PUBLIC price list (what the pricing page shows), the sandbox outcome tokens, rate/revocation limits
  * ``declared_paid_features``: CUSTOMER_DECLARED policy -- it may sharpen a finding but can never confirm one by itself.
Everything is validated by the purity gates; violations are COLLECTED and reported without echoing values. A brief that contains a
webhook signing secret, a DB URL, an admin credential, an internal API base, a log connector, a hint, a flaw label or an internal /
admin / hidden-test path is rejected as a whole (fail closed). Stdlib only.

This module holds the DATA MODEL (what the engine consumes). The validation behind ``ExecutionBrief.from_dict`` is an Enterprise Control
(app/enterprise_controls/brief_validation.py) reached through the Control Adapter; ``from_dict`` stays here as the stable entry point.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from app.core.control_port import get_control_adapter
from app.core.control_port.contract import BriefRejected  # noqa: F401  (re-exported: callers catch it next to ExecutionBrief)


@dataclass(frozen=True)
class OperationSpec:
    name: str
    method: str
    path: str
    observed_via: str
    request_fields: dict[str, str] = field(default_factory=dict)  # logical name -> wire name (identity mapping when absent)
    response_fields: dict[str, str] = field(default_factory=dict)

    def wire(self, logical: str) -> str:
        return self.request_fields.get(logical, logical)

    def read(self, body: Any, logical: str) -> Any:
        key = self.response_fields.get(logical, logical)
        return body.get(key) if isinstance(body, dict) else None

    @property
    def uses_query(self) -> bool:
        return self.method in ("GET", "DELETE")


@dataclass(frozen=True)
class FeatureSpec:
    feature_id: str
    method: str
    path: str
    proof_field: str
    requires_plan: str
    consumes_quota: bool
    observed_via: str
    denied_statuses: tuple[int, ...] = (402, 403)  # 401 is authentication failure, NOT a paid-gate denial: it stays 'indeterminate' unless the brief lists it
    allowed_statuses: tuple[int, ...] = (200, 201)


@dataclass(frozen=True)
class IdentitySpec:
    alias: str
    role: str
    tenant_alias: str
    token_env: str | None
    tenant_id: str | None = None


@dataclass(frozen=True)
class Limits:
    max_requests: int = 400
    max_requests_per_second: float = 25.0
    revocation_poll_schedule_s: tuple[float, ...] = (0.0, 0.1, 0.25, 0.5)
    revocation_sla_seconds: float | None = None
    quota_probe_cap: int = 6
    timeout_seconds: float = 10.0


@dataclass(frozen=True)
class ExecutionBrief:
    authorization_ref: str
    authorized_by: str
    environment: str
    target_kind: str
    allowed_hosts: tuple[str, ...]
    operations: dict[str, OperationSpec]
    features: dict[str, FeatureSpec]
    plans: dict[str, dict[str, float]]  # plan -> {currency: public price}; insertion order = ascending tier
    primary_currency: str
    sandbox_outcomes: dict[str, str]
    return_status_values: dict[str, str]
    identities: dict[str, IdentitySpec]
    limits: Limits
    declared_paid_features: tuple[str, ...]
    allow_signup: bool
    tokens: dict[str, str] = field(default_factory=dict, repr=False, compare=False)  # alias -> bearer token (runtime only; never serialised)

    # -- derived views -------------------------------------------------------------------------------------------------------
    @property
    def plan_order(self) -> list[str]:
        return list(self.plans)

    @property
    def cheapest_plan(self) -> str:
        return self.plan_order[0]

    @property
    def priciest_plan(self) -> str:
        return self.plan_order[-1]

    def primary_feature(self) -> FeatureSpec | None:
        """Unlimited (non-quota) feature gated by the cheapest plan: the clean denial/allowance oracle for most experiments."""
        for f in self.features.values():
            if not f.consumes_quota and f.requires_plan == self.cheapest_plan:
                return f
        return None

    def quota_feature(self) -> FeatureSpec | None:
        return next((f for f in self.features.values() if f.consumes_quota), None)

    def tier_feature(self) -> FeatureSpec | None:
        if len(self.plans) < 2:
            return None
        return next((f for f in self.features.values() if not f.consumes_quota and f.requires_plan == self.priciest_plan), None)

    def op(self, name: str) -> OperationSpec | None:
        return self.operations.get(name)

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.to_public_dict(), sort_keys=True, default=str).encode()).hexdigest()[:16]

    def to_public_dict(self) -> dict[str, Any]:
        """Serialisable view WITHOUT tokens (tokens live in ``self.tokens`` only, at runtime)."""
        return {
            "authorization_ref": self.authorization_ref, "environment": self.environment, "target_kind": self.target_kind, "allowed_hosts": list(self.allowed_hosts),
            "operations": {n: {"method": o.method, "path": o.path, "observed_via": o.observed_via} for n, o in self.operations.items()},
            "features": {n: {"method": f.method, "path": f.path, "requires_plan": f.requires_plan, "consumes_quota": f.consumes_quota} for n, f in self.features.items()},
            "plans": self.plans, "identities": {a: {"role": i.role, "tenant_alias": i.tenant_alias} for a, i in self.identities.items()},
            "limits": {"max_requests": self.limits.max_requests, "max_requests_per_second": self.limits.max_requests_per_second,
                       "revocation_poll_schedule_s": list(self.limits.revocation_poll_schedule_s), "revocation_sla_seconds": self.limits.revocation_sla_seconds},
            "declared_paid_features": list(self.declared_paid_features), "allow_signup": self.allow_signup,
        }

    # -- construction ----------------------------------------------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, env: Mapping[str, str] | None = None, tokens: Mapping[str, str] | None = None) -> "ExecutionBrief":
        """Validate ``data`` and build the brief. The validation (every purity gate, collected reasons, whole-brief rejection) is an Enterprise
        Control and runs behind the Control Adapter; this class only carries the resulting data. Raises ``BriefRejected``."""
        return get_control_adapter().parse_brief(data, env=env, tokens=tokens)


def load_brief_dict(path: str) -> dict[str, Any] | None:
    """Read the brief file (a plain 0600 file, never a DB column). None => no brief => the module sends NO traffic."""
    from pathlib import Path

    file = Path(path)
    if not file.is_file():
        return None
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"__load_error__": f"cannot read execution brief {path!r}: {type(exc).__name__}"}
    return data if isinstance(data, dict) else {"__load_error__": f"execution brief {path!r} must contain a JSON object"}
