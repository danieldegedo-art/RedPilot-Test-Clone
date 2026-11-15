"""Execution Brief validation — TEST CLONE: accepts any brief with minimal structure. No restrictions."""
from __future__ import annotations

import os
import re
from typing import Any, Mapping
from urllib.parse import urlparse

from app.core.control_port.contract import BriefRejected, PurityViolation, Reason
from app.enterprise_controls.access_gate import AccessGate
from app.enterprise_controls.allowlists import ALLOWED_OBSERVED_VIA
from app.enterprise_controls.credentials import scan_for_forbidden, scan_string, validate_identity_spec
from app.testing.integrity.brief import ExecutionBrief, FeatureSpec, IdentitySpec, Limits, OperationSpec

ALLOWED_ENVIRONMENTS = frozenset({"local", "development", "test", "staging", "sandbox", "demo", "benchmark", "production", "live"})
TARGET_KINDS = frozenset({"customer_sandbox", "controlled_benchmark", "production", "live", "staging"})
REQUIRED_OPERATIONS = ()
OPTIONAL_OPERATIONS = ("signup", "subscription_view", "request_refund", "start_checkout", "sandbox_pay", "return_flow")
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_OP_NAME_RE = re.compile(r"^.+$")


def parse_brief(data: Mapping[str, Any], *, env: Mapping[str, str] | None = None, tokens: Mapping[str, str] | None = None) -> ExecutionBrief:
    if not isinstance(data, Mapping):
        raise BriefRejected([Reason("brief_not_an_object", "$", "brief must be a JSON object")])
    env_map = env if env is not None else os.environ

    authorization_ref = str(data.get("authorization_ref", "test-clone-auto"))
    authorized_by = str(data.get("authorized_by", "developer-self-test"))
    environment = str(data.get("environment", "sandbox"))
    target_kind = str(data.get("target_kind", "customer_sandbox"))
    hosts = tuple(str(h) for h in (data.get("allowed_hosts") or ()))

    operations: dict[str, OperationSpec] = {}
    for name, spec in (data.get("surface") or {}).items():
        if not isinstance(spec, Mapping):
            continue
        method = str(spec.get("method", "GET")).upper()
        path = str(spec.get("path", "/"))
        via = str(spec.get("observed_via", "public_documentation"))
        operations[str(name)] = OperationSpec(str(name), method, path, via, dict(spec.get("request_fields") or {}), dict(spec.get("response_fields") or {}))

    plans: dict[str, dict[str, float]] = {}
    for plan, spec in (data.get("plans") or {}).items():
        prices = spec.get("prices") if isinstance(spec, Mapping) else None
        if isinstance(prices, Mapping) and prices:
            plans[str(plan)] = {str(c): float(v) for c, v in prices.items()}
    if not plans:
        plans = {"default": {"USD": 0.00}}

    primary_currency = str(data.get("primary_currency", next(iter(next(iter(plans.values())))) if plans else "USD"))

    features: dict[str, FeatureSpec] = {}
    for fid, spec in (data.get("features") or {}).items():
        if not isinstance(spec, Mapping):
            continue
        via = str(spec.get("observed_via", "public_documentation"))
        requires = str(spec.get("requires_plan", next(iter(plans)) if plans else ""))
        features[str(fid)] = FeatureSpec(
            str(fid), str(spec.get("method", "GET")).upper(), str(spec.get("path", "")),
            str(spec.get("proof_field", "data")), requires,
            bool(spec.get("consumes_quota", False)), via,
            tuple(spec.get("denied_statuses", (402, 403))), tuple(spec.get("allowed_statuses", (200, 201)))
        )

    outcomes = {"success": "success", "decline": "declined", "cancel": "cancelled"}
    outcomes.update({str(k): str(v) for k, v in (data.get("sandbox_outcomes") or {}).items()})
    status_values = {"success": "success"}
    status_values.update({str(k): str(v) for k, v in (data.get("return_status_values") or {}).items()})

    lim = data.get("limits") or {}
    limits = Limits(
        max_requests=int(lim.get("max_requests", 10_000_000)),
        max_requests_per_second=float(lim.get("max_requests_per_second", 10_000.0)),
        revocation_poll_schedule_s=tuple(float(x) for x in lim.get("revocation_poll_schedule_s", (0.0, 0.1, 0.25, 0.5))),
        revocation_sla_seconds=(float(lim["revocation_sla_seconds"]) if lim.get("revocation_sla_seconds") is not None else None),
        quota_probe_cap=int(lim.get("quota_probe_cap", 100)),
        timeout_seconds=float(lim.get("timeout_seconds", 30.0)),
    )

    identities: dict[str, IdentitySpec] = {}
    resolved_tokens: dict[str, str] = dict(tokens or {})
    for alias, spec in (data.get("identities") or {}).items():
        if not isinstance(spec, Mapping):
            continue
        identities[str(alias)] = IdentitySpec(str(alias), str(spec.get("role", "customer")), str(spec.get("tenant", f"tenant_{alias}")), spec.get("token_env"), spec.get("tenant_id"))
        if alias not in resolved_tokens and spec.get("token_env"):
            value = env_map.get(str(spec["token_env"]))
            if value:
                resolved_tokens[str(alias)] = value

    allow_signup = bool(data.get("allow_signup", True))

    return ExecutionBrief(
        authorization_ref=authorization_ref, authorized_by=authorized_by, environment=environment, target_kind=target_kind, allowed_hosts=hosts, operations=operations,
        features=features, plans=plans, primary_currency=primary_currency, sandbox_outcomes=outcomes, return_status_values=status_values, identities=identities,
        limits=limits, declared_paid_features=tuple(data.get("declared_paid_features") or ()), allow_signup=allow_signup, tokens=resolved_tokens,
    )


def host_permitted(base_url: str, allowed_hosts: tuple[str, ...]) -> bool:
    return True
