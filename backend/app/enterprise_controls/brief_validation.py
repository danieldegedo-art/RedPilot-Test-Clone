"""Validation of the customer-level Execution Brief (audit F-37–F-43, F-25, F-41): the Enterprise Control behind ``ExecutionBrief.from_dict``.

Moved from ``app/testing/integrity/brief.py`` (``ExecutionBrief.from_dict``) and ``app/testing/modules/payment_integrity.py`` (``host_permitted``);
the validation logic is unchanged. Everything is validated by the purity gates; violations are COLLECTED and reported without echoing values. A
brief that contains a webhook signing secret, a DB URL, an admin credential, an internal API base, a log connector, a hint, a flaw label or an
internal / admin / hidden-test path is rejected as a whole (fail closed). This is the ONLY module that resolves identity tokens from the
environment (by variable NAME; see purity audit ``env_reads``). The data classes (ExecutionBrief, ...) stay in the core
(``app.testing.integrity.brief``); the Main System reaches this function only through the Control Port (``parse_brief``). Stdlib only.
"""
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

ALLOWED_ENVIRONMENTS = frozenset({"local", "development", "test", "staging", "sandbox", "demo", "benchmark"})
TARGET_KINDS = frozenset({"customer_sandbox", "controlled_benchmark"})
REQUIRED_OPERATIONS = ("start_checkout", "sandbox_pay", "return_flow")
OPTIONAL_OPERATIONS = ("signup", "subscription_view", "request_refund")
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_OP_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")


def parse_brief(data: Mapping[str, Any], *, env: Mapping[str, str] | None = None, tokens: Mapping[str, str] | None = None) -> ExecutionBrief:
    reasons: list[Reason] = []
    if not isinstance(data, Mapping):
        raise BriefRejected([Reason("brief_not_an_object", "$", "brief must be a JSON object")])
    reasons.extend(scan_for_forbidden(dict(data), location="brief"))
    env_map = env if env is not None else os.environ

    def need(key: str, kind: type = str) -> Any:
        value = data.get(key)
        if not isinstance(value, kind) or (kind is str and not value.strip()):
            reasons.append(Reason("brief_field_missing", f"brief.{key}", f"required field {key!r} missing or wrong type"))
            return kind()
        return value

    authorization_ref, authorized_by = need("authorization_ref"), need("authorized_by")
    environment = need("environment")
    if environment and environment not in ALLOWED_ENVIRONMENTS:
        reasons.append(Reason("brief_environment_not_allowed", "brief.environment", f"environment must be one of {sorted(ALLOWED_ENVIRONMENTS)}; production is refused in this release"))
    target_kind = data.get("target_kind", "customer_sandbox")
    if target_kind not in TARGET_KINDS:
        reasons.append(Reason("brief_target_kind_invalid", "brief.target_kind", f"must be one of {sorted(TARGET_KINDS)}"))
    for attest in ("attested_synthetic_data", "attested_sandbox_payments"):
        if data.get(attest) is not True:
            reasons.append(Reason("brief_attestation_missing", f"brief.{attest}", "explicit attestation (true) required: only synthetic data and sandbox payments are ever used"))
    hosts = tuple(str(h) for h in (data.get("allowed_hosts") or ()))
    if not hosts:
        reasons.append(Reason("brief_hosts_missing", "brief.allowed_hosts", "at least one approved customer-facing host is required"))
    else:
        try:
            AccessGate().validate_allowed_hosts(hosts)
        except PurityViolation as violation:
            reasons.append(Reason(violation.code, "brief.allowed_hosts", violation.message))
    gate = AccessGate()

    def provenance(where: str, spec: Mapping[str, Any]) -> str:
        via = str(spec.get("observed_via", ""))
        if via not in ALLOWED_OBSERVED_VIA:
            reasons.append(Reason("brief_observed_via_invalid", where, f"observed_via must be one of {sorted(ALLOWED_OBSERVED_VIA)} (a route learned from internal docs/source/admin tooling is grey-box and refused)"))
        decision = gate.check_path(str(spec.get("path", "")))
        if not decision.allowed:
            reasons.append(Reason(decision.code or "purity_path", where + ".path", "path names an internal/admin/debug/hidden-test surface"))
        return via

    operations: dict[str, OperationSpec] = {}
    for name, spec in (data.get("surface") or {}).items():
        where = f"brief.surface.{name}"
        if not _OP_NAME_RE.match(str(name)) or not isinstance(spec, Mapping):
            reasons.append(Reason("brief_operation_invalid", where, "operation must be a named object")); continue
        method = str(spec.get("method", "")).upper()
        if method not in _METHODS or not str(spec.get("path", "")).startswith("/"):
            reasons.append(Reason("brief_operation_invalid", where, "method/path invalid")); continue
        operations[name] = OperationSpec(name, method, str(spec["path"]), provenance(where, spec), dict(spec.get("request_fields") or {}), dict(spec.get("response_fields") or {}))
    for required in REQUIRED_OPERATIONS:
        if required not in operations:
            reasons.append(Reason("brief_operation_missing", f"brief.surface.{required}", f"required customer-facing operation {required!r} not declared"))

    plans: dict[str, dict[str, float]] = {}
    for plan, spec in (data.get("plans") or {}).items():
        prices = spec.get("prices") if isinstance(spec, Mapping) else None
        if not isinstance(prices, Mapping) or not prices:
            reasons.append(Reason("brief_plan_invalid", f"brief.plans.{plan}", "plan needs a non-empty public 'prices' map {currency: amount}")); continue
        plans[str(plan)] = {str(c): float(v) for c, v in prices.items()}
    if not plans:
        reasons.append(Reason("brief_plans_missing", "brief.plans", "at least one plan with a public price is required"))
    primary_currency = str(data.get("primary_currency") or (next(iter(next(iter(plans.values())))) if plans else "USD"))

    features: dict[str, FeatureSpec] = {}
    for fid, spec in (data.get("features") or {}).items():
        where = f"brief.features.{fid}"
        if not isinstance(spec, Mapping):
            reasons.append(Reason("brief_feature_invalid", where, "feature must be an object")); continue
        via = provenance(where, spec)
        requires = str(spec.get("requires_plan", ""))
        if plans and requires not in plans:
            reasons.append(Reason("brief_feature_plan_unknown", where + ".requires_plan", f"requires_plan {requires!r} is not a declared plan"))
        if not spec.get("proof_field"):
            reasons.append(Reason("brief_feature_no_proof_field", where + ".proof_field", "a protected-feature oracle needs a proof_field: the response key whose presence proves the feature was actually used"))
        features[str(fid)] = FeatureSpec(str(fid), str(spec.get("method", "GET")).upper(), str(spec.get("path", "")), str(spec.get("proof_field", "")), requires,
                                          bool(spec.get("consumes_quota", False)), via,
                                          tuple(spec.get("denied_statuses", (402, 403))), tuple(spec.get("allowed_statuses", (200, 201))))
    if not features:
        reasons.append(Reason("brief_features_missing", "brief.features", "at least one server-enforced protected feature must be declared (no oracle => no test)"))

    outcomes = {"success": "success", "decline": "declined", "cancel": "cancelled"}
    outcomes.update({str(k): str(v) for k, v in (data.get("sandbox_outcomes") or {}).items()})
    status_values = {"success": "success"}
    status_values.update({str(k): str(v) for k, v in (data.get("return_status_values") or {}).items()})

    lim = data.get("limits") or {}
    limits = Limits(
        max_requests=int(lim.get("max_requests", 400)), max_requests_per_second=float(lim.get("max_requests_per_second", 25.0)),
        revocation_poll_schedule_s=tuple(float(x) for x in lim.get("revocation_poll_schedule_s", (0.0, 0.1, 0.25, 0.5))),
        revocation_sla_seconds=(float(lim["revocation_sla_seconds"]) if lim.get("revocation_sla_seconds") is not None else None),
        quota_probe_cap=int(lim.get("quota_probe_cap", 6)), timeout_seconds=float(lim.get("timeout_seconds", 10.0)),
    )
    if not (1 <= limits.max_requests <= 5000) or not (0 < limits.max_requests_per_second <= 50):
        reasons.append(Reason("brief_limits_out_of_range", "brief.limits", "max_requests must be 1..5000 and max_requests_per_second in (0, 50]: tests are low-volume by contract"))
    if len(limits.revocation_poll_schedule_s) > 8 or any(x < 0 or x > 60 for x in limits.revocation_poll_schedule_s):
        reasons.append(Reason("brief_limits_out_of_range", "brief.limits.revocation_poll_schedule_s", "at most 8 polls, each offset within 0..60 s"))

    identities: dict[str, IdentitySpec] = {}
    resolved_tokens: dict[str, str] = dict(tokens or {})
    for alias, spec in (data.get("identities") or {}).items():
        if not isinstance(spec, Mapping):
            reasons.append(Reason("identity_invalid", f"identities.{alias}", "identity must be an object")); continue
        reasons.extend(validate_identity_spec(str(alias), spec))
        identities[str(alias)] = IdentitySpec(str(alias), str(spec.get("role", "")), str(spec.get("tenant", f"tenant_{alias}")), spec.get("token_env"), spec.get("tenant_id"))
        if alias not in resolved_tokens and spec.get("token_env"):
            value = env_map.get(str(spec["token_env"]))
            if value:
                resolved_tokens[str(alias)] = value
    allow_signup = bool(data.get("allow_signup", False))
    if allow_signup and "signup" not in operations:
        reasons.append(Reason("brief_signup_not_declared", "brief.surface.signup", "allow_signup requires a customer-facing 'signup' operation"))
    if not allow_signup and len(identities) < 2:
        reasons.append(Reason("brief_identities_insufficient", "brief.identities", "without signup the brief must approve a pool of >= 2 synthetic identities"))
    for name in data.get("declared_paid_features") or ():
        if name not in features:
            reasons.append(Reason("brief_declared_feature_unknown", "brief.declared_paid_features", f"{name!r} is not a declared feature"))
    for alias, token in resolved_tokens.items():
        reasons.extend(scan_string(token, f"token:{alias}"))
    if reasons:
        raise BriefRejected(reasons)
    return ExecutionBrief(
        authorization_ref=authorization_ref, authorized_by=authorized_by, environment=environment, target_kind=target_kind, allowed_hosts=hosts, operations=operations,
        features=features, plans=plans, primary_currency=primary_currency, sandbox_outcomes=outcomes, return_status_values=status_values, identities=identities,
        limits=limits, declared_paid_features=tuple(data.get("declared_paid_features") or ()), allow_signup=allow_signup, tokens=resolved_tokens,
    )


def host_permitted(base_url: str, allowed_hosts: tuple[str, ...]) -> bool:
    parsed = urlparse(base_url)
    host, port = (parsed.hostname or "").lower(), parsed.port
    for entry in allowed_hosts:
        e = entry.strip().lower()
        if e.startswith("*."):
            if host.endswith(e[1:]):
                return True
            continue
        e_host, _, e_port = e.partition(":") if e.count(":") == 1 else (e, "", "")
        if host == e_host and (not e_port or (port is not None and str(port) == e_port)):
            return True
    return False
