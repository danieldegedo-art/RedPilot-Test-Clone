"""The COLD FLOOR gate for OPERATION COLD CROWN -- stricter than the four-rule grey-box floor.

The mission's cold floor: the engine is given EXACTLY ONE thing per target -- a cold domain (base
URL) -- and nothing else. This gate asserts that, fail-closed, as a precondition of every cold run
and records a per-run attestation for the scorecard. It is scorer-side plumbing: it inspects the
exact brief dict the engine will receive, and the realised run (internal-route hits).

Cold floor (each asserted here):
  1. DOMAIN ONLY. The brief declares NO surface, NO features, NO plans, NO identities, NO field
     names, NO roles -- only: allowed_hosts (the cold domain), allow_signup, the RoE attestation,
     primary_currency, limits. (surface/features/plans/identities must all be empty.)
  2. NO source / blueprints / credentials (the four-rule forbidden-key set, reused).
  3. NO internal/admin/hidden surface reached at runtime (internal_route_hits must be 0; the
     ScopeGuard independently blocks those paths, and the target's internal routes are honeypots).
  4. BOTTOM-UP identities only (no admin/root identity declared; the engine mints its own ordinary
     synthetic tenants through the product's public sign-up).

This is STRICTER than the shipped four-rule floor: rule 1 additionally forbids ANY handed-in
surface/spec/field-names/roles, which the grey-box floor permitted (observed_via public_api_reference).
The engine must discover the surface by authorized use of the product itself (the root bootstrap
catalog), never from a handed-in spec. Stdlib only.
"""
from __future__ import annotations

from typing import Any

_INTERNAL_PREFIXES = ("/internal", "/admin", "/__", "/_debug")
_ADMIN_ROLES = {"admin", "administrator", "root", "superuser", "superadmin", "owner", "staff", "operator", "system"}
_FORBIDDEN_KEYS = {
    "source", "source_code", "repo", "repository", "src", "codebase",
    "topology", "architecture", "infra", "infrastructure", "network_map",
    "internal_hosts", "internal_services", "db_url", "database_url",
    "service_mesh", "k8s", "kubernetes", "vpc", "subnet_map", "blueprint",
}
# Keys that would constitute a handed-in surface/spec and so break the cold floor.
_SURFACE_KEYS = ("surface", "operations", "features", "plans", "identities",
                 "declared_paid_features", "discovery", "routes", "openapi", "spec")


class ColdFloorViolation(Exception):
    """Raised (fail closed) when a run would violate the cold floor."""


def cold_brief_dict(base_url: str) -> dict[str, Any]:
    """The ONLY input the cold engine receives: the domain + RoE attestation + allow_signup +
    currency + limits. NO surface, NO features, NO plans, NO identities. The engine must discover
    everything else by authorized use of the product."""
    host = base_url.split("//", 1)[1]
    return {
        "authorization_ref": "COLD-CROWN-AUTH", "authorized_by": "qa-gauntlet-owner",
        "environment": "benchmark", "target_kind": "controlled_benchmark",
        "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [host],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1, 0.3], "quota_probe_cap": 6, "timeout_seconds": 10},
        # explicitly empty -- the cold floor requires it, and this gate asserts it
        "surface": {}, "features": {}, "plans": {}, "identities": {},
    }


def _flat_keys(obj: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(str(k)); keys.extend(_flat_keys(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            keys.extend(_flat_keys(v))
    return keys


def precheck(brief: dict[str, Any]) -> dict[str, Any]:
    """Assert the cold floor against the brief BEFORE the run. Returns the pre-run attestation;
    raises ColdFloorViolation (fail closed) on any violation."""
    reasons: list[str] = []

    # rule 1: domain only -- no handed-in surface of any kind.
    for key in _SURFACE_KEYS:
        val = brief.get(key)
        if val:  # non-empty dict/list/str => a surface was handed in => not cold
            reasons.append(f"rule1_surface_handed_in: {key!r} is non-empty ({len(val)}) -- cold brief must declare no surface")
    if not brief.get("allowed_hosts"):
        reasons.append("rule1_no_domain: a cold run needs exactly the base URL (allowed_hosts)")
    if not brief.get("allow_signup"):
        reasons.append("rule1_no_signup: the engine must mint its own ordinary identities bottom-up via public sign-up")

    # rule 2: no source/blueprint/credential keys anywhere in the brief.
    present = sorted(k for k in _flat_keys(brief) if k.lower() in _FORBIDDEN_KEYS)
    if present:
        reasons.append(f"rule2_forbidden_keys: {present}")

    # rule 4: no admin identity declared (identities must be empty anyway; belt and suspenders).
    for alias, ident in (brief.get("identities") or {}).items():
        if str((ident or {}).get("role", "")).lower() in _ADMIN_ROLES:
            reasons.append(f"rule4_admin_identity: {alias}")

    if reasons:
        raise ColdFloorViolation("; ".join(reasons))
    return {
        "rule1_domain_only": "pass(static)",
        "rule2_no_source_blueprints_credentials": "pass",
        "rule3_no_internal_access": "pending(runtime)",
        "rule4_bottom_up_identities_only": "pass",
        "handed_in": "base_url + RoE attestation + allow_signup + currency + limits ONLY",
        "surface_declared": {k: len(brief.get(k) or {}) for k in ("surface", "features", "plans", "identities")},
    }


def postcheck(attestation: dict[str, Any], internal_route_hits: int) -> dict[str, Any]:
    """Complete rule 3 with the realised run: the engine must have touched NO internal route."""
    if internal_route_hits:
        raise ColdFloorViolation(f"rule3_internal_route_hit_at_runtime: {internal_route_hits}")
    out = dict(attestation)
    out["rule3_no_internal_access"] = "pass"
    out["internal_route_hits"] = internal_route_hits
    out["cold_floor_satisfied"] = True
    return out
