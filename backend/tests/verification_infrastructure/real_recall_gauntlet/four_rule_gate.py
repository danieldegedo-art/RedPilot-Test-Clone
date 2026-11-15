"""The four-rule HARD FLOOR gate for the authorized GREY-BOX posture.

The ADD-ON REVISION requires that the four rules be asserted as preconditions of EVERY run and
that the run FAIL CLOSED if any would be violated. This module is that gate. It is scorer-side
plumbing: it inspects the brief dict the engine will receive (brief + URL only) and the realised
run (internal-route hits), and returns a per-run attestation recorded in the scorecard.

The four rules (grey-box changes OBSERVABILITY/ACCESS, never the attack primitives):
  1. No internal access      -- only surfaces a normal AUTHORIZED user can reach; no internal/
                                undocumented services, logs, DBs, queues, buses.
  2. No source code          -- behaviour + the vendor's PUBLISHED API spec/docs only.
  3. No network blueprints    -- no topology/architecture/infra maps.
  4. No administrative creds   -- the engine's synthetic identities are ordinary users/tenants/
                                low roles; privilege work is strictly bottom-up.
"""
from __future__ import annotations

from typing import Any

_INTERNAL_PREFIXES = ("/internal", "/admin", "/__", "/_debug")
_ADMIN_ROLES = {"admin", "administrator", "root", "superuser", "superadmin", "owner", "staff", "operator", "system"}
# Source / blueprint smells that must never appear in a grey-box brief (fail closed if present).
_FORBIDDEN_KEYS = {
    "source", "source_code", "repo", "repository", "src", "codebase",        # rule 2
    "topology", "architecture", "infra", "infrastructure", "network_map",     # rule 3
    "internal_hosts", "internal_services", "db_url", "database_url",          # rule 1/3
    "service_mesh", "k8s", "kubernetes", "vpc", "subnet_map", "blueprint",
}


class FourRuleViolation(Exception):
    """Raised (fail closed) when a run would violate the hard floor."""


def _paths(brief: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for coll in ("surface", "operations", "features"):
        for spec in (brief.get(coll) or {}).values():
            if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                out.append(spec["path"])
    return out


def precheck(brief: dict[str, Any]) -> dict[str, Any]:
    """Assert rules 1-4 against the brief BEFORE the run. Returns the pre-run attestation; raises
    FourRuleViolation (fail closed) on any violation."""
    reasons: list[str] = []

    # rule 1 (static): no declared internal/admin/hidden path.
    bad_paths = [p for p in _paths(brief) if p.startswith(_INTERNAL_PREFIXES)]
    if bad_paths:
        reasons.append(f"rule1_internal_path_declared: {bad_paths}")

    # rule 2 + 3: no source/blueprint keys anywhere in the brief (the engine gets brief + URL only).
    present = sorted(k for k in _flat_keys(brief) if k.lower() in _FORBIDDEN_KEYS)
    if present:
        reasons.append(f"rule2_3_forbidden_keys: {present}")

    # rule 4: every declared identity is an ordinary (non-admin) role.
    for alias, ident in (brief.get("identities") or {}).items():
        role = str((ident or {}).get("role", "")).lower()
        if role in _ADMIN_ROLES:
            reasons.append(f"rule4_admin_identity: {alias}={role}")

    if reasons:
        raise FourRuleViolation("; ".join(reasons))
    return {
        "rule1_no_internal_access": "pass(static)",
        "rule2_no_source": "pass",
        "rule3_no_network_blueprints": "pass",
        "rule4_no_admin_credentials": "pass",
        "declared_identities": sorted((brief.get("identities") or {}).keys()) or ["engine-signed-up-ordinary-tenants"],
        "target_kind": brief.get("target_kind"),
    }


def postcheck(attestation: dict[str, Any], internal_route_hits: int) -> dict[str, Any]:
    """Complete rule 1 with the realised run: the engine must have touched NO internal route.
    Fail closed if it did."""
    if internal_route_hits:
        raise FourRuleViolation(f"rule1_internal_route_hit_at_runtime: {internal_route_hits}")
    out = dict(attestation)
    out["rule1_no_internal_access"] = "pass"
    out["internal_route_hits"] = internal_route_hits
    out["grey_box_within_four_rules"] = True
    return out


def _flat_keys(obj: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(str(k))
            keys.extend(_flat_keys(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            keys.extend(_flat_keys(v))
    return keys
