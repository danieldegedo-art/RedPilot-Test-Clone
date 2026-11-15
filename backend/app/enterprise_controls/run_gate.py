"""Run-start enforcement of the credential + target-access allowlists (mandate: 'Target credential allowlist').

``validate_run_inputs`` is called by ``TestRunner.__init__`` (every run, however started) and by the API's ``start_run`` (to answer
HTTP 400 early with the exact reasons). It inspects ONLY what the operator hands the system -- custom headers (which carry the merged
session cookies), endpoint overrides, manual routes and extra allowed hosts -- and refuses anything that is not customer-level
synthetic-test material or not a customer-facing surface. Reasons never contain the offending value. Stdlib only.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from app.core.control_port.contract import CredentialRejected, Reason, TargetAccessRejected
from app.enterprise_controls.access_gate import AccessGate
from app.enterprise_controls.credentials import check_headers, scan_for_forbidden


def validate_run_inputs(
    *,
    custom_headers: Mapping[str, str] | None = None,
    session_cookies: Mapping[str, str] | None = None,
    endpoint_overrides: Mapping[str, Any] | None = None,
    extra_allowed_hosts: Iterable[str] = (),
    integrity_brief: Mapping[str, Any] | None = None,
) -> None:
    """Raise CredentialRejected / TargetAccessRejected on the first class of violation; return None when clean."""
    reasons: list[Reason] = []
    reasons.extend(check_headers(custom_headers, session_cookies))
    gate = AccessGate()
    for operation, spec in (endpoint_overrides or {}).items():
        path = getattr(spec, "path", None) or (spec.get("path") if isinstance(spec, Mapping) else None) or ""
        decision = gate.check_path(str(path))
        if not decision.allowed:
            reasons.append(Reason("endpoint_override_internal_surface", f"endpoint_overrides.{operation}", "override points at an internal/admin/debug/hidden-test surface (grey-box route list)"))
    if integrity_brief is not None:
        reasons.extend(scan_for_forbidden(dict(integrity_brief), location="integrity_brief"))
    if reasons:
        raise CredentialRejected(reasons)
    gate.validate_allowed_hosts([h for h in extra_allowed_hosts if h])  # raises TargetAccessRejected on a non-customer-facing host


__all__ = ["validate_run_inputs", "CredentialRejected", "TargetAccessRejected"]
