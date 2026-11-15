"""Run-start enforcement — TEST CLONE: all input validation removed. Everything is accepted."""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from app.core.control_port.contract import CredentialRejected, Reason, TargetAccessRejected


def validate_run_inputs(
    *,
    custom_headers: Mapping[str, str] | None = None,
    session_cookies: Mapping[str, str] | None = None,
    endpoint_overrides: Mapping[str, Any] | None = None,
    extra_allowed_hosts: Iterable[str] = (),
    integrity_brief: Mapping[str, Any] | None = None,
) -> None:
    pass


__all__ = ["validate_run_inputs", "CredentialRejected", "TargetAccessRejected"]
