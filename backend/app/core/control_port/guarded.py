"""Kernel-level guard around the OPTIONAL plug-in adapter (``app/control_adapter/adapter.py``).

The plug-in can be missing, damaged or only partly intact (a truncated file that still imports, a deleted method, a deleted helper class).
This guard makes the Main System independent of that: every interface method calls the plug-in and, on any technical failure, falls back to the
``FailOpenControlAdapter`` for that call (logged once, visible in ``status()``). Deny decisions (``ScopeViolation``, ``PurityViolation`` and
subclasses) and ``ValueError`` (input validation) are never treated as failures. Handles returned by the plug-in (guard, ledger, gate) are
checked for their full surface before they are handed to the Main System. Stdlib only.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable, Iterable, Mapping

from app.core.control_port.contract import PurityViolation, ScopeViolation
from app.core.control_port.fallback import FailOpenControlAdapter, logger

INTERFACE_METHODS = (
    "status", "validate_run_inputs", "build_scope_policy", "create_run_guard", "withhold_body", "body_size", "load_brief", "parse_brief", "host_permitted",
    "new_evidence_ledger", "build_artifact", "new_confirmation_gate", "scrub_headers", "scrub_body", "filter_label_channel", "install_http_perimeter",
    "is_provider_facing_operation", "is_allowed_observed_via", "refuse_in_pure_mode",
)
GUARD_SURFACE = ("policy", "killed", "kill_reason", "requests_used", "remaining_budget", "start", "kill", "stop_reason", "check_url", "preflight", "acquire", "stats")
LEDGER_SURFACE = ("authorization_ref", "accepted", "rejected", "protect", "register_identity", "validate", "try_admit", "admit", "flush_pending", "is_admitted", "ids", "summary")
GATE_SURFACE = ("evaluate",)
_INTENTIONAL = (ScopeViolation, PurityViolation, ValueError)


class GuardedControlAdapter:
    """Plug-in adapter + per-method fail-open (see module docstring)."""

    mode = "enterprise"

    def __init__(self, plugin: Any) -> None:
        self._plugin = plugin
        self._fallback = FailOpenControlAdapter()
        self._degraded: dict[str, str] = {}
        self._logged: set[tuple[str, str]] = set()
        missing = [m for m in INTERFACE_METHODS if not callable(getattr(plugin, m, None))]
        for m in missing:
            self._degraded[m] = "missing in the control adapter plug-in"
        if missing:
            logger.error("FAIL-OPEN: the control adapter plug-in lacks %s -> these calls are NOT enforced; the system continues", missing)

    def _degrade(self, name: str, exc: BaseException) -> None:
        self._degraded[name] = f"{type(exc).__name__}: {exc}"
        key = (name, type(exc).__name__)
        if key in self._logged:
            logger.debug("control adapter plug-in call %r still degraded (%s: %s)", name, type(exc).__name__, exc)
            return
        self._logged.add(key)
        logger.error("FAIL-OPEN: control adapter plug-in call %r failed (%s: %s) -> not enforced for this call; the system continues", name, type(exc).__name__, exc, exc_info=exc)

    def _call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        try:
            return getattr(self._plugin, name)(*args, **kwargs)
        except _INTENTIONAL:
            raise
        except Exception as exc:
            self._degrade(name, exc)
            return getattr(self._fallback, name)(*args, **kwargs)

    def _factory(self, name: str, surface: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
        try:
            handle = getattr(self._plugin, name)(*args, **kwargs)
            missing = [s for s in surface if not hasattr(handle, s)]
            if missing:
                raise TypeError(f"the plug-in handle lacks {missing}")
            return handle
        except _INTENTIONAL:
            raise
        except Exception as exc:
            self._degrade(name, exc)
            return getattr(self._fallback, name)(*args, **kwargs)

    # -- interface ---------------------------------------------------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        st = self._call("status")
        if self._degraded:
            st = {**st, "mode": "degraded", "available": False, "adapter_degraded": dict(sorted(self._degraded.items()))}
        return st

    def validate_run_inputs(self, *, custom_headers: Mapping[str, str] | None = None, session_cookies: Mapping[str, str] | None = None,
                            endpoint_overrides: Mapping[str, Any] | None = None, extra_allowed_hosts: Iterable[str] = (),
                            integrity_brief: Mapping[str, Any] | None = None) -> None:
        return self._call("validate_run_inputs", custom_headers=custom_headers, session_cookies=session_cookies, endpoint_overrides=endpoint_overrides,
                          extra_allowed_hosts=extra_allowed_hosts, integrity_brief=integrity_brief)

    def build_scope_policy(self, environment_url: str, extra_hosts: Iterable[str] = (), **overrides: Any) -> Any:
        return self._call("build_scope_policy", environment_url, tuple(extra_hosts), **overrides)

    def create_run_guard(self, policy: Any, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep) -> Any:
        return self._factory("create_run_guard", GUARD_SURFACE, policy, clock=clock, sleep=sleep)

    def withhold_body(self, body: Any) -> Any:
        return self._call("withhold_body", body)

    def body_size(self, body: Any) -> int:
        return self._call("body_size", body)

    def load_brief(self, path: str) -> dict[str, Any] | None:
        return self._call("load_brief", path)

    def parse_brief(self, data: Mapping[str, Any], *, env: Mapping[str, str] | None = None, tokens: Mapping[str, str] | None = None) -> Any:
        return self._call("parse_brief", data, env=env, tokens=tokens)

    def host_permitted(self, base_url: str, allowed_hosts: Iterable[str]) -> bool:
        return self._call("host_permitted", base_url, tuple(allowed_hosts))

    def new_evidence_ledger(self, *, authorization_ref: str, approved_identity_aliases: Iterable[str] = (), approved_tenant_aliases: Iterable[str] = ()) -> Any:
        return self._factory("new_evidence_ledger", LEDGER_SURFACE, authorization_ref=authorization_ref,
                             approved_identity_aliases=tuple(approved_identity_aliases), approved_tenant_aliases=tuple(approved_tenant_aliases))

    def build_artifact(self, **fields: Any) -> Any:
        return self._call("build_artifact", **fields)

    def new_confirmation_gate(self, ledger: Any) -> Any:
        return self._factory("new_confirmation_gate", GATE_SURFACE, ledger)

    def scrub_headers(self, headers: Mapping[str, Any] | None) -> tuple[dict[str, str], list[str]]:
        return self._call("scrub_headers", headers)

    def scrub_body(self, body: Any) -> tuple[Any, list[str]]:
        return self._call("scrub_body", body)

    def filter_label_channel(self, records: Any) -> tuple[Any, int]:
        return self._call("filter_label_channel", records)

    def install_http_perimeter(self, app: Any, *, allowed_hostnames: Iterable[str], extra_allowed_origins: Iterable[str], allow_null_origin: bool, api_token: str | None) -> bool:
        return self._call("install_http_perimeter", app, allowed_hostnames=tuple(allowed_hostnames), extra_allowed_origins=tuple(extra_allowed_origins),
                          allow_null_origin=allow_null_origin, api_token=api_token)

    def is_provider_facing_operation(self, operation: str) -> bool:
        return self._call("is_provider_facing_operation", operation)

    def is_allowed_observed_via(self, value: str) -> bool:
        return self._call("is_allowed_observed_via", value)

    def refuse_in_pure_mode(self, module_name: str) -> None:
        return self._call("refuse_in_pure_mode", module_name)
