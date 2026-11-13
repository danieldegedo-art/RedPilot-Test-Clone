"""Normal operation of the Control Adapter: delegation to ``app.enterprise_controls`` with fail-open on technical unavailability.

Every control group is loaded lazily and on its own (``app.enterprise_controls.<module>``). A group is *unavailable* when
  * its module cannot be imported (missing file, syntax/import error), or
  * constructing its control object fails, or
  * a call raises something that is neither a control outcome nor input validation (a technical failure).
An unavailable group falls back to the ``FailOpenControlAdapter`` behaviour for that call, the failure is logged loudly once, and it is
visible in ``status()``. All other groups keep running normally.

NEVER treated as unavailability -- always passed through unchanged:
  * deny decisions: ``ScopeViolation`` and ``PurityViolation`` with all subclasses (TargetAccessRejected, CredentialRejected,
    ProvenanceRejected, BenchmarkLeak, QuarantinedModuleError, ConfirmationRefused, BriefRejected);
  * ``ValueError``: the documented input validation of the controls (e.g. invalid scope limits).
Stdlib only.
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import time
from typing import Any, Awaitable, Callable, Iterable, Mapping, TypeVar

from app.core.control_port.contract import ConfirmationCandidate, EvidenceArtifact, GateDecision, PurityViolation, Reason, ScopeViolation
from app.core.control_port.fallback import (
    GROUPS, FailOpenControlAdapter, OpenLedger, OpenScopePolicy, PassThroughGuard, UnavailableGate, logger,
)

T = TypeVar("T")

_MODULES = {
    "scope": "scope", "access_gate": "access_gate", "run_gate": "run_gate", "brief": "brief_validation", "brief_store": "brief_store",
    "evidence": "provenance", "confirmation": "oracle_gate", "blindness": "blindness", "perimeter": "http_perimeter",
    "allowlists": "allowlists", "quarantine": "quarantine",
}
assert set(_MODULES) == set(GROUPS)

_INTENTIONAL = (ScopeViolation, PurityViolation, ValueError)  # control outcomes / input validation: never "unavailable"
_FB = FailOpenControlAdapter  # fail-open behaviour, called explicitly (zero-arg super() does not work inside lambdas)


class _Handle:
    """Shared plumbing of the per-run handles: call the real control object, fall back (permanently for this handle) on a technical failure."""

    _group = ""

    def __init__(self, adapter: "EnterpriseControlAdapter", real: Any) -> None:
        self._adapter = adapter
        self._real = real

    def _degrade(self, where: str, exc: BaseException) -> None:
        self._adapter._degrade(self._group, f"{type(self).__name__}.{where}", exc)
        self._real = None

    def _call(self, where: str, real_fn: Callable[[Any], T], fb_fn: Callable[[], T]) -> T:
        if self._real is not None:
            try:
                return real_fn(self._real)
            except _INTENTIONAL:
                raise
            except Exception as exc:
                self._degrade(where, exc)
        return fb_fn()

    async def _acall(self, where: str, real_fn: Callable[[Any], Awaitable[T]], fb_fn: Callable[[], Awaitable[T]]) -> T:
        if self._real is not None:
            try:
                return await real_fn(self._real)
            except _INTENTIONAL:
                raise
            except Exception as exc:
                self._degrade(where, exc)
        return await fb_fn()


class _RunGuardHandle(_Handle):
    """RunGuard (A4): the real ScopeGuard plus a PassThroughGuard kept in sync for kill/start, so cancel keeps working whatever happens."""

    _group = "scope"

    def __init__(self, adapter: "EnterpriseControlAdapter", real: Any, fallback: PassThroughGuard) -> None:
        super().__init__(adapter, real)
        self._fb = fallback

    @property
    def policy(self) -> Any:
        return self._fb.policy

    @property
    def killed(self) -> bool:
        return self._fb.killed

    @property
    def kill_reason(self) -> str:
        return self._fb.kill_reason

    @property
    def requests_used(self) -> int:
        return self._call("requests_used", lambda g: g.requests_used, lambda: self._fb.requests_used)

    @property
    def remaining_budget(self) -> int:
        return self._call("remaining_budget", lambda g: g.remaining_budget, lambda: self._fb.remaining_budget)

    def start(self) -> None:
        self._fb.start()
        self._call("start", lambda g: g.start(), lambda: None)

    def kill(self, reason: str = "kill switch engaged") -> None:
        self._fb.kill(reason)
        self._call("kill", lambda g: g.kill(reason), lambda: None)

    def stop_reason(self) -> str | None:
        return self._call("stop_reason", lambda g: g.stop_reason(), lambda: self._fb.stop_reason())

    def check_url(self, url: str, probe_class: str | None = None) -> None:
        return self._call("check_url", lambda g: g.check_url(url, probe_class), lambda: self._fb.check_url(url, probe_class))

    def preflight(self, url: str, probe_class: str | None = None) -> None:
        return self._call("preflight", lambda g: g.preflight(url, probe_class), lambda: self._fb.preflight(url, probe_class))

    async def acquire(self, url: str, method: str = "GET", probe_class: str | None = None) -> None:
        return await self._acall("acquire", lambda g: g.acquire(url, method, probe_class), lambda: self._fb.acquire(url, method, probe_class))

    def stats(self) -> dict[str, Any]:
        return self._call("stats", lambda g: g.stats(), lambda: self._fb.stats())


class _LedgerHandle(_Handle):
    """Evidence ledger (A9): real EvidenceLedger plus an OpenLedger sharing the same stores, so nothing is lost when the real one degrades."""

    _group = "evidence"

    def __init__(self, adapter: "EnterpriseControlAdapter", real: Any, fallback: OpenLedger) -> None:
        super().__init__(adapter, real)
        self._fb = fallback

    @property
    def authorization_ref(self) -> str:
        return self._fb.authorization_ref

    @property
    def accepted(self) -> dict[str, EvidenceArtifact]:
        return self._fb.accepted  # same dict object as the real ledger's

    @property
    def rejected(self) -> list[dict[str, Any]]:
        return self._fb.rejected

    def protect(self, *values: str) -> None:
        return self._call("protect", lambda l: l.protect(*values), lambda: self._fb.protect(*values))

    def register_identity(self, alias: str, tenant_alias: str | None = None) -> None:
        return self._call("register_identity", lambda l: l.register_identity(alias, tenant_alias), lambda: self._fb.register_identity(alias, tenant_alias))

    def validate(self, artifact: EvidenceArtifact | None) -> list[Reason]:
        return self._call("validate", lambda l: l.validate(artifact), lambda: self._fb.validate(artifact))

    def try_admit(self, artifact: EvidenceArtifact | None) -> tuple[bool, list[Reason]]:
        return self._call("try_admit", lambda l: l.try_admit(artifact), lambda: self._fb.try_admit(artifact))

    def admit(self, artifact: EvidenceArtifact | None) -> EvidenceArtifact:
        return self._call("admit", lambda l: l.admit(artifact), lambda: self._fb.admit(artifact))

    async def flush_pending(self) -> None:
        # ZR-009: forward the durable write-through to the real ledger; on a
        # technical failure degrade this handle to the OpenLedger no-op for the
        # rest of the run (shared stores, so self.accepted stays intact).
        return await self._acall("flush_pending", lambda l: l.flush_pending(), lambda: self._fb.flush_pending())

    def is_admitted(self, artifact_id: str) -> bool:
        return self._call("is_admitted", lambda l: l.is_admitted(artifact_id), lambda: self._fb.is_admitted(artifact_id))

    def ids(self) -> list[str]:
        return self._call("ids", lambda l: l.ids(), lambda: self._fb.ids())

    def summary(self) -> dict[str, Any]:
        return self._call("summary", lambda l: l.summary(), lambda: self._fb.summary())


class _GateHandle(_Handle):
    """Confirmation gate (A11)."""

    _group = "confirmation"

    def evaluate(self, candidate: ConfirmationCandidate) -> GateDecision:
        return self._call("evaluate", lambda g: g.evaluate(candidate), lambda: UnavailableGate().evaluate(candidate))


class EnterpriseControlAdapter(FailOpenControlAdapter):
    """Delegates to app.enterprise_controls; falls back per group / per call (see module docstring)."""

    mode = "enterprise"

    def __init__(self) -> None:
        self._mods: dict[str, Any] = {}
        self._errors: dict[str, str] = {}
        self._logged: set[tuple[str, str, str]] = set()

    # -- availability ------------------------------------------------------------------------------
    def _degrade(self, group: str, where: str, exc: BaseException) -> None:
        self._errors[group] = f"{where}: {type(exc).__name__}: {exc}"
        key = (group, where, type(exc).__name__)
        if key in self._logged:
            logger.debug("control group %r still degraded (%s: %s)", group, where, exc)
            return
        self._logged.add(key)
        logger.log(
            logging.CRITICAL if group == "perimeter" else logging.ERROR,
            "FAIL-OPEN: enterprise control group %r is unavailable (%s: %s) -> its controls are NOT enforced; the system continues", group, where, exc,
            exc_info=exc,
        )

    def _module(self, group: str) -> Any:
        if group not in self._mods:
            try:
                self._mods[group] = importlib.import_module(f"app.enterprise_controls.{_MODULES[group]}")
            except Exception as exc:  # ImportError, SyntaxError, a failing import-time statement ... = the component is not usable
                self._mods[group] = None
                self._degrade(group, "import", exc)
        return self._mods[group]

    def _run(self, group: str, where: str, call: Callable[[Any], T], fallback: Callable[[], T]) -> T:
        mod = self._module(group)
        if mod is None:
            return fallback()
        try:
            return call(mod)
        except _INTENTIONAL:
            raise
        except Exception as exc:
            self._degrade(group, where, exc)
            return fallback()

    def status(self) -> dict[str, Any]:
        groups = {g: {"available": self._module(g) is not None and g not in self._errors, "error": self._errors.get(g)} for g in GROUPS}
        ok = all(v["available"] for v in groups.values())
        return {"mode": "enterprise" if ok else "degraded", "available": ok, "groups": groups}

    # -- A1-A3 run admission and scope --------------------------------------------------------------
    def validate_run_inputs(self, *, custom_headers: Mapping[str, str] | None = None, session_cookies: Mapping[str, str] | None = None,
                            endpoint_overrides: Mapping[str, Any] | None = None, extra_allowed_hosts: Iterable[str] = (),
                            integrity_brief: Mapping[str, Any] | None = None) -> None:
        kw = dict(custom_headers=custom_headers, session_cookies=session_cookies, endpoint_overrides=endpoint_overrides,
                  extra_allowed_hosts=extra_allowed_hosts, integrity_brief=integrity_brief)
        return self._run("run_gate", "validate_run_inputs", lambda m: m.validate_run_inputs(**kw), lambda: None)

    def build_scope_policy(self, environment_url: str, extra_hosts: Iterable[str] = (), **overrides: Any) -> Any:
        extra = tuple(extra_hosts)
        return self._run("scope", "build_scope_policy", lambda m: m.ScopePolicy.for_environment(environment_url, extra, **overrides),
                         lambda: _FB.build_scope_policy(self, environment_url, extra, **overrides))

    def create_run_guard(self, policy: Any, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep) -> Any:
        fallback = PassThroughGuard(policy, clock=clock, sleep=sleep)
        real = None
        mod = self._module("scope")
        if mod is not None and not isinstance(policy, OpenScopePolicy):
            try:
                real = mod.ScopeGuard(policy, clock=clock, sleep=sleep)
            except _INTENTIONAL:
                raise
            except Exception as exc:
                self._degrade("scope", "create_run_guard", exc)
        return _RunGuardHandle(self, real, fallback)

    # -- A5 probe bodies -----------------------------------------------------------------------------
    def withhold_body(self, body: Any) -> Any:
        return self._run("access_gate", "withhold_body", lambda m: m.withhold_body(body), lambda: _FB.withhold_body(self, body))

    def body_size(self, body: Any) -> int:
        return self._run("access_gate", "body_size", lambda m: m.body_size(body), lambda: _FB.body_size(self, body))

    # -- A6-A8 execution brief -----------------------------------------------------------------------
    def load_brief(self, path: str) -> dict[str, Any] | None:
        return self._run("brief_store", "load_brief", lambda m: m.load_brief_dict(path), lambda: _FB.load_brief(self, path))

    def parse_brief(self, data: Mapping[str, Any], *, env: Mapping[str, str] | None = None, tokens: Mapping[str, str] | None = None) -> Any:
        return self._run("brief", "parse_brief", lambda m: m.parse_brief(data, env=env, tokens=tokens), lambda: _FB.parse_brief(self, data, env=env, tokens=tokens))

    def host_permitted(self, base_url: str, allowed_hosts: Iterable[str]) -> bool:
        hosts = tuple(allowed_hosts)
        return self._run("brief", "host_permitted", lambda m: m.host_permitted(base_url, hosts), lambda: _FB.host_permitted(self, base_url, hosts))

    # -- A9-A13 evidence, confirmation, blindness ----------------------------------------------------
    def new_evidence_ledger(self, *, authorization_ref: str, approved_identity_aliases: Iterable[str] = (), approved_tenant_aliases: Iterable[str] = ()) -> Any:
        real = None
        mod = self._module("evidence")
        if mod is not None:
            try:
                real = mod.EvidenceLedger(authorization_ref=authorization_ref, approved_identity_aliases=approved_identity_aliases,
                                          approved_tenant_aliases=approved_tenant_aliases)
            except _INTENTIONAL:
                raise
            except Exception as exc:
                self._degrade("evidence", "new_evidence_ledger", exc)
        fallback = OpenLedger(authorization_ref=authorization_ref, accepted=getattr(real, "accepted", None), rejected=getattr(real, "rejected", None))
        return _LedgerHandle(self, real, fallback)

    def new_confirmation_gate(self, ledger: Any) -> Any:
        real = None
        mod = self._module("confirmation")
        if mod is not None:
            try:
                real = mod.ConfirmationGate(ledger)
            except _INTENTIONAL:
                raise
            except Exception as exc:
                self._degrade("confirmation", "new_confirmation_gate", exc)
        return _GateHandle(self, real)

    def scrub_headers(self, headers: Mapping[str, Any] | None) -> tuple[dict[str, str], list[str]]:
        return self._run("blindness", "scrub_headers", lambda m: m.scrub_headers(headers), lambda: _FB.scrub_headers(self, headers))

    def scrub_body(self, body: Any) -> tuple[Any, list[str]]:
        return self._run("blindness", "scrub_body", lambda m: m.scrub_body(body), lambda: _FB.scrub_body(self, body))

    def filter_label_channel(self, records: Any) -> tuple[Any, int]:
        return self._run("blindness", "filter_label_channel", lambda m: m.filter_label_channel(records), lambda: _FB.filter_label_channel(self, records))

    # -- A14-A16 API perimeter, provider/provenance rules, quarantine ---------------------------------
    def install_http_perimeter(self, app: Any, *, allowed_hostnames: Iterable[str], extra_allowed_origins: Iterable[str], allow_null_origin: bool,
                               api_token: str | None) -> bool:
        def real(m: Any) -> bool:
            app.add_middleware(m.LocalOnlyGuardMiddleware, allowed_hostnames=allowed_hostnames, extra_allowed_origins=extra_allowed_origins,
                               allow_null_origin=allow_null_origin, api_token=api_token)
            return True

        return self._run("perimeter", "install_http_perimeter", real,
                         lambda: _FB.install_http_perimeter(self, app, allowed_hostnames=allowed_hostnames, extra_allowed_origins=extra_allowed_origins,
                                                            allow_null_origin=allow_null_origin, api_token=api_token))

    def is_provider_facing_operation(self, operation: str) -> bool:
        return self._run("allowlists", "is_provider_facing_operation", lambda m: operation in m.PROVIDER_FACING_OPERATIONS,
                         lambda: _FB.is_provider_facing_operation(self, operation))

    def is_allowed_observed_via(self, value: str) -> bool:
        return self._run("allowlists", "is_allowed_observed_via", lambda m: value in m.ALLOWED_OBSERVED_VIA, lambda: _FB.is_allowed_observed_via(self, value))

    def refuse_in_pure_mode(self, module_name: str) -> None:
        return self._run("quarantine", "refuse_in_pure_mode", lambda m: m.refuse_in_pure_mode(module_name), lambda: _FB.refuse_in_pure_mode(self, module_name))
