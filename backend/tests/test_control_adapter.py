"""Control Adapter: normal operation (delegation), fail-open availability mode for ALL control groups, partial/mid-run failure, boundary.

Runs under pytest AND as a plain script. Stdlib only: no network, no httpx. The Enterprise Controls are made "unavailable" by blocking their
modules in ``sys.modules`` (an import then raises ImportError), exactly like a missing or broken optional component.
"""
from __future__ import annotations

import asyncio
import contextlib
import copy
import inspect
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.core.control_port import (  # noqa: E402
    ConfirmationCandidate, ConfirmationRefused, CredentialRejected, EvidenceClass, OracleObservation, QuarantinedModuleError, ScopeViolation,
    BriefRejected, KIND_FEATURE_USE, get_control_adapter, reset_control_adapter,
)
from app.control_adapter.adapter import EnterpriseControlAdapter  # noqa: E402  (the optional plug-in: tested directly, never imported by the Main System)
from app.core.control_port.fallback import GROUPS, FailOpenControlAdapter, PassThroughGuard  # noqa: E402
from app.core.control_port.guarded import INTERFACE_METHODS, GuardedControlAdapter  # noqa: E402
from app.core.control_port.interface import ControlAdapter, RunGuard  # noqa: E402
from app.testing.integrity.brief import ExecutionBrief  # noqa: E402
from app.testing.integrity.findings import Finding, OracleSpec  # noqa: E402
from app.testing.purity.taxonomy import TruthLabel, Verdict  # noqa: E402

_EC_MODULES = ["allowlists", "access_gate", "audit", "blindness", "brief_store", "brief_validation", "credentials", "http_perimeter", "inventory",
               "oracle_gate", "provenance", "quarantine", "run_gate", "scope"]
_MISSING = object()


@contextlib.contextmanager
def optional_blocked(*, controls: bool = True, plugin: bool = False, only: tuple[str, ...] = ()):
    """Make optional parts unimportable (``None`` in sys.modules => ImportError) and reset the adapter; restore everything afterwards.
    controls: the whole Enterprise Controls package; plugin: the delegation adapter package; only: just these control modules."""
    names: list[str] = []
    if only:
        names += [f"app.enterprise_controls.{m}" for m in only]
    else:
        if controls:
            names += ["app.enterprise_controls"] + [f"app.enterprise_controls.{m}" for m in _EC_MODULES]
        if plugin:
            names += ["app.control_adapter", "app.control_adapter.adapter"]
    saved = {n: sys.modules.get(n, _MISSING) for n in names}
    for n in names:
        sys.modules[n] = None
    reset_control_adapter()
    try:
        yield
    finally:
        for n, v in saved.items():
            if v is _MISSING:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = v
        reset_control_adapter()


def controls_blocked(*modules: str):
    """The Enterprise Controls (or only the named control modules) unavailable."""
    return optional_blocked(only=modules) if modules else optional_blocked()


class FakeClock:
    def __init__(self) -> None:
        self.t, self.sleeps = 1000.0, []

    def __call__(self) -> float:
        return self.t

    async def sleep(self, s: float) -> None:
        self.sleeps.append(round(s, 9))
        self.t += s
        await asyncio.sleep(0)


class _LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def __enter__(self) -> "_LogCapture":
        logging.getLogger("app.control_adapter").addHandler(self)
        logging.getLogger("app.control_adapter").setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc: object) -> None:
        logging.getLogger("app.control_adapter").removeHandler(self)


def _enterprise() -> GuardedControlAdapter:
    reset_control_adapter()
    a = get_control_adapter()
    assert isinstance(a, GuardedControlAdapter) and a.mode == "enterprise", type(a)
    return a


def _brief() -> dict:
    return {
        "authorization_ref": "BENCH-AUTH-001", "authorized_by": "qa-benchmark-owner", "environment": "benchmark", "target_kind": "controlled_benchmark",
        "attested_synthetic_data": True, "attested_sandbox_payments": True, "allow_signup": True, "primary_currency": "USD",
        "allowed_hosts": ["shop.example.test:8080"],
        "surface": {
            "signup": {"method": "POST", "path": "/api/v1/account/signup", "observed_via": "product_ui"},
            "start_checkout": {"method": "POST", "path": "/api/v1/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": "/api/v1/checkout/{payment_id}/sandbox-pay", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": "/api/v1/checkout/return", "observed_via": "authorized_browser_trace"},
            "subscription_view": {"method": "GET", "path": "/api/v1/account/subscription", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": "/api/v1/account/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0, "JPY": 1300.0}}, "enterprise": {"prices": {"USD": 99.0, "JPY": 14500.0}}},
        "features": {
            "premium_export": {"method": "POST", "path": "/api/v1/premium/export", "proof_field": "export_id", "requires_plan": "basic", "observed_via": "product_ui"},
        },
        "declared_paid_features": ["premium_export"],
        "limits": {"max_requests": 600, "max_requests_per_second": 25, "revocation_sla_seconds": 1.0, "revocation_poll_schedule_s": [0.0, 0.1, 0.25, 0.5],
                   "quota_probe_cap": 6, "timeout_seconds": 10},
    }


def _spec() -> OracleSpec:
    return OracleSpec(*["x"] * 10)


def _artifacts(a, ledger, n: int = 3):
    arts = []
    for i in range(1, n + 1):
        art = a.build_artifact(payload={"op": "x", "n": i}, source_type="start_checkout", classification=EvidenceClass.EXTERNAL_CUSTOMER_API, identity_alias="buyer_a",
                               tenant_alias="tenant_a", target="http://shop.example.test/api/x", session_isolation_id=f"s-{i}", authorization_ref="REF-1", sequence=i)
        arts.append(art)
    return arts


def _candidate(arts, *, qualifying: bool = False) -> ConfirmationCandidate:
    def ob(oid, outcome, art, *, disc=None, proof=False, sess="s"):
        return OracleObservation(oracle_id=oid, feature_id="f1", identity_alias="buyer_a", tenant_alias="tenant_a", outcome=outcome, kind=KIND_FEATURE_USE, proof_present=proof,
                                 session_isolation_id=sess, artifact_ids=(art.artifact_id,), discriminating=disc, observed_at="t")
    return ConfirmationCandidate("H1", ob("c", "denied", arts[0], disc=True), ob("s", "allowed", arts[1], proof=True, sess="s-A"),
                                 ob("r", "allowed", arts[2], proof=True, sess="s-B"), qualifying)


# ====================================================================================================== A. normal operation
def test_normal_mode_every_group_is_available():
    a = _enterprise()
    st = a.status()
    assert st["mode"] == "enterprise" and st["available"] is True
    assert set(st["groups"]) == set(GROUPS) and all(g["available"] and g["error"] is None for g in st["groups"].values()), st


def test_denials_pass_through_the_adapter_unchanged():
    a = _enterprise()
    with pytest.raises(CredentialRejected):
        a.validate_run_inputs(custom_headers={"X-Admin-Token": "x"})
    with pytest.raises(BriefRejected):
        a.parse_brief({})
    guard = a.create_run_guard(a.build_scope_policy("http://shop.example.test", max_requests=5))
    for url, code in [("http://shop.example.test/internal/ledger", "purity_path_internal_surface"), ("http://evil.example.test/", "host_not_allowed"),
                      ("ftp://shop.example.test/x", "scheme_not_allowed"), ("http://shop.example.test:5432/", "purity_port_not_customer_facing")]:
        with pytest.raises(ScopeViolation) as ei:
            guard.preflight(url)
        assert ei.value.code == code, (url, ei.value.code)
    with pytest.raises(ValueError):  # input validation is NOT unavailability
        a.build_scope_policy("not a url")
    assert a.status()["available"] is True  # none of the above degraded anything


def test_guard_handle_behaves_exactly_like_the_real_guard():
    from app.enterprise_controls.scope import ScopeGuard, ScopePolicy

    async def run(make):
        fc = FakeClock()
        g = make(fc)
        res = []
        for url in ["http://shop.example.test/a"] * 6 + ["http://shop.example.test/internal/x", "http://evil.test/"]:
            try:
                await g.acquire(url)
                res.append("ok")
            except ScopeViolation as e:
                res.append(e.code)
        g.kill("op")
        try:
            await g.acquire("http://shop.example.test/a")
        except ScopeViolation as e:
            res.append(e.code)
        return res, fc.sleeps, g.stats()

    pol = dict(max_requests=5, max_requests_per_second=2.0, burst=2)
    a = _enterprise()
    via_adapter = asyncio.run(run(lambda fc: a.create_run_guard(a.build_scope_policy("http://shop.example.test", **pol), clock=fc, sleep=fc.sleep)))
    direct = asyncio.run(run(lambda fc: ScopeGuard(ScopePolicy.for_environment("http://shop.example.test", **pol), clock=fc, sleep=fc.sleep)))
    assert via_adapter == direct


def test_ledger_and_gate_through_the_adapter_confirm_with_a_real_token():
    a = _enterprise()
    ledger = a.new_evidence_ledger(authorization_ref="REF-1", approved_identity_aliases=["buyer_a"], approved_tenant_aliases=["tenant_a"])
    arts = _artifacts(a, ledger)
    assert all(ledger.try_admit(x)[0] for x in arts)
    bad = a.build_artifact(payload={"x": 1}, source_type="s", classification=EvidenceClass.EXTERNAL_CUSTOMER_API, identity_alias="root", tenant_alias="tenant_a",
                           target="http://shop.example.test/api/x", session_isolation_id="s-9", authorization_ref="REF-1", sequence=9)
    ok, reasons = ledger.try_admit(bad)
    assert ok is False and [r.code for r in reasons] == ["provenance_identity_unapproved"]
    decision = a.new_confirmation_gate(ledger).evaluate(_candidate(arts))
    assert decision.confirmed is True and decision.token is not None
    assert decision.token.covers("H1") and not decision.token.covers("OTHER")
    f = Finding("H1", "P0", "t", Verdict.CONFIRMED_P0, "high", "s", _spec(), token=decision.token)  # a token minted by the real gate is accepted
    assert f.verdict == Verdict.CONFIRMED_P0


def test_brief_through_the_adapter_and_the_facade():
    a = _enterprise()
    brief = ExecutionBrief.from_dict(_brief())
    assert brief.authorization_ref == "BENCH-AUTH-001" and brief.fingerprint()
    assert a.host_permitted("http://shop.example.test:8080", ("shop.example.test:8080",)) is True
    assert a.host_permitted("http://evil.test", ("shop.example.test:8080",)) is False
    for mutate, code in [(lambda b: b.__setitem__("attested_synthetic_data", False), "brief_attestation_missing"),
                         (lambda b: b.__setitem__("environment", "production"), "brief_environment_not_allowed"),
                         (lambda b: b.__setitem__("allowed_hosts", ["169.254.169.254"]), "purity_host_not_customer_facing")]:
        raw = _brief()
        mutate(raw)
        with pytest.raises(BriefRejected) as ei:
            ExecutionBrief.from_dict(raw)
        assert code in [r.code for r in ei.value.reasons]


def test_perimeter_is_installed_in_normal_mode():
    a = _enterprise()
    calls = []

    class App:
        def add_middleware(self, cls, **kw):
            calls.append((cls.__name__, kw))

    assert a.install_http_perimeter(App(), allowed_hostnames=["localhost"], extra_allowed_origins=[], allow_null_origin=False, api_token="t") is True
    assert calls and calls[0][0] == "LocalOnlyGuardMiddleware" and calls[0][1]["api_token"] == "t"


def test_quarantine_guard_is_unconditional_in_normal_mode():
    _enterprise()
    from app.testing.purity.quarantine import refuse_in_pure_mode
    with pytest.raises(QuarantinedModuleError) as ei:
        refuse_in_pure_mode("legacy.module")
    assert isinstance(ei.value, ImportError)


# ====================================================================================================== B. fail-open: ALL groups
def test_fail_open_when_the_component_is_missing_the_system_keeps_running():
    with controls_blocked(), _LogCapture() as logs:
        a = get_control_adapter()
        assert type(a) is FailOpenControlAdapter and a.mode == "fail_open"
        st = a.status()
        assert st["available"] is False and set(st["groups"]) == set(GROUPS)
        assert any(r.levelno == logging.CRITICAL for r in logs.records), "fail-open must never be silent"


def test_fail_open_run_admission_scope_and_access_gate_are_open():
    with controls_blocked():
        a = get_control_adapter()
        a.validate_run_inputs(custom_headers={"X-Admin-Token": "x"}, extra_allowed_hosts=["169.254.169.254"], integrity_brief={"webhook_secret": "whsec_x"})  # no raise
        policy = a.build_scope_policy("http://shop.example.test", ["extra.example.test"], max_requests=3)
        assert "shop.example.test" in policy.allowed_hosts and "extra.example.test" in policy.allowed_hosts and policy.max_requests == 3
        guard = a.create_run_guard(policy)
        guard.check_url("http://169.254.169.254/latest/meta-data")
        guard.preflight("http://shop.example.test/internal/ledger")

        async def many():
            for _ in range(10):  # the request budget is an authorisation bound and is not enforced in fail-open mode (max_requests=3)
                await guard.acquire("http://169.254.169.254/x", "GET", "negative_access_control")
        asyncio.run(many())
        s = guard.stats()
        assert s["requests_used"] == 10 and s["requests_denied"] == 0 and s["purity_gate"]["denied"] == 0
        assert s["degraded"] is True and s["control_mode"] == "fail_open"


def test_fail_open_keeps_kill_deadline_and_rate_limit_working():
    with controls_blocked():
        a = get_control_adapter()

        async def rate(guard_factory):
            fc = FakeClock()
            g = guard_factory(fc)
            await asyncio.gather(*[g.acquire("http://shop.example.test/x") for _ in range(9)])
            return fc.sleeps

        pol = dict(max_requests_per_second=2.0, burst=2, max_requests=100)
        open_sleeps = asyncio.run(rate(lambda fc: a.create_run_guard(a.build_scope_policy("http://shop.example.test", **pol), clock=fc, sleep=fc.sleep)))
        assert len(open_sleeps) == 7 and all(s > 0 for s in open_sleeps)  # the shared token bucket still throttles
        # kill switch (Cancel): effective immediately, also for a request that is already waiting
        fc = FakeClock()
        g = a.create_run_guard(a.build_scope_policy("http://shop.example.test", max_requests_per_second=1.0, burst=1), clock=fc, sleep=fc.sleep)
        g.start()
        asyncio.run(g.acquire("http://shop.example.test/x"))
        g.kill("operator cancel")
        assert g.killed and g.kill_reason == "operator cancel" and g.stop_reason() == "killed: operator cancel"
        for call in (lambda: g.preflight("http://shop.example.test/x"), lambda: asyncio.run(g.acquire("http://shop.example.test/x"))):
            with pytest.raises(ScopeViolation) as ei:
                call()
            assert ei.value.code == "killed"
        # deadline
        fc = FakeClock()
        g = a.create_run_guard(a.build_scope_policy("http://shop.example.test", deadline_seconds=10.0, max_requests_per_second=1000.0), clock=fc, sleep=fc.sleep)
        g.start()
        asyncio.run(g.acquire("http://shop.example.test/x"))
        fc.t += 10.5
        with pytest.raises(ScopeViolation) as ei:
            g.preflight("http://shop.example.test/x")
        assert ei.value.code == "deadline_exceeded" and g.stop_reason() == "deadline_exceeded"


def test_rate_limiter_is_identical_in_the_real_guard_and_the_fail_open_guard():
    from app.enterprise_controls.scope import ScopeGuard, ScopePolicy

    async def sleeps(make):
        fc = FakeClock()
        g = make(fc)
        await asyncio.gather(*[g.acquire("http://shop.example.test/x") for _ in range(12)])
        return fc.sleeps, round(fc.t, 6)

    kw = dict(max_requests_per_second=3.0, burst=2, max_requests=100)
    real = asyncio.run(sleeps(lambda fc: ScopeGuard(ScopePolicy.for_environment("http://shop.example.test", **kw), clock=fc, sleep=fc.sleep)))
    with controls_blocked():
        a = get_control_adapter()
        fail_open = asyncio.run(sleeps(lambda fc: a.create_run_guard(a.build_scope_policy("http://shop.example.test", **kw), clock=fc, sleep=fc.sleep)))
    assert real == fail_open


def test_fail_open_evidence_ledger_admits_but_the_gate_can_never_confirm():
    with controls_blocked():
        a = get_control_adapter()
        ledger = a.new_evidence_ledger(authorization_ref="REF-1", approved_identity_aliases=["buyer_a"], approved_tenant_aliases=["tenant_a"])
        arts = _artifacts(a, ledger)
        assert all(ledger.try_admit(x)[0] for x in arts) and set(ledger.accepted) == {x.artifact_id for x in arts}
        ok, reasons = ledger.try_admit(None)
        assert ok is False and reasons[0].code == "provenance_missing"
        assert ledger.summary()["degraded"] is True
        decision = a.new_confirmation_gate(ledger).evaluate(_candidate(arts))
        assert decision.confirmed is False and decision.token is None and "control_unavailable" in decision.reasons[0]
        with pytest.raises(ConfirmationRefused):  # no token can exist without the real gate, so CONFIRMED_P0 stays unreachable (nothing is forged)
            Finding("H1", "P0", "t", Verdict.CONFIRMED_P0, "high", "s", _spec(), token=decision.token)
        Finding("H1", "P0", "t", Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, "medium", "s", _spec())  # what the engine falls back to; every other verdict still works


def test_fail_open_brief_is_never_accepted_unvalidated():
    with controls_blocked():
        a = get_control_adapter()
        assert a.load_brief("/nonexistent/brief.json") is None
        for call in (lambda: a.parse_brief(_brief()), lambda: ExecutionBrief.from_dict(_brief())):
            with pytest.raises(BriefRejected) as ei:
                call()
            assert [r.code for r in ei.value.reasons] == ["control_unavailable"]
        assert a.host_permitted("http://anything.test", ()) is True


def test_fail_open_blindness_probe_bodies_and_rules_are_pass_through():
    with controls_blocked():
        a = get_control_adapter()
        headers, dropped = a.scrub_headers({"X-Debug": "1", "Content-Type": "application/json"})
        assert headers == {"x-debug": "1", "content-type": "application/json"} and dropped == []
        assert a.scrub_body({"ground_truth": 1}) == ({"ground_truth": 1}, [])
        recs = [{"ground_truth": "x", "label_provenance": "unknown"}]
        assert a.filter_label_channel(recs) == (recs, 0)
        assert a.withhold_body("secret page") == "secret page" and a.body_size("abcd") == 4
        assert a.is_provider_facing_operation("stripe_webhook") is False and a.is_allowed_observed_via("server_log") is True
        a.refuse_in_pure_mode("legacy.module")  # returns: the quarantine import guard is part of the unavailable component
        from app.testing.purity.quarantine import refuse_in_pure_mode
        refuse_in_pure_mode("legacy.module")


def test_fail_open_perimeter_is_not_installed_and_says_so_loudly():
    with controls_blocked(), _LogCapture() as logs:
        a = get_control_adapter()
        calls = []

        class App:
            def add_middleware(self, cls, **kw):
                calls.append(cls)

        assert a.install_http_perimeter(App(), allowed_hostnames=["localhost"], extra_allowed_origins=[], allow_null_origin=False, api_token=None) is False
        assert calls == []
        assert any(r.levelno == logging.CRITICAL and "perimeter" in r.getMessage() for r in logs.records)


def test_endpoints_follow_the_provider_rule_only_while_the_controls_are_available():
    import dataclasses
    from app.testing.endpoints import EndpointMap

    def paths():
        base = EndpointMap()
        ov = {o: dataclasses.replace(base.get(o), path="/custom/x") for o in ("stripe_webhook",)}
        m = EndpointMap(overrides=ov)
        return m.get("stripe_webhook").path, m.ignored_provider_overrides
    _enterprise()
    assert paths() == (EndpointMap().get("stripe_webhook").path, ["stripe_webhook"])  # normal: operator override ignored
    with controls_blocked():
        assert paths() == ("/custom/x", [])  # fail-open: override honoured


# ====================================================================================================== C. partial and mid-run failure
def test_one_broken_group_degrades_alone_all_other_groups_keep_enforcing():
    with controls_blocked("scope"):
        a = get_control_adapter()
        assert isinstance(a, GuardedControlAdapter) and a.mode == "enterprise"
        st = a.status()
        assert st["mode"] == "degraded" and st["groups"]["scope"]["available"] is False
        assert all(v["available"] for g, v in st["groups"].items() if g != "scope")
        guard = a.create_run_guard(a.build_scope_policy("http://shop.example.test"))
        guard.preflight("http://evil.test/")  # scope controls are down: open
        with pytest.raises(CredentialRejected):  # the run gate is a different group and still enforces
            a.validate_run_inputs(custom_headers={"X-Admin-Token": "x"})
        with pytest.raises(BriefRejected):
            a.parse_brief({})


def test_a_technical_failure_inside_a_control_fails_open_for_that_group_only():
    import app.enterprise_controls.scope as scope_mod
    a = _enterprise()
    original = scope_mod.ScopeGuard.preflight

    def boom(self, *args, **kwargs):
        raise RuntimeError("simulated defect inside the control")
    scope_mod.ScopeGuard.preflight = boom
    try:
        with _LogCapture() as logs:
            guard = a.create_run_guard(a.build_scope_policy("http://shop.example.test"))
            guard.preflight("http://shop.example.test/internal/ledger")  # control crashed -> open, no exception reaches the Main System
            guard.preflight("http://shop.example.test/internal/ledger")  # (still open; logged only once)
            assert len([r for r in logs.records if r.levelno >= logging.ERROR]) == 1
        st = a.status()
        assert st["groups"]["scope"]["available"] is False and "RuntimeError" in st["groups"]["scope"]["error"]
        with pytest.raises(CredentialRejected):
            a.validate_run_inputs(custom_headers={"X-Admin-Token": "x"})
    finally:
        scope_mod.ScopeGuard.preflight = original
        reset_control_adapter()


def test_a_failing_guard_never_loses_the_kill_switch():
    import app.enterprise_controls.scope as scope_mod
    a = _enterprise()
    original = scope_mod.ScopeGuard.acquire

    async def boom(self, *args, **kwargs):
        raise RuntimeError("simulated defect")
    scope_mod.ScopeGuard.acquire = boom
    try:
        guard = a.create_run_guard(a.build_scope_policy("http://shop.example.test"))
        asyncio.run(guard.acquire("http://shop.example.test/x"))  # degrades to the pass-through guard
        guard.kill("cancel")
        with pytest.raises(ScopeViolation) as ei:
            asyncio.run(guard.acquire("http://shop.example.test/x"))
        assert ei.value.code == "killed" and guard.killed
    finally:
        scope_mod.ScopeGuard.acquire = original
        reset_control_adapter()


# ====================================================================================================== D. interface and boundary
def test_both_adapters_implement_the_complete_interface():
    names = [n for n in dir(ControlAdapter) if not n.startswith("_")]
    assert set(names) == {"body_size", "build_artifact", "build_scope_policy", "create_run_guard", "filter_label_channel", "host_permitted", "install_http_perimeter",
                          "is_allowed_observed_via", "is_provider_facing_operation", "load_brief", "new_confirmation_gate", "new_evidence_ledger", "parse_brief",
                          "refuse_in_pure_mode", "scrub_body", "scrub_headers", "status", "validate_run_inputs", "withhold_body"}, names  # interface drift must be a conscious change
    for adapter in (FailOpenControlAdapter(), EnterpriseControlAdapter(), GuardedControlAdapter(EnterpriseControlAdapter())):
        missing = [n for n in names if not hasattr(adapter, n)]
        assert not missing, (type(adapter).__name__, missing)


def test_run_guard_surface_is_complete_for_the_handle_and_the_fail_open_guard():
    surface = [n for n in dir(RunGuard) if not n.startswith("_")]
    a = _enterprise()
    handle = a.create_run_guard(a.build_scope_policy("http://shop.example.test"))
    fb = PassThroughGuard(a.build_scope_policy("http://shop.example.test"))
    for obj in (handle, fb):
        assert not [n for n in surface if not hasattr(obj, n)], (type(obj).__name__, surface)
    from app.enterprise_controls.scope import ScopeGuard
    real = ScopeGuard(a.build_scope_policy("http://shop.example.test"))  # instance: `policy` is an instance attribute
    assert not [n for n in surface if not hasattr(real, n)], "the Protocol must not promise more than the real guard offers"


def test_enterprise_adapter_and_fail_open_adapter_signatures_agree():
    for name in [n for n in dir(ControlAdapter) if not n.startswith("_") and callable(getattr(FailOpenControlAdapter, n, None))]:
        s1, s2 = inspect.signature(getattr(FailOpenControlAdapter, name)), inspect.signature(getattr(EnterpriseControlAdapter, name))
        assert list(s1.parameters) == list(s2.parameters), (name, s1, s2)


def test_main_system_reaches_the_controls_only_through_the_control_port():
    from app.enterprise_controls import audit
    assert audit.control_boundary() == []
    hits = {name: hits for name, hits in audit.run_all().items() if hits}
    assert hits == {}, hits


def test_control_port_imports_without_the_controls():
    code = (
        "import sys\n"
        "sys.modules['app.enterprise_controls'] = None\n"
        "sys.path.insert(0, %r)\n"
        "import app.core.control_port as cp\n"
        "a = cp.get_control_adapter()\n"
        "print(type(a).__name__, a.mode)\n" % str(BACKEND)
    )
    import subprocess
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "FailOpenControlAdapter fail_open", out.stdout


# ====================================================================================================== E. optional parts missing or damaged
def _assert_fail_open_system():
    """The Main System keeps working: the adapter is the fail-open one and none of the controls is enforced."""
    a = get_control_adapter()
    assert type(a) is FailOpenControlAdapter and a.mode == "fail_open", type(a)
    a.validate_run_inputs(custom_headers={"X-Admin-Token": "x"})
    g = a.create_run_guard(a.build_scope_policy("http://shop.example.test", max_requests=2))
    for _ in range(4):
        asyncio.run(g.acquire("http://169.254.169.254/latest/meta-data"))
    with pytest.raises(BriefRejected) as ei:
        ExecutionBrief.from_dict(_brief())
    assert [r.code for r in ei.value.reasons] == ["control_unavailable"]


def test_the_plugin_adapter_missing_means_fail_open_for_everything():
    with optional_blocked(controls=False, plugin=True), _LogCapture() as logs:
        _assert_fail_open_system()
        assert any(r.levelno == logging.CRITICAL for r in logs.records)


def test_both_optional_parts_missing_means_fail_open_for_everything():
    with optional_blocked(controls=True, plugin=True):
        _assert_fail_open_system()


class _Plugin:
    """A damaged plug-in adapter: some methods are missing, others raise technical errors."""
    mode = "enterprise"

    def validate_run_inputs(self, **kw):
        raise AttributeError("damaged")

    def build_scope_policy(self, environment_url, extra_hosts=(), **kw):
        raise ValueError("input validation is a control outcome and must pass through")

    def create_run_guard(self, policy, **kw):
        return object()  # a handle without the guard surface

    def parse_brief(self, data, **kw):
        raise NameError("deleted helper class")

    def host_permitted(self, base_url, allowed_hosts):
        raise ScopeViolation("deny", "a deny decision must pass through")

    def is_allowed_observed_via(self, value):
        return False  # intact methods keep working


def test_the_guard_makes_the_main_system_independent_of_a_damaged_plugin():
    reset_control_adapter(GuardedControlAdapter(_Plugin()))
    try:
        a = get_control_adapter()
        assert a.is_allowed_observed_via("server_log") is False  # intact method of the plug-in is used
        a.validate_run_inputs(custom_headers={"X-Admin-Token": "x"})  # AttributeError in the plug-in -> fail-open
        assert a.withhold_body("page") == "page" and a.body_size("abcd") == 4  # method missing in the plug-in -> fail-open
        with pytest.raises(BriefRejected):  # NameError -> fallback, which refuses the brief (never accepts it unvalidated)
            a.parse_brief(_brief())
        g = a.create_run_guard(FailOpenControlAdapter().build_scope_policy("http://shop.example.test"))
        assert isinstance(g, PassThroughGuard)  # handle without the surface -> fail-open guard
        with pytest.raises(ValueError):
            a.build_scope_policy("http://x")
        with pytest.raises(ScopeViolation):
            a.host_permitted("http://x", ("x",))
        st = a.status()
        assert st["mode"] == "degraded" and {"validate_run_inputs", "parse_brief", "create_run_guard", "withhold_body"} <= set(st["adapter_degraded"]), st
    finally:
        reset_control_adapter()


def test_every_interface_method_survives_a_completely_broken_plugin():
    class Broken:
        mode = "enterprise"

        def __getattr__(self, name):
            def boom(*a, **k):
                raise RuntimeError("everything is broken")
            return boom
    reset_control_adapter(GuardedControlAdapter(Broken()))
    try:
        a = get_control_adapter()
        ref = FailOpenControlAdapter()
        assert a.body_size("abc") == ref.body_size("abc") and a.scrub_body({"x": 1}) == ref.scrub_body({"x": 1})
        assert a.is_provider_facing_operation("stripe_webhook") is False and a.is_allowed_observed_via("x") is True
        a.refuse_in_pure_mode("legacy.module")
        a.validate_run_inputs()
        assert a.load_brief("/nope") is None and a.host_permitted("http://x", ()) is True
        assert a.install_http_perimeter(object(), allowed_hostnames=[], extra_allowed_origins=[], allow_null_origin=False, api_token=None) is False
        led = a.new_evidence_ledger(authorization_ref="R")
        assert led.accepted == {} and a.new_confirmation_gate(led).evaluate(None).confirmed is False
        assert isinstance(a.create_run_guard(FailOpenControlAdapter().build_scope_policy("http://shop.example.test")), PassThroughGuard)
        assert a.status()["mode"] == "degraded" and set(a.status()["adapter_degraded"]) >= {"validate_run_inputs", "body_size", "install_http_perimeter"}
    finally:
        reset_control_adapter()


_PROBE = textwrap.dedent("""
    import sys, json, asyncio
    sys.path.insert(0, %(root)r)
    import app.core.control_port as cp
    from app.testing.integrity.brief import ExecutionBrief, BriefRejected
    from app.testing.integrity.findings import Finding
    from app.testing.endpoints import EndpointMap
    from app.testing.purity.quarantine import refuse_in_pure_mode
    a = cp.get_control_adapter()
    g = a.create_run_guard(a.build_scope_policy("http://shop.example.test", max_requests=2))
    asyncio.run(g.acquire("http://169.254.169.254/latest/meta-data"))   # a denylisted host must not stop the system when the controls are gone
    a.validate_run_inputs(custom_headers={"Accept": "text/html"})
    try:
        refuse_in_pure_mode("legacy.module"); quarantine = "returned"
    except cp.QuarantinedModuleError:
        quarantine = "refused"
    try:
        ExecutionBrief.from_dict({}); brief = "accepted"
    except BriefRejected as e:
        brief = ",".join(r.code for r in e.reasons)
    print(json.dumps({"adapter": type(a).__name__, "mode": a.mode, "brief": brief, "quarantine": quarantine, "degraded": g.stats().get("degraded")}))
""")


def _start_main_system(mutate) -> dict:
    """Copy the app package, damage/delete files for real, start the Main System in a fresh interpreter and report what happened."""
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "app"
        shutil.copytree(BACKEND / "app", dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        mutate(dst)
        code = _PROBE % {"root": tmp}
        out = subprocess.run([sys.executable, "-c", code], cwd=tmp, capture_output=True, text=True, timeout=180)
        assert out.returncode == 0, out.stderr[-1500:]
        return json.loads(out.stdout.strip().splitlines()[-1])


def _rm(*rel):
    def mutate(app: Path) -> None:
        for r in rel:
            shutil.rmtree(app / r)
    return mutate


def _write(rel: str, text: str):
    def mutate(app: Path) -> None:
        (app / rel).write_text(text, encoding="utf-8")
    return mutate


def _truncate(rel: str, keep: float):
    def mutate(app: Path) -> None:
        f = app / rel
        lines = f.read_text(encoding="utf-8").splitlines(keepends=True)
        f.write_text("".join(lines[: int(len(lines) * keep)]), encoding="utf-8")
    return mutate


def test_main_system_starts_when_the_optional_folders_are_really_deleted_or_damaged():
    # deleted (the exact scenario: folders vanish by mistake)
    for label, mutate in [("enterprise_controls deleted", _rm("enterprise_controls")), ("control_adapter deleted", _rm("control_adapter")),
                          ("both deleted", _rm("enterprise_controls", "control_adapter"))]:
        r = _start_main_system(mutate)
        assert r["adapter"] == "FailOpenControlAdapter" and r["mode"] == "fail_open" and r["brief"] == "control_unavailable" and r["degraded"] is True, (label, r)
        assert r["quarantine"] == "returned", (label, r)  # the quarantine import guard is part of the unavailable controls
    # corrupted files
    for label, mutate in [("plug-in syntax error", _write("control_adapter/adapter.py", "def broken(:\n")), ("plug-in package garbage", _write("control_adapter/__init__.py", "}{ not python")),
                          ("controls package garbage", _write("enterprise_controls/__init__.py", "\x00\x01 garbage")),
                          ("plug-in truncated", _truncate("control_adapter/adapter.py", 0.55))]:
        r = _start_main_system(mutate)
        assert r["adapter"] in ("FailOpenControlAdapter", "GuardedControlAdapter") and r["brief"] != "accepted", (label, r)
    # one damaged control module degrades only its group: the brief gate is a different group and still rejects with its real reasons
    r = _start_main_system(_write("enterprise_controls/scope.py", "this is not python at all {{"))
    assert r["adapter"] == "GuardedControlAdapter" and r["mode"] == "enterprise" and r["degraded"] is True and r["brief"] != "control_unavailable" and r["brief"] != "accepted", r
    assert r["quarantine"] == "refused", r  # ... and the quarantine group is intact, so it still refuses


if __name__ == "__main__":  # plain-script mode
    failures = 0
    for fn_name, fn in sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)):
        try:
            fn()
            print(f"PASS {fn_name}")
        except BaseException as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL {fn_name}: {type(e).__name__}: {e}")
    sys.exit(1 if failures else 0)
