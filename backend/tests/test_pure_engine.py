"""Tests of the pure black-box Protected-Feature Oracle engine: Execution Brief, claims/UI detection, controls, gap engine, regression, product module.

The engine is exercised end to end against the controlled benchmark target (tests/verification_infrastructure/purity_benchmark). That target keeps
its seeded flaws, hints and internal routes to itself; the engine only ever receives a base URL and a customer-level Execution Brief.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

_INFRA = os.path.join(os.path.dirname(__file__), "verification_infrastructure")
if _INFRA not in sys.path:
    sys.path.insert(0, _INFRA)

from app.testing.context import RunSettings  # noqa: E402
from app.testing.endpoints import EndpointMap  # noqa: E402
from app.testing.enums import TestScope  # noqa: E402
from app.testing.event_bus import EventBus  # noqa: E402
from app.testing.integrity.brief import BriefRejected, ExecutionBrief  # noqa: E402
from app.testing.integrity.engine import claims_paid  # noqa: E402
from app.testing.integrity.gaps import capability_gaps, unknown_exposures  # noqa: E402
from app.testing.integrity.regression import build_regression_spec, replay_regression  # noqa: E402
from app.testing.purity.taxonomy import Coverage, Verdict  # noqa: E402
from app.testing.runner import TestRunner  # noqa: E402
from app.enterprise_controls.scope import ScopePolicy  # noqa: E402
from purity_benchmark.customer_target import TargetFlags, start_customer_target  # noqa: E402
from purity_benchmark.lab import public_brief, run_scenario  # noqa: E402
from purity_benchmark.scenarios import EXPERIMENTS, by_name  # noqa: E402

_CACHE: dict[str, object] = {}


async def _run(name: str):
    if name not in _CACHE:
        _CACHE[name] = await run_scenario(by_name(name))
    return _CACHE[name]


def _codes(reasons) -> set[str]:
    return {r.code for r in reasons}


# ------------------------------------------------------------------------------------------------------------------------ brief
def test_brief_resolves_tokens_from_env_names_and_never_serialises_them():
    data = public_brief("http://127.0.0.1:9")
    data["allow_signup"] = False
    del data["surface"]["signup"]
    data["identities"] = {"identity_a": {"role": "customer", "synthetic": True, "token_env": "QA_IDENTITY_A_TOKEN", "tenant": "tenant_a"},
                          "identity_b": {"role": "customer", "synthetic": True, "token_env": "QA_IDENTITY_B_TOKEN", "tenant": "tenant_b"}}
    brief = ExecutionBrief.from_dict(data, env={"QA_IDENTITY_A_TOKEN": "tok_aaaa1111", "QA_IDENTITY_B_TOKEN": "tok_bbbb2222"})
    assert brief.tokens == {"identity_a": "tok_aaaa1111", "identity_b": "tok_bbbb2222"}
    public = json.dumps(brief.to_public_dict())
    assert "tok_aaaa1111" not in public and "tok_bbbb2222" not in public and "tok_aaaa1111" not in repr(brief)
    assert brief.cheapest_plan == "basic" and brief.priciest_plan == "enterprise"
    assert brief.primary_feature().feature_id == "premium_export" and brief.quota_feature().feature_id == "credits_use" and brief.tier_feature().feature_id == "enterprise_report"


def test_brief_is_rejected_fail_closed_with_value_free_reasons():
    cases = {
        "brief_environment_not_allowed": {"environment": "production"},
        "brief_attestation_missing": {"attested_sandbox_payments": False},
        "brief_hosts_missing": {"allowed_hosts": []},
        "brief_identities_insufficient": {"allow_signup": False},
        "brief_limits_out_of_range": {"limits": {"max_requests": 999999, "max_requests_per_second": 500}},
        "brief_target_kind_invalid": {"target_kind": "real_production_shop"},
    }
    for code, override in cases.items():
        data = public_brief("http://127.0.0.1:9")
        for k, v in override.items():
            data[k] = {**data[k], **v} if isinstance(v, dict) and isinstance(data.get(k), dict) else v
        if code == "brief_identities_insufficient":
            del data["surface"]["signup"]
        with pytest.raises(BriefRejected) as exc:
            ExecutionBrief.from_dict(data, env={})
        assert code in _codes(exc.value.reasons), (code, _codes(exc.value.reasons))
    data = public_brief("http://127.0.0.1:9")
    data["features"]["premium_export"]["proof_field"] = ""
    data["features"]["credits_use"]["requires_plan"] = "platinum"
    del data["surface"]["return_flow"]
    with pytest.raises(BriefRejected) as exc:
        ExecutionBrief.from_dict(data, env={})
    assert {"brief_feature_no_proof_field", "brief_feature_plan_unknown", "brief_operation_missing"} <= _codes(exc.value.reasons)


def test_brief_fingerprint_is_stable_and_reflects_the_surface():
    a = ExecutionBrief.from_dict(public_brief("http://127.0.0.1:9"), env={})
    b = ExecutionBrief.from_dict(public_brief("http://127.0.0.1:9"), env={})
    c_data = public_brief("http://127.0.0.1:9")
    c_data["plans"]["enterprise"]["prices"]["USD"] = 199.0
    assert a.fingerprint() == b.fingerprint() != ExecutionBrief.from_dict(c_data, env={}).fingerprint()


def test_claims_paid_only_detects_customer_visible_paid_claims():
    assert claims_paid({"status": "ok", "message": "Payment successful! Premium unlocked.", "premium_badge": True})
    assert claims_paid({"plan": "basic", "status": "active", "badge": "premium"})
    assert claims_paid({"data": {"subscription": "active"}})
    assert not claims_paid({"status": "payment_not_completed", "message": "Your payment was not completed."})
    assert not claims_paid({"plan": "free", "status": "inactive", "badge": None})
    assert not claims_paid({"message": "Payment was not successful"}) and not claims_paid("premium") and not claims_paid(None)


# ------------------------------------------------------------------------------------------------------------------------ oracle
@pytest.mark.asyncio
async def test_oracle_requires_proof_field():
    from app.testing.integrity.brief import FeatureSpec
    from app.testing.integrity.oracle import ProtectedFeatureOracle
    from app.testing.integrity.session import CallResult
    from types import SimpleNamespace

    feature = FeatureSpec("premium_export", "POST", "/api/v1/premium/export", "export_id", "basic", False, "product_ui")
    def session(status, body, admitted=True, error=None):
        async def feature_call(f, *, label):
            return CallResult("feature:x", status, body, {}, error, 1.0, "ev-1" if admitted else None, admitted)
        return SimpleNamespace(feature_call=feature_call, identity_alias="identity_a", tenant_alias="tenant_a", session_id="s1")
    oracle = ProtectedFeatureOracle()
    cases = [(200, {"export_id": "e1"}, "allowed"), (201, {"export_id": "e1"}, "allowed"), (200, {"ok": True}, "indeterminate"), (200, {"export_id": ""}, "indeterminate"), (200, "<html>premium</html>", "indeterminate"),
             (402, {}, "denied"), (403, {}, "denied"), (401, {}, "indeterminate"), (202, {"job_id": "j"}, "indeterminate"), (500, {}, "indeterminate"), (404, {}, "indeterminate")]
    for status, body, expected in cases:
        assert (await oracle.check(session(status, body), feature, oracle_id="t")).outcome == expected, (status, body)
    assert (await oracle.check(session(200, {"export_id": "e"}, admitted=False), feature, oracle_id="t")).outcome == "indeterminate", "evidence rejected by the ledger => not a proof"
    assert (await oracle.check(session(None, None, error="timeout"), feature, oracle_id="t")).outcome == "indeterminate"


# ------------------------------------------------------------------------------------------------------------- controls + traffic
@pytest.mark.asyncio
async def test_controls_use_only_customer_level_calls():
    run = await _run("fully_fixed")
    c = run.result.controls
    assert c["setup_ok"] and c["legit_payer_allowed"] and c["clean_identity_denied"] and not c["feature_open_to_unpaid"] and c["top_tier_payer_allowed"] and not c["cheapest_payer_reaches_top_tier"]
    brief_paths = {o.path.split("{")[0].rstrip("/") for o in run.brief.operations.values()} | {f.path for f in run.brief.features.values()}
    seen = {p for _, p in run.target.request_log}
    assert seen and all(any(p == b or p.startswith(b + "/") for b in brief_paths) for p in seen), f"requests outside the brief's customer-facing surface: {seen - brief_paths}"
    assert run.internal_hits == 0
    tokens = {h.get("authorization") for h in run.target.request_headers_seen if h.get("authorization")}
    assert tokens and all(t.startswith("Bearer tok_") for t in tokens)  # only synthetic identities' own bearer tokens, nothing else
    assert all("cookie" not in h for h in run.target.request_headers_seen), "clean sessions: no cookies are ever carried"
    assert set(run.result.verdicts().values()) == {"RULED_OUT"}


@pytest.mark.asyncio
async def test_open_feature_is_partial_not_confirmed():
    run = await _run("open_feature")
    by = run.result.by_id()
    assert by["PBB-OPEN"].verdict == Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE and "confirmation_pattern_not_executable" in " ".join(by["PBB-OPEN"].reasons)
    assert not run.result.confirmed() and all(by[e].verdict != Verdict.RULED_OUT for e in EXPERIMENTS if e != "PBB-E")


@pytest.mark.asyncio
async def test_ui_claims_never_confirm():
    run = await _run("ui_only_anomaly")
    by = run.result.by_id()
    assert not run.result.confirmed()
    assert by["PBB-U"].verdict == Verdict.RULED_OUT and by["PBB-U"].divergences, "the UI-only anomaly is reported as a divergence, not an entitlement"
    assert by["PBB-E"].verdict == Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE and "NOT a P0" in by["PBB-E"].summary


@pytest.mark.asyncio
async def test_broken_setup_is_blocked_never_passed():
    run = await _run("broken_setup")
    assert {f.verdict for f in run.result.findings} == {Verdict.BLOCKED}
    assert run.result.controls["setup_ok"] is False


@pytest.mark.asyncio
async def test_confirmed_findings_carry_an_oracle_token_and_admitted_evidence():
    run = await _run("cross_tenant_binding")
    f = run.result.by_id()["PBB-G"]
    assert f.verdict == Verdict.CONFIRMED_P0 and f.token is not None and f.token.covers("PBB-G")
    assert f.artifact_ids and all(run.ledger.is_admitted(i) for i in f.artifact_ids)
    assert f.to_dict()["confirmed_via_oracle_gate"] and "UNKNOWN" in f.to_dict()["internal_cause"]
    assert run.result.ledger_summary["rejected"] == 0


@pytest.mark.asyncio
async def test_global_entitlement_leak_is_confirmed_by_the_control_pattern_and_blocks_attribution():
    run = await _run("global_entitlement_leak")
    by = run.result.by_id()
    leak = by["PBB-LEAK"]
    assert leak.verdict == Verdict.CONFIRMED_P0 and leak.token is not None and leak.token.covers("PBB-LEAK")
    assert all(by[e].verdict == Verdict.UNKNOWN and "entitlement_leak_to_unrelated_identity" in by[e].reasons for e in EXPERIMENTS), "later payments cannot be attributed once entitlement is not isolated"
    labels = {a.payload["label"] for a in run.ledger.accepted.values()}
    assert {"CTRL:K:primary", "CTRL:K:after_other_payment", "PBB-LEAK:repro"} <= labels, "denied -> allowed after another identity's payment -> clean-session reproduction"
    rows = {r.p0_class: r for r in capability_gaps(run.brief, run.result)}
    assert rows["entitlement_leak_to_unrelated_identity"].coverage == Coverage.COVERED
    assert "PBB-LEAK" not in (await _run("fully_fixed")).result.by_id(), "no leak finding on a clean target"


# --------------------------------------------------------------------------------------------------------------------------- gaps
def test_gap_engine_marks_unsupported_classes_blocked():
    rows = capability_gaps(None, None)
    assert all(r.coverage == Coverage.BLOCKED for r in rows) and len(rows) == 11
    assert len(unknown_exposures(rows)) == 11


@pytest.mark.asyncio
async def test_gap_engine_never_reports_full_coverage_even_for_a_clean_target():
    run = await _run("fully_fixed")
    rows = {r.p0_class: r for r in capability_gaps(run.brief, run.result)}
    for name in ("provider_event_authenticity_and_replay", "concurrent_duplicate_checkout_or_race", "lifecycle_trial_coupon_renewal_expiry_downgrade"):
        assert rows[name].coverage == Coverage.BLOCKED and "NOT SUPPORTED" in rows[name].reason
    assert rows["unconfirmed_payment_grants_access"].coverage == Coverage.COVERED
    assert rows["duplicate_value_via_return_flow_repetition"].coverage == Coverage.PARTIALLY_COVERED  # sequential only
    assert len(unknown_exposures(list(rows.values()))) >= 3
    blocked = await _run("opaque_async_feature_internal_flaw")
    assert all(r.coverage in (Coverage.BLOCKED, Coverage.UNKNOWN) for r in capability_gaps(blocked.brief, blocked.result) if r.experiment)


# ----------------------------------------------------------------------------------------------------------------------- regression
@pytest.mark.asyncio
async def test_regression_spec_replays_and_flags_stale_specs():
    buggy = await _run("failed_payment_grants_access")
    spec = build_regression_spec(buggy.result, buggy.brief)
    kinds = {c["hypothesis_id"]: c["kind"] for c in spec["checks"]}
    assert kinds["PBB-U"] == "regression_for_confirmed_p0" and kinds["PBB-F"] == "false_positive_control"
    assert spec["contains_secrets"] is False and "tok_" not in json.dumps(spec) and "pay_" not in json.dumps(spec)
    assert spec["rerun_triggers"] and spec["clean_session_instructions"]

    async def replay(name: str, *, rebind: bool):
        async def runner(ids):
            return (await run_scenario(by_name(name), experiments=ids)).result
        probe = await run_scenario(by_name(name), experiments=["PBB-U"])
        local = dict(spec, brief_fingerprint=probe.brief.fingerprint()) if rebind else spec
        return await replay_regression(local, probe.brief, runner)

    assert (await replay("fully_fixed", rebind=True)).passed, "after the fix the confirmed P0 must turn RULED_OUT"
    still_buggy = await replay("failed_payment_grants_access", rebind=True)
    assert not still_buggy.passed and any("REGRESSION" in d for d in still_buggy.details)
    stale = await replay("fully_fixed", rebind=False)
    assert stale.stale and not stale.passed, "a changed brief fingerprint makes the spec stale: re-validate, do not trust"


# --------------------------------------------------------------------------------------------------------------- product module e2e
async def _module(base_url: str, brief: dict | None, *, enabled="payment_integrity"):
    runner = TestRunner(run_id="pi-pure", base_url=base_url, scope=TestScope.COMPREHENSIVE, settings=RunSettings(enabled_modules={enabled}, integrity_brief=brief), endpoints=EndpointMap(),
                        event_bus=EventBus(), scope_policy=ScopePolicy.for_environment(base_url, max_requests_per_second=5000.0))
    collector = await runner.execute()
    return {r.test_case_id: r for r in collector.results}


def _status(result) -> str:
    return str(getattr(result.status, "value", result.status)).lower()


@pytest.mark.asyncio
async def test_module_without_a_brief_sends_no_request_and_lists_the_gaps():
    target, server, port = await start_customer_target(TargetFlags())
    try:
        results = await _module(f"http://127.0.0.1:{port}", None)
        assert target.request_log == [], "no brief => no authorisation => not one request"
        gap = results["PI-CAPABILITY-GAP"]
        assert _status(gap) == "warning" and "NO experiment ran" in gap.actual and len(gap.input_parameters["capability_gaps"]) == 11
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_run_start_refuses_a_brief_with_secrets_before_any_request():
    from app.core.control_port import CredentialRejected

    target, server, port = await start_customer_target(TargetFlags())
    try:
        bad = public_brief(f"http://127.0.0.1:{port}")
        bad["webhook_secret"] = "whsec_" + "z" * 20
        bad["database_url"] = "postgresql://u:pw@db/shop"
        with pytest.raises(CredentialRejected) as exc:
            await _module(f"http://127.0.0.1:{port}", bad)  # TestRunner.__init__ refuses: the run never starts (the API answers HTTP 400 even earlier)
        assert "whsec_" not in str(exc.value) and "pw@" not in str(exc.value) and "config_secret_key" in str(exc.value)
        assert target.request_log == []
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_module_rejects_an_invalid_brief_without_sending_anything():
    target, server, port = await start_customer_target(TargetFlags())
    try:
        bad = public_brief(f"http://127.0.0.1:{port}")
        bad["environment"] = "production"
        bad["attested_sandbox_payments"] = False
        results = await _module(f"http://127.0.0.1:{port}", bad)
        r = results["PI-BRIEF-INVALID"]
        assert _status(r) == "error" and "brief_environment_not_allowed" in r.actual and "brief_attestation_missing" in r.actual and target.request_log == []
        assert "PI-CAPABILITY-GAP" in results
        unreadable = await _module(f"http://127.0.0.1:{port}", {"__load_error__": "cannot read integrity brief file"})
        assert "PI-BRIEF-UNREADABLE" in unreadable and target.request_log == []
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_module_refuses_a_target_the_brief_does_not_authorise():
    target, server, port = await start_customer_target(TargetFlags())
    try:
        brief = public_brief(f"http://127.0.0.1:{port}")
        brief["allowed_hosts"] = ["staging.shop.example.test"]
        results = await _module(f"http://127.0.0.1:{port}", brief)
        assert "PI-BRIEF-HOST" in results and target.request_log == []
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_module_confirms_a_p0_with_the_oracle_and_attests_purity():
    target, server, port = await start_customer_target(TargetFlags(return_trusts_status_claim=True))
    try:
        results = await _module(f"http://127.0.0.1:{port}", public_brief(f"http://127.0.0.1:{port}"))
        u = results["PI-PBB-U"]
        assert _status(u) == "fail" and "[CONFIRMED_P0]" in u.name and u.input_parameters["_integrity"]["confirmed_via_oracle_gate"] is True
        assert "internal cause" in u.actual.lower() and "UNKNOWN" in u.actual
        summary = results["PI-SUMMARY"]
        assert _status(summary) == "fail" and "never means 'no P0 exists'" in summary.actual
        att = summary.input_parameters["black_box_purity_attestation"]
        assert att["external_evidence_only"] is True and att["source_code_used"] is False and att["internal_causal_claims_made"] is False
        assert summary.input_parameters["regression_spec"]["checks"] and target.internal_hits == 0
        assert all(_status(results[k]) == "pass" for k in ("PI-PBB-F", "PI-PBB-G", "PI-PBB-X", "PI-PBB-C"))
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_module_never_reports_pass_for_a_clean_target_while_gaps_remain():
    target, server, port = await start_customer_target(TargetFlags())
    try:
        results = await _module(f"http://127.0.0.1:{port}", public_brief(f"http://127.0.0.1:{port}"))
        assert all(_status(results[f"PI-PBB-{c}"]) == "pass" for c in "UFHCGXRE")
        s = results["PI-SUMMARY"]
        assert _status(s) == "warning" and len(s.input_parameters["capability_gaps"]) >= 3, "all experiments RULED_OUT, but uncovered P0 classes keep the summary at WARNING"
    finally:
        await server.aclose()


# --------------------------------------------------------------------------------------------- static identity pool (token_env, no signup)
async def _mint_pool(target, n: int):
    """Pre-provision n synthetic identities on the target the way a customer would receive them (token + own tenant id), WITHOUT the engine's signup."""
    pool = []
    for _ in range(n):
        status, body, _ = await target.handle("POST", "/api/v1/account/signup", {}, {})
        assert status == 201
        pool.append(body)
    return pool


def _static_brief(base_url: str, pool: list[dict]) -> tuple[dict, dict]:
    data = public_brief(base_url)
    data["allow_signup"] = False
    del data["surface"]["signup"]
    env = {}
    data["identities"] = {}
    for i, ident in enumerate(pool):
        alias = f"pool_{i:02d}"
        data["identities"][alias] = {"role": "customer", "synthetic": True, "token_env": f"QA_POOL_{i:02d}_TOKEN", "tenant": f"tenant_{alias}", "tenant_id": ident["tenant_id"]}
        env[f"QA_POOL_{i:02d}_TOKEN"] = ident["token"]
    return data, env


@pytest.mark.asyncio
async def test_static_identity_pool_runs_all_experiments_without_signup():
    from app.testing.http_client import QAHttpClient
    from app.testing.integrity.engine import PureBlackBoxEngine
    from app.enterprise_controls.scope import ScopeGuard

    target, server, port = await start_customer_target(TargetFlags(tenant_claim_trusted=True))
    base = f"http://127.0.0.1:{port}"
    try:
        pool = await _mint_pool(target, 22)
        target.request_log.clear()
        data, env = _static_brief(base, pool)
        brief = ExecutionBrief.from_dict(data, env=env)
        assert set(brief.tokens) == set(brief.identities) and all(t.startswith("tok_") for t in brief.tokens.values())
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=ScopeGuard(ScopePolicy.for_environment(base, max_requests=400, max_requests_per_second=50)), stateless=True)
        result = await PureBlackBoxEngine(http, brief, base_url=base).run()
        await http.aclose()
        v = result.verdicts()
        assert v["PBB-G"] == "CONFIRMED_P0" and all(v[e] == "RULED_OUT" for e in ("PBB-U", "PBB-F", "PBB-H", "PBB-C", "PBB-X", "PBB-R", "PBB-E")), v
        assert "/api/v1/account/signup" not in {p for _, p in target.request_log}, "a static pool must never trigger signup"
        assert set(result.stats["synthetic_identities_used"]) <= set(brief.identities)
        blob = json.dumps(result.to_dict(), default=str)
        assert all(t not in blob for t in brief.tokens.values()), "tokens never appear in the engine's output"
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_exhausted_identity_pool_ends_blocked_not_passed():
    from app.testing.http_client import QAHttpClient
    from app.testing.integrity.engine import PureBlackBoxEngine
    from app.enterprise_controls.scope import ScopeGuard

    target, server, port = await start_customer_target(TargetFlags())
    base = f"http://127.0.0.1:{port}"
    try:
        data, env = _static_brief(base, await _mint_pool(target, 2))
        brief = ExecutionBrief.from_dict(data, env=env)
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=ScopeGuard(ScopePolicy.for_environment(base, max_requests=400, max_requests_per_second=50)), stateless=True)
        result = await PureBlackBoxEngine(http, brief, base_url=base).run()
        await http.aclose()
        assert {f.verdict for f in result.findings} == {Verdict.BLOCKED}, result.verdicts()
        assert any("identity_pool_exhausted" in r for f in result.findings for r in f.reasons)
    finally:
        await server.aclose()


def test_brief_without_a_token_for_an_identity_cannot_authenticate():
    data = public_brief("http://127.0.0.1:9")
    data["allow_signup"] = False
    del data["surface"]["signup"]
    data["identities"] = {"identity_a": {"role": "customer", "synthetic": True, "token_env": "QA_IDENTITY_A_TOKEN"}, "identity_b": {"role": "customer", "synthetic": True, "token_env": "QA_IDENTITY_B_TOKEN"}}
    brief = ExecutionBrief.from_dict(data, env={"QA_IDENTITY_A_TOKEN": "tok_only_a"})
    assert set(brief.tokens) == {"identity_a"}, "an unset token_env yields no token (the engine then reports identity_pool_exhausted: BLOCKED)"


# ------------------------------------------------------------------------------------------------------------------- adversarial self-review
def test_engine_refuses_a_client_that_keeps_cookies():
    from app.testing.http_client import QAHttpClient
    from app.testing.integrity.engine import PureBlackBoxEngine
    from app.core.control_port import PurityViolation

    brief = ExecutionBrief.from_dict(public_brief("http://127.0.0.1:9"), env={})
    stateful = QAHttpClient("http://127.0.0.1:9", 2.0, None, {}, "ua", max_retries=0, guard=None)
    with pytest.raises(PurityViolation) as exc:
        PureBlackBoxEngine(stateful, brief, base_url="http://127.0.0.1:9")
    assert exc.value.code == "engine_requires_stateless_client"
    PureBlackBoxEngine(QAHttpClient("http://127.0.0.1:9", 2.0, None, {}, "ua", max_retries=0, guard=None, stateless=True), brief, base_url="http://127.0.0.1:9")


@pytest.mark.asyncio
async def test_stateless_client_never_carries_a_cookie_between_requests():
    import httpx

    from app.testing.http_client import QAHttpClient

    seen: list[dict] = []
    def handler(request):
        seen.append({k.lower(): v for k, v in dict(request.headers).items()})
        return httpx.Response(200, json={"ok": True}, headers={"Set-Cookie": "sid=target-session-cookie; Path=/"})
    client = QAHttpClient("http://target.test", 2.0, None, {}, "ua", max_retries=0, guard=None, transport=httpx.MockTransport(handler), stateless=True)
    for _ in range(3):
        await client.request("GET", "/api/v1/account/subscription", extra_headers={"Authorization": "Bearer tok_one"})
    assert len(seen) == 3 and all("cookie" not in h for h in seen), "a Set-Cookie of the target must never travel with a later request"
    await client.aclose()


@pytest.mark.asyncio
async def test_tokens_echoed_by_the_target_never_reach_stored_evidence():
    from app.testing.http_client import QAHttpClient
    from app.testing.integrity.engine import PureBlackBoxEngine
    from app.enterprise_controls.scope import ScopeGuard
    from purity_benchmark.customer_target import CustomerLevelTarget

    class Echoing(CustomerLevelTarget):
        async def handle(self, method, raw_path, body, headers):  # a careless target that reflects the bearer token and the payment id in its messages
            status, payload, extra = await super().handle(method, raw_path, body, headers)
            auth = headers.get("authorization", "")
            if isinstance(payload, dict) and auth:
                payload = dict(payload, message=f"hello {auth} ref {payload.get('payment_id', '')}")
            return status, payload, extra

    import asyncio as _asyncio
    from purity_benchmark import customer_target as ct

    target = Echoing(TargetFlags())
    tracked = ct._TrackedServer(None)
    def _on_connect(reader, writer):
        task = _asyncio.ensure_future(ct._serve_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)
    server = await _asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    port = server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    try:
        brief = ExecutionBrief.from_dict(public_brief(base), env={})
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=ScopeGuard(ScopePolicy.for_environment(base, max_requests=400, max_requests_per_second=50)), stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base)
        result = await engine.run(["PBB-U"])
        await http.aclose()
        blob = json.dumps([a.payload for a in engine.ledger.accepted.values()])
        import re

        assert not re.search(r"tok_[0-9a-f]{16}", blob) and not re.search(r"pay_[0-9a-f]{10}", blob), "an echoed token / payment id must be replaced by its pseudonym in EVERY stored artifact (incl. the call that returned it)"
        assert "hello Bearer ref:" in blob, "the echo is kept but its sensitive value is pseudonymised"
        assert engine.ledger.summary()["rejected"] == 0 and result.by_id()["PBB-U"].verdict == Verdict.RULED_OUT
    finally:
        await tracked.aclose()


@pytest.mark.asyncio
async def test_redirect_to_an_internal_route_is_blocked_at_the_hop():
    import asyncio as _asyncio

    from app.testing.http_client import QAHttpClient
    from app.testing.integrity.engine import PureBlackBoxEngine
    from app.enterprise_controls.scope import ScopeGuard
    from purity_benchmark import customer_target as ct

    class Redirecting(ct.CustomerLevelTarget):
        async def handle(self, method, raw_path, body, headers):
            if raw_path.startswith("/api/v1/checkout/return"):
                self.request_log.append((method, "/api/v1/checkout/return"))
                return 302, {}, {"Location": "/internal/ledger"}
            return await super().handle(method, raw_path, body, headers)

    target = Redirecting(TargetFlags())
    tracked = ct._TrackedServer(None)
    def _on_connect(reader, writer):
        task = _asyncio.ensure_future(ct._serve_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)
    server = await _asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    base = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    try:
        brief = ExecutionBrief.from_dict(public_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=400, max_requests_per_second=50))
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=guard, stateless=True)
        result = await PureBlackBoxEngine(http, brief, base_url=base).run(["PBB-U"])
        await http.aclose()
        assert target.internal_hits == 0, "the redirect hop to an internal route must be refused by the purity gate before it reaches the target"
        assert guard.stats()["purity_gate"]["denied"] >= 1 and set(result.verdicts().values()) <= {"UNKNOWN", "BLOCKED"}
    finally:
        await tracked.aclose()
