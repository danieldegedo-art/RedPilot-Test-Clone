"""Black-Box Purity Benchmark tests (mandate: 'mandatory_purity_benchmark').

The five required situations map to scenarios (see purity_benchmark/scenarios.py -> purity_role):
 1 real payment-to-entitlement flaw confirmable only through the protected-feature oracle   -> failed_payment_grants_access
 2 UI-only / redirect-only anomaly must NOT become CONFIRMED_P0                              -> ui_only_anomaly
 3 internal evidence would reveal the problem, external evidence insufficient -> UNKNOWN/BLOCKED -> opaque_async_feature_internal_flaw
 4 target-side internal hint available to the benchmark environment must be ignored           -> hints_decoy_fixed / hints_real_flaw
 5 cross-identity / cross-tenant binding provable only by authorised external comparison      -> cross_tenant_binding / cross_identity_binding
The engine runs BLIND: it receives a base URL and a customer-level Execution Brief, nothing else. Truth lives scorer-side only.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.testing.integrity.regression import build_regression_spec  # noqa: E402
from app.core.control_port import BenchmarkLeak  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402
from purity_benchmark.lab import public_brief, run_scenario  # noqa: E402
from purity_benchmark.scenarios import SCENARIOS, Scenario, T, by_name, secret_tokens  # noqa: E402
from purity_benchmark.scorer import evidence_integrity, metamorphic_equal, score  # noqa: E402

_RUNS: dict[str, object] = {}


async def _all():
    for sc in SCENARIOS:
        if sc.name not in _RUNS:
            _RUNS[sc.name] = await run_scenario(sc)
    return _RUNS


@pytest.mark.asyncio
async def test_blind_matrix_matches_ground_truth():
    runs = await _all()
    s = score(runs.values())
    oc = s["outcome_counts"]
    assert s["scenarios"] == len(SCENARIOS) >= 19 and s["truth_counts"]["P0"] >= 15
    assert oc["TP"] == s["truth_counts"]["P0"], f"every seeded, externally provable P0 must be confirmed: {oc}"
    assert oc["FP"] == 0, "no false positive (UI-only, decoy hints, within-tolerance lag, open/opaque/broken targets)"
    assert oc["FALSE_ASSURANCE"] == 0 and oc["FALSE_ASSURANCE_UNPROVABLE"] == 0, "never RULED_OUT where a P0 exists or where nothing external can prove anything"
    assert oc["MISSED_AS_UNKNOWN"] == 0 and oc["DIV_MISSED"] == 0
    assert oc["HONEST_UNKNOWN"] == s["truth_counts"]["UNK"] and oc["TN"] == s["truth_counts"]["SAFE"] - oc["INCONCLUSIVE_ON_SAFE"]
    assert s["confirmed_p0_without_external_oracle"] == 0 and s["purity_gate_denials_caused_by_engine"] == 0
    bad = [p for p in s["pairs_detail"] if p["outcome"] not in ("TP", "TN", "HONEST_UNKNOWN", "DIV_OK", "INCONCLUSIVE_ON_SAFE")]
    assert not bad, bad


@pytest.mark.asyncio
async def test_purity_benchmark_required_situations():
    runs = await _all()
    v = lambda name: runs[name].result.by_id()  # noqa: E731
    # 1 confirmed ONLY through the external protected-feature oracle
    f = v("failed_payment_grants_access")["PBB-U"]
    assert f.verdict == Verdict.CONFIRMED_P0 and f.token and f.token.covers("PBB-U")
    assert f.to_dict()["confirmed_via_oracle_gate"] and f.metrics["variants"]
    # 2 UI-only anomaly: never confirmed, divergence reported
    ui = v("ui_only_anomaly")
    assert not runs["ui_only_anomaly"].result.confirmed() and ui["PBB-U"].divergences and ui["PBB-E"].divergences
    # 3 internal evidence would reveal the flaw; external evidence insufficient -> UNKNOWN/BLOCKED, internal routes untouched
    op = runs["opaque_async_feature_internal_flaw"]
    assert {x.verdict for x in op.result.findings} <= {Verdict.UNKNOWN, Verdict.BLOCKED} and op.internal_hits == 0
    assert any(e["plan"] for e in op.target.entitlements.values()), "precondition: the internal flaw exists (an unpaid tenant holds an entitlement)"
    # 4 hints present and ignored
    for name in ("hints_decoy_fixed", "hints_real_flaw"):
        r = runs[name]
        assert r.result.stats["volunteered_hints_dropped"] > 0 and r.internal_hits == 0 and "x-debug-entitlement" in r.result.stats["hint_names_sample"]
    assert all(x.verdict == Verdict.RULED_OUT for x in runs["hints_decoy_fixed"].result.findings), "lying hints must not create findings"
    # 5 cross-tenant / cross-identity
    assert v("cross_tenant_binding")["PBB-G"].verdict == Verdict.CONFIRMED_P0 and v("cross_identity_binding")["PBB-X"].verdict == Verdict.CONFIRMED_P0
    assert v("fully_fixed")["PBB-G"].verdict == Verdict.RULED_OUT and v("fully_fixed")["PBB-X"].verdict == Verdict.RULED_OUT
    # clean-session reproducibility + safe regression
    spec = build_regression_spec(runs["failed_payment_grants_access"].result, runs["failed_payment_grants_access"].brief)
    assert any(c["kind"] == "regression_for_confirmed_p0" and c["expect_after_fix"] == "RULED_OUT" for c in spec["checks"])


@pytest.mark.asyncio
async def test_internal_routes_and_hints_are_ignored():
    runs = await _all()
    assert sum(r.internal_hits for r in runs.values()) == 0, "no engine run may touch /internal, /admin or /__benchmark__ -- they exist in every benchmark target"
    ok, diffs = metamorphic_equal(runs["failed_payment_grants_access"], runs["hints_real_flaw"])
    assert ok, f"verdicts must not depend on benchmark-environment hints: {diffs}"
    for r in runs.values():
        assert not r.result.stats["guard"]["purity_gate"]["denied"], r.scenario.name
        paths = {p for _, p in r.target.request_log}
        assert not any(p.startswith(("/internal", "/admin", "/__benchmark__")) for p in paths), (r.scenario.name, paths)


@pytest.mark.asyncio
async def test_engine_inputs_contain_no_ground_truth():
    runs = await _all()
    for name, r in runs.items():
        tokens = [t.lower() for t in secret_tokens(r.scenario)]
        blob = json.dumps({"brief": r.brief_dict, "public": r.brief.to_public_dict(), "requests": [p for _, p in r.target.request_log], "headers": r.target.request_headers_seen,
                           "artifacts": [a.payload for a in r.ledger.accepted.values()]}, default=str).lower()
        leaked = [t for t in tokens if t in blob]
        assert not leaked, f"{name}: ground truth reached the engine or its evidence: {leaked}"
        assert r.blindness_checks >= 4


@pytest.mark.asyncio
async def test_a_leak_of_benchmark_ground_truth_into_the_brief_aborts_the_run():
    leaky = Scenario("leaky_probe", {}, T(), brief_overrides={"authorized_by": "failed_payment_grants_access"})
    with pytest.raises(BenchmarkLeak):
        await run_scenario(leaky)
    leaky2 = Scenario("leaky_probe_2", {}, T(), brief_overrides={"flaw_hint": "return flow"})
    with pytest.raises(BenchmarkLeak):
        await run_scenario(leaky2)


@pytest.mark.asyncio
async def test_refund_scenarios():
    runs = await _all()
    r = lambda name: runs[name].result.by_id()["PBB-R"]  # noqa: E731
    assert r("refund_retention").verdict == Verdict.CONFIRMED_P0 and r("refund_retention").metrics["first_denied_at_s"] is None
    assert r("revocation_lag_beyond_sla").verdict == Verdict.CONFIRMED_P0 and r("revocation_lag_beyond_sla").metrics["declared_tolerance_s"] == 0.5
    within = r("revocation_lag_within_sla")
    assert within.verdict == Verdict.RULED_OUT and 0.3 < within.metrics["first_denied_at_s"] <= 2.0, "the measured lag is an externally observed upper bound"
    fixed = r("fully_fixed")
    assert fixed.verdict == Verdict.RULED_OUT and fixed.metrics["first_denied_at_s"] <= 0.2


@pytest.mark.asyncio
async def test_unmodelled_flaw_is_a_listed_gap_not_a_clean_bill_of_health():
    runs = await _all()
    s = score([runs["unprobed_coupon_flaw"]])
    assert s["blind_spot_flaws_total"] == 1 and s["blind_spot_flaws_detected"] == 0 and s["blind_spot_flaws_listed_as_gap"] == 1
    assert set(runs["unprobed_coupon_flaw"].result.verdicts().values()) == {"RULED_OUT"}, "the modelled classes are genuinely clean in that target"


@pytest.mark.asyncio
async def test_evidence_is_externally_classified_redacted_and_hash_verified():
    runs = await _all()
    for name, r in runs.items():
        ev = evidence_integrity(r)
        assert ev["bad_hash"] == 0 and ev["bad_classification"] == 0 and ev["missing_provenance_fields"] == 0 and ev["unredacted_identifiers_or_tokens"] == 0, (name, ev)
        assert r.result.ledger_summary["rejected"] == 0, name
        assert set(r.result.ledger_summary["accepted_by_classification"]) <= {"controlled_black_box_benchmark"}
    from app.testing.integrity.brief import ExecutionBrief
    from purity_benchmark.customer_target import TargetFlags, start_customer_target
    from app.testing.integrity.engine import PureBlackBoxEngine
    from app.testing.http_client import QAHttpClient
    from app.enterprise_controls.scope import ScopeGuard, ScopePolicy

    target, server, port = await start_customer_target(TargetFlags())
    base = f"http://127.0.0.1:{port}"
    try:  # a customer sandbox (not a benchmark) is classified differently
        brief = ExecutionBrief.from_dict(public_brief(base, {"target_kind": "customer_sandbox", "environment": "sandbox"}), env={})
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=ScopeGuard(ScopePolicy.for_environment(base, max_requests=300, max_requests_per_second=50)), stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base)
        res = await engine.run(["PBB-U"])
        assert set(res.ledger_summary["accepted_by_classification"]) == {"approved_sandbox_payment", "external_customer_api"}
        await http.aclose()
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_clean_session_reproduction_is_independent():
    runs = await _all()
    r = runs["cross_tenant_binding"]
    arts = list(r.ledger.accepted.values())
    post = next(a for a in arts if a.payload["label"] == "G:B:post")
    repro = next(a for a in arts if a.payload["label"] == "PBB-G:repro")
    assert post.provenance.identity_alias == repro.provenance.identity_alias, "same identity, independent session"
    assert post.provenance.session_isolation_id != repro.provenance.session_isolation_id
    k = next(a for a in arts if a.payload["label"] == "PBB-G:K:recheck")
    assert k.payload["response"]["status"] in (402, 403) and post.payload["response"]["status"] == 200


@pytest.mark.asyncio
async def test_three_fresh_runs_give_the_same_verdicts():
    for name in ("failed_payment_grants_access", "cross_tenant_binding"):
        first = (await _all())[name].result.verdicts()
        for _ in range(2):
            assert (await run_scenario(by_name(name))).result.verdicts() == first, name


@pytest.mark.asyncio
async def test_every_scenario_stays_low_volume_and_respects_the_budget():
    for name, r in (await _all()).items():
        calls = r.result.stats["customer_level_calls"]
        assert calls <= 140, (name, calls)
        g = r.result.stats["guard"]
        assert g["requests_used"] <= r.brief.limits.max_requests and r.request_count_at_target == calls, name
