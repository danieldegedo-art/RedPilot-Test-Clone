"""Executable regression for the Oracle Engine and its benchmark. Every scorecard claim that matters is pinned here,
including the legacy prober's documented weaknesses (so 'the baseline was bad' stays a tested fact, not a story).

Runs under pytest and as a plain script. The full benchmark (17 scenarios x 10 oracles + legacy + reproducibility)
is executed ONCE and shared by the tests below."""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

from benchmark_lab import P0_LIKE, run_benchmark  # noqa: E402
from entitlement_target import EntitlementTarget, start_entitlement_target  # noqa: E402
from oracle_engine import OracleEngine  # noqa: E402

_CARD: dict | None = None


def _card() -> dict:
    global _CARD
    if _CARD is None:
        _CARD = asyncio.run(run_benchmark(repro_runs=2))
    return _CARD


def test_engine_matches_every_expectation_derived_from_the_target_flags() -> None:
    card = _card()
    assert card["regression_pass_rate"]["counts"]["mismatches"] == [], card["regression_pass_rate"]["counts"]["mismatches"]
    assert card["regression_pass_rate"]["post"] == 1.0 and card["scenario_count"] == 17


def test_zero_false_positives_and_zero_false_assurance_and_the_legacy_baseline_is_documented() -> None:
    card = _card()
    assert card["false_positive_rate"]["post"] == 0.0, "the engine reported a P0 where none exists"
    assert card["false_assurance_rate"]["post"] == 0.0, "the engine declared a real P0 clean"
    assert card["false_positive_rate"]["baseline"] > 0, "the legacy prober's false positives (free-tier decoy) must stay reproducible evidence"
    assert card["false_assurance_rate"]["baseline"] > 0.5, "the legacy prober's masking blind spot must stay reproducible evidence"


def test_legacy_prober_reports_two_false_p0s_on_the_free_tier_decoy_the_engine_reports_none() -> None:
    card = _card()
    legacy = card["legacy_matrix"]["free_tier_decoy"]
    assert legacy["B"] == "confirmed_p0" and legacy["G"] == "confirmed_p0", "documented baseline: BB-001 and BB-004 raise a false confirmed_p0"
    assert not any(v in P0_LIKE for v in card["matrix"]["free_tier_decoy"].values())
    assert not any(v in P0_LIKE for v in card["matrix"]["free_tier_declared_open"].values())


def test_where_legacy_can_operate_at_all_raw_detection_is_equal_the_gap_is_capability_not_skill() -> None:
    sl = _card()["seeded_p0_detection_rate"]["perimeter_off_slice"]
    assert sl["engine"] >= sl["legacy"] == 1.0, "no perimeter: legacy detects B,C,F,G too -- the honest fair comparison"
    assert _card()["seeded_p0_detection_rate"]["post"] >= 0.8


def test_masking_is_never_ruled_out_without_a_secret_and_is_found_with_one() -> None:
    matrix = _card()["matrix"]
    for cls in "BCFGH":
        assert matrix["signature_only_fixed_no_secret"][cls] == "unknown_critical_exposure", (cls, "perimeter rejection must read UNKNOWN, never ruled_out")
        assert matrix["signature_only_fixed"][cls] == "confirmed_p0", (cls, "with a sandbox secret the bug behind the perimeter must be found")
    assert matrix["signature_only_fixed_no_secret"]["A"] == "ruled_out" == matrix["signature_only_fixed"]["A"]
    legacy = _card()["legacy_matrix"]["signature_only_fixed"]
    assert all(legacy[c] == "ruled_out" for c in "BCFG"), "documented baseline: the legacy prober declares the masked P0s clean"


def test_grant_recorded_without_usable_benefit_is_a_divergence_not_a_p0_and_not_ruled_out() -> None:
    assert _card()["matrix"]["only_B_status_trust"]["B"] == "observed_divergence"
    assert _card()["matrix"]["stale_status_view"]["E"] == "observed_divergence"


def test_chains_reproducibility_and_completeness_claims() -> None:
    card = _card()
    assert card["multi_step_chain_detection_rate"]["post"] == 1.0
    assert card["confirmed_finding_reproducibility"]["post"] >= 0.9, card["confirmed_finding_reproducibility"]["counts"]
    assert card["oracle_completeness"]["post"] == 1.0 and card["oracle_completeness"]["baseline"] == 0.4
    assert card["evidence_artifact_completeness"]["post"] == 1.0
    assert card["newly_testable_p0_classes"]["newly_testable"] == ["A", "D", "E", "H", "I"]


def test_setup_failure_becomes_blocked_not_a_crash_and_not_a_clean_result() -> None:
    card = _card()
    assert "broken_setup" in card["robustness"]["legacy_crashed_on"], "documented baseline: the legacy prober crashes on a failed setup"
    assert len(card["robustness"]["new_blocked_instead"]) == 9
    assert card["matrix"]["broken_setup"]["BASELINE"] == "ruled_out"


def test_a_stop_probe_turns_every_oracle_into_blocked() -> None:
    async def scenario() -> None:
        _, server, port = await start_entitlement_target(EntitlementTarget())
        engine = OracleEngine(f"http://127.0.0.1:{port}")
        try:
            result = await engine.run_all(stop=lambda: "budget_exhausted")
        finally:
            await engine.aclose()
            server.close()
            await server.wait_closed()
        assert len(result.findings) == 10 and all(f.blocked_reason and "budget_exhausted" in f.blocked_reason and f.verdict is None for f in result.findings)

    asyncio.run(scenario())


def test_the_engine_shares_an_injected_client_and_does_not_close_it() -> None:
    from app.testing.http_client import QAHttpClient

    async def scenario() -> None:
        _, server, port = await start_entitlement_target(EntitlementTarget())
        client = QAHttpClient(base_url=f"http://127.0.0.1:{port}", timeout_seconds=3.0, proxy_url=None, headers={}, user_agent="t")
        engine = OracleEngine(client=client)
        try:
            await engine.oracle_baseline()
            await engine.aclose()  # must NOT close the injected client
            _, resp = await client.request("GET", "/api/v1/access/still_open")
            assert resp.status_code == 200, "the injected client must still be usable after engine.aclose()"
        finally:
            await client.aclose()
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


if __name__ == "__main__":
    import inspect
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and inspect.isfunction(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{'ALL PASSED' if not failures else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
