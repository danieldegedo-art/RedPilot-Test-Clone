"""ZR-004 / B3: app/testing/integrity/oracle_calibration.py.

Stdlib only (ledger verifier uses pesm.InMemoryPESMStore, already dependency-free).
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.oracle_calibration import (  # noqa: E402
    CONFIDENCE_WEIGHT, LedgerLookup, OracleNotCalibrated, OracleTier, ResourceDelta,
    calibrate, calibrate_oracle, calibration_from_outcomes, make_feature_use_verifier,
    make_ledger_cross_check_verifier, resource_delta_verifier,
    ruled_out_is_trustworthy, ruled_out_result_is_trustworthy, select_tier,
)
from app.testing.pesm import EntitlementState, EntitlementStatus, InMemoryPESMStore  # noqa: E402

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)


def _always(outcome: str):
    async def v(_session):
        return outcome
    return v


def _echo_label(positive_label: str):
    """Returns 'allowed' only for the probe matching positive_label -- a
    verifier that discriminates correctly, for the positive-calibration tests."""
    async def v(session):
        return "allowed" if session == positive_label else "denied"
    return v


# ---- the confidence table matches Section 14.1 exactly --------------------------

def test_confidence_weights_match_section_14_1_ordering():
    order = sorted(OracleTier, key=lambda t: -CONFIDENCE_WEIGHT[t])
    assert order == [OracleTier.LEDGER_BILLING_CROSS_CHECK, OracleTier.DURABLE_STATE_CHANGE,
                     OracleTier.EXTERNAL_SIDE_EFFECT, OracleTier.RESOURCE_DATA_DELTA, OracleTier.NON_AUTHORITATIVE]
    assert CONFIDENCE_WEIGHT[OracleTier.NON_AUTHORITATIVE] == 0.0
    assert CONFIDENCE_WEIGHT[OracleTier.LEDGER_BILLING_CROSS_CHECK] == 1.0


# ---- calibration: both probes checked, neither short-circuits -------------------

def test_calibration_requires_both_probes_to_pass():
    cases = {
        ("allowed", "denied"): True,    # both correct
        ("denied", "denied"): False,    # positive probe wrong
        ("allowed", "allowed"): False,  # negative probe wrong
        ("denied", "allowed"): False,   # both wrong
        ("indeterminate", "denied"): False,
    }
    for (pos_answer, neg_answer), expected in cases.items():
        results = {"pos": pos_answer, "neg": neg_answer}

        async def v(session, results=results):
            return results[session]

        result = asyncio.run(calibrate(OracleTier.DURABLE_STATE_CHANGE, v, "pos", "neg"))
        assert result.calibrated is expected, (pos_answer, neg_answer)


def test_calibration_failure_reason_names_which_probe_failed():
    async def wrong_positive(session):
        return "denied" if session == "pos" else "denied"
    result = asyncio.run(calibrate(OracleTier.DURABLE_STATE_CHANGE, wrong_positive, "pos", "neg"))
    assert not result.calibrated and "known-positive" in result.reason

    async def wrong_negative(session):
        return "allowed"
    result = asyncio.run(calibrate(OracleTier.DURABLE_STATE_CHANGE, wrong_negative, "pos", "neg"))
    assert not result.calibrated and "known-negative" in result.reason


# ---- CalibratedOracle: refuses to run uncalibrated -------------------------------

def test_an_uncalibrated_oracle_refuses_to_check_anything():
    async def go():
        oracle = await calibrate_oracle(OracleTier.DURABLE_STATE_CHANGE, _always("denied"), "pos", "neg")
        assert not oracle.calibration.calibrated
        try:
            await oracle.check("real-session")
            raise AssertionError("expected OracleNotCalibrated")
        except OracleNotCalibrated as e:
            assert "DURABLE_STATE_CHANGE" not in str(e)  # uses .value (lowercase), not the member name
            assert "durable_state_change" in str(e)
    asyncio.run(go())


def test_a_calibrated_oracle_runs_normally_and_reports_its_tiers_weight():
    async def go():
        oracle = await calibrate_oracle(OracleTier.LEDGER_BILLING_CROSS_CHECK, _echo_label("pos"), "pos", "neg")
        assert oracle.calibration.calibrated
        assert oracle.confidence_weight == 1.0
        assert await oracle.check("pos") == "allowed"
        assert await oracle.check("neg") == "denied"
    asyncio.run(go())


def test_confidence_weight_is_zero_for_an_uncalibrated_oracle_regardless_of_tier():
    async def go():
        oracle = await calibrate_oracle(OracleTier.LEDGER_BILLING_CROSS_CHECK, _always("denied"), "pos", "neg")
        assert oracle.confidence_weight == 0.0  # would be 1.0 if calibrated -- must not leak an un-earned weight
    asyncio.run(go())


# ---- the H4 fix: ruled_out_is_trustworthy ----------------------------------------

def test_ruled_out_from_a_calibrated_oracle_is_trustworthy():
    async def go():
        oracle = await calibrate_oracle(OracleTier.DURABLE_STATE_CHANGE, _echo_label("pos"), "pos", "neg")
        return ruled_out_is_trustworthy(oracle)
    trustworthy, reason = asyncio.run(go())
    assert trustworthy and reason is None


def test_ruled_out_from_an_uncalibrated_oracle_is_never_trustworthy_this_is_h4():
    """The actual bug class ZR-004 exists to close: an oracle that can't tell
    allowed from denied still returning 'denied' for a real hypothesis, and
    that being silently accepted as RULED_OUT."""
    async def go():
        oracle = await calibrate_oracle(OracleTier.DURABLE_STATE_CHANGE, _always("denied"), "pos", "neg")
        return ruled_out_is_trustworthy(oracle)
    trustworthy, reason = asyncio.run(go())
    assert not trustworthy and "not calibrated" in reason and "durable_state_change" in reason


# ---- select_tier: highest confidence first, None when nothing qualifies ---------

def test_select_tier_picks_highest_confidence_available():
    assert select_tier(frozenset({"independent_read", "quota_counter", "ledger_access"})) == OracleTier.LEDGER_BILLING_CROSS_CHECK
    assert select_tier(frozenset({"independent_read", "quota_counter"})) == OracleTier.DURABLE_STATE_CHANGE
    assert select_tier(frozenset({"quota_counter"})) == OracleTier.RESOURCE_DATA_DELTA


def test_select_tier_returns_none_when_nothing_qualifies_never_guesses():
    assert select_tier(frozenset()) is None
    assert select_tier(frozenset({"something_recon_found_that_matches_no_tier"})) is None


def test_select_tier_never_returns_non_authoritative():
    """NON_AUTHORITATIVE is zero-confidence by definition (ZR-024) -- it must
    never be what a target with no real evidence "falls back" to."""
    for evidence in (frozenset(), frozenset({"x"}), frozenset({"ledger_access", "independent_read", "side_effect_channel", "quota_counter"})):
        assert select_tier(evidence) != OracleTier.NON_AUTHORITATIVE


# ---- the ledger cross-check verifier, against a real PESM store -----------------

def test_ledger_cross_check_verifier_reads_pesm_as_the_source_of_truth():
    async def go():
        store = InMemoryPESMStore()
        await store.record_state(EntitlementState("feat-1", "alice", None, EntitlementStatus.ACTIVE, NOW, "test"))
        verify = make_ledger_cross_check_verifier(store)
        active = await verify(LedgerLookup("feat-1", "alice", None, as_of=NOW))
        unknown_identity = await verify(LedgerLookup("feat-1", "nobody", None, as_of=NOW))
        return active, unknown_identity
    active, unknown = asyncio.run(go())
    assert active == "allowed" and unknown == "indeterminate"


def test_ledger_cross_check_verifier_denied_for_never_granted_state():
    async def go():
        store = InMemoryPESMStore()
        await store.record_state(EntitlementState("feat-1", "bob", None, EntitlementStatus.NEVER_GRANTED, NOW, "test"))
        return await make_ledger_cross_check_verifier(store)(LedgerLookup("feat-1", "bob", None, as_of=NOW))
    assert asyncio.run(go()) == "denied"


def test_ledger_cross_check_respects_as_of_does_not_see_the_future():
    async def go():
        store = InMemoryPESMStore()
        await store.record_state(EntitlementState("feat-1", "carol", None, EntitlementStatus.ACTIVE, NOW, "test"))
        verify = make_ledger_cross_check_verifier(store)
        before_grant = datetime(2026, 10, 1, tzinfo=timezone.utc)
        return await verify(LedgerLookup("feat-1", "carol", None, as_of=before_grant))
    assert asyncio.run(go()) == "indeterminate"


# ---- the resource-delta verifier, pure arithmetic --------------------------------

def test_resource_delta_allowed_when_delta_meets_the_declared_minimum():
    assert asyncio.run(resource_delta_verifier(ResourceDelta(before=10, after=12, expected_min_delta=2))) == "allowed"


def test_resource_delta_indeterminate_when_positive_but_below_minimum():
    assert asyncio.run(resource_delta_verifier(ResourceDelta(before=10, after=10.5, expected_min_delta=2))) == "indeterminate"


def test_resource_delta_denied_when_zero_or_negative():
    assert asyncio.run(resource_delta_verifier(ResourceDelta(before=10, after=10, expected_min_delta=1))) == "denied"
    assert asyncio.run(resource_delta_verifier(ResourceDelta(before=10, after=8, expected_min_delta=1))) == "denied"


# ---- outcome-based calibration + the ProtectedFeatureOracle verifier wrapper -----

def test_calibration_from_outcomes_matches_running_the_probes():
    assert calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "allowed", "denied").calibrated
    assert not calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "denied", "denied").calibrated
    assert not calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "allowed", "allowed").calibrated
    r = calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "indeterminate", "denied")
    assert not r.calibrated and "known-positive" in r.reason


def test_ruled_out_result_variant_agrees_with_the_oracle_variant():
    good = calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "allowed", "denied")
    bad = calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "denied", "denied")
    assert ruled_out_result_is_trustworthy(good) == (True, None)
    ok, reason = ruled_out_result_is_trustworthy(bad)
    assert not ok and "not calibrated" in reason and "durable_state_change" in reason


class _FakeObs:
    def __init__(self, outcome):
        self.outcome = outcome


class _FakeOracle:
    """Minimal stand-in with ProtectedFeatureOracle's check() contract."""

    def __init__(self, by_session):
        self._by = by_session
        self.calls = []

    async def check(self, session, feature, *, oracle_id):
        self.calls.append((session, oracle_id))
        return _FakeObs(self._by[session])


def test_make_feature_use_verifier_wraps_the_oracle_outcome_and_calibrates():
    async def go():
        oracle = _FakeOracle({"paid": "allowed", "clean": "denied"})
        verifier = make_feature_use_verifier(oracle, feature=object(), oracle_id="CAL:primary")
        result = await calibrate(OracleTier.DURABLE_STATE_CHANGE, verifier, "paid", "clean")
        return result, oracle
    result, oracle = asyncio.run(go())
    assert result.calibrated
    assert oracle.calls == [("paid", "CAL:primary"), ("clean", "CAL:primary")]


def test_make_feature_use_verifier_surfaces_a_non_discriminating_oracle():
    async def go():
        oracle = _FakeOracle({"paid": "denied", "clean": "denied"})  # can't tell paid from clean -> H4
        verifier = make_feature_use_verifier(oracle, feature=object(), oracle_id="CAL:primary")
        return await calibrate(OracleTier.DURABLE_STATE_CHANGE, verifier, "paid", "clean")
    result = asyncio.run(go())
    assert not result.calibrated and ruled_out_result_is_trustworthy(result)[0] is False


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
