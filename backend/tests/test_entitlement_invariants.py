"""B2: tests for app/testing/integrity/entitlement_invariants.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.entitlement_invariants import (  # noqa: E402
    LIBRARY, EntitlementObservation, InvariantStatus, check, check_all, check_all_payload, get,
)
from app.testing.integrity.findings import EXPERIMENT_CLASSES, SPECS  # noqa: E402

VIOLATION_CASES = {
    "PBB-U": dict(payment_qualifying=False, feature_usable=True),
    "PBB-F": dict(paid_tier_rank=1, used_tier_rank=2),
    "PBB-H": dict(billed_below_public_price=True, top_tier_usable=True),
    "PBB-C": dict(uses_observed=3, paid_quota=1),
    "PBB-G": dict(feature_usable=True, is_payer_tenant=False),
    "PBB-X": dict(feature_usable=True, is_payer_identity=False),
    "PBB-R": dict(refund_confirmed=True, feature_usable=True, beyond_revocation_tolerance=True),
    "PBB-E": dict(view_claims_paid=True, server_allows=False),
    "PBB-LEAK": dict(unrelated_identity=True, feature_usable=True),
    "PBB-OPEN": dict(never_paid=True, feature_usable=True),
}


def test_each_invariant_detects_its_own_violation():
    for hyp, kw in VIOLATION_CASES.items():
        res = check(get(hyp), EntitlementObservation(**kw))
        assert res.status == InvariantStatus.VIOLATED, (hyp, res.status)


def test_hold_cases():
    assert check(get("PBB-U"), EntitlementObservation(payment_qualifying=False, feature_usable=False)).status == InvariantStatus.HOLD
    # a refund within the revocation tolerance must HOLD, not fire
    assert check(get("PBB-R"), EntitlementObservation(refund_confirmed=True, feature_usable=True, beyond_revocation_tolerance=False)).status == InvariantStatus.HOLD
    # tier used == tier paid must HOLD (not merely >=)
    assert check(get("PBB-F"), EntitlementObservation(paid_tier_rank=1, used_tier_rank=1)).status == InvariantStatus.HOLD
    # a tenant that IS the payer must HOLD
    assert check(get("PBB-G"), EntitlementObservation(feature_usable=True, is_payer_tenant=True)).status == InvariantStatus.HOLD


def test_missing_input_is_inconclusive_not_guessed():
    assert check(get("PBB-U"), EntitlementObservation(payment_qualifying=False)).status == InvariantStatus.INCONCLUSIVE  # feature_usable unknown
    assert check(get("PBB-R"), EntitlementObservation(refund_confirmed=True, feature_usable=True)).status == InvariantStatus.INCONCLUSIVE  # tolerance unknown


def test_statements_are_sourced_from_the_oracle_specs_not_reworded():
    for inv in LIBRARY:
        assert inv.statement == SPECS[inv.invariant_id].invariant


def test_one_invariant_per_oracle_class_each_with_a_false_positive_guard():
    assert {i.invariant_id for i in LIBRARY} == set(EXPERIMENT_CLASSES)
    assert all(i.false_positive_guard for i in LIBRARY)


def test_pbb_e_divergence_is_flagged_non_authoritative():
    assert "NON-AUTHORITATIVE" in get("PBB-E").false_positive_guard  # a view/server divergence is never a P0 on its own


def test_check_all_and_payload_are_json_safe():
    obs = EntitlementObservation(payment_qualifying=False, feature_usable=True)  # PBB-U violated; most others inconclusive
    payload = check_all_payload(obs)
    assert "PBB-U" in payload["violated"] and len(payload["results"]) == len(EXPERIMENT_CLASSES)
    assert json.loads(json.dumps(payload)) == payload
