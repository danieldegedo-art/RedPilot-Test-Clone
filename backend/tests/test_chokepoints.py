"""B42 (bounded form): tests for app/testing/integrity/chokepoints.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.chokepoints import (  # noqa: E402
    CONTROL_POINTS, chokepoint_report, chokepoint_weights, rank_chokepoints,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402

FLOWS = {"PBB-U": "checkout", "PBB-E": "entitlement", "PBB-F": "subscription", "PBB-H": "payment", "PBB-G": "entitlement",
         "PBB-X": "payment", "PBB-LEAK": "entitlement", "PBB-C": "checkout", "PBB-R": "refund", "PBB-OPEN": "entitlement"}
ALL = list(FLOWS)


class _F:
    def __init__(self, hid, verdict):
        self.hypothesis_id = hid
        self.verdict = verdict
        self.affected_flow = FLOWS[hid]


class _Result:
    def __init__(self, verdicts):
        self._f = [_F(h, v) for h, v in verdicts.items()]

    @property
    def findings(self):
        return self._f

    def by_id(self):
        return {f.hypothesis_id: f for f in self._f}


def _all_ruled_out(**overrides):
    v = {h: Verdict.RULED_OUT for h in ALL}
    v.update(overrides)
    return _Result(v)


def _cp(ranked, control_id):
    return next(c for c in ranked if c.control_id == control_id)


def test_six_chokepoints_with_correct_cascade_width():
    ranked = rank_chokepoints(_all_ruled_out())
    assert {c.control_id for c in ranked} == set(CONTROL_POINTS)
    assert _cp(ranked, "entitlement_identity_binding").cascade_width == 3  # PBB-G/X/LEAK
    assert _cp(ranked, "payment_event_verification").cascade_width == 2    # PBB-U/E
    assert _cp(ranked, "grant_idempotency").cascade_width == 1             # PBB-C


def test_a_confirmed_finding_marks_its_chokepoint_proven_flawed_and_ranks_it_first():
    ranked = rank_chokepoints(_all_ruled_out(**{"PBB-U": Verdict.CONFIRMED_P0}))
    assert ranked[0].control_id == "payment_event_verification"
    assert ranked[0].confirmed == ("PBB-U",) and ranked[0].priority_rank == 1
    # a PROVEN-flawed cascade-2 chokepoint outranks a non-confirmed cascade-3 one
    assert ranked[1].control_id == "entitlement_identity_binding" and ranked[1].confirmed == ()


def test_cascade_width_is_structural_even_if_not_all_governed_classes_ran():
    ranked = rank_chokepoints(_Result({"PBB-G": Verdict.RULED_OUT}))
    cp = _cp(ranked, "entitlement_identity_binding")
    assert cp.cascade_width == 3 and cp.confirmed == ()  # width counts the full governed set


def test_confidence_is_provisional_when_the_region_is_sparsely_covered():
    sparse = rank_chokepoints(_Result({"PBB-G": Verdict.RULED_OUT}))  # 1 of 3 governed classes tested
    assert _cp(sparse, "entitlement_identity_binding").confidence == "provisional"
    dense = rank_chokepoints(_Result({"PBB-G": Verdict.RULED_OUT, "PBB-X": Verdict.RULED_OUT}))  # 2 of 3
    assert _cp(dense, "entitlement_identity_binding").confidence == "high"


def test_weights_boost_wide_cascades_and_halve_provisional_ones():
    dense = chokepoint_weights(_all_ruled_out())
    assert dense["PBB-G"] == 3.0  # cascade 3, high confidence
    sparse = chokepoint_weights(_Result({"PBB-G": Verdict.RULED_OUT}))
    assert sparse["PBB-G"] == 1.5  # cascade 3 but provisional -> halved, never inflated


def test_attack_distance_is_the_nearest_governed_flow():
    ranked = rank_chokepoints(_all_ruled_out())
    assert _cp(ranked, "payment_event_verification").attack_distance == 0  # PBB-U is checkout (entry, distance 0)


def test_report_is_json_safe_and_names_the_highest_leverage_fix():
    rep = chokepoint_report(_all_ruled_out(**{"PBB-U": Verdict.CONFIRMED_P0}))
    assert json.loads(json.dumps(rep)) == rep
    assert rep["summary"]["highest_leverage_fix"] == "payment_event_verification"
    assert rep["summary"]["proven_flawed"] == ["payment_event_verification"]
