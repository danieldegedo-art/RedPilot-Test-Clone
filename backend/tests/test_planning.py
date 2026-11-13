"""ZR-010: tests for app/testing/integrity/planning.py (next-best-action / info-gain). Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.planning import (  # noqa: E402
    information_gain, next_best_actions, next_best_actions_payload,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402

PARTIAL = Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE


def _ids(actions):
    return [a.hypothesis_id for a in actions]


def test_chokepoint_leverage_decides_when_only_it_differs():
    # both COVERED + both RULED_OUT -> only chokepoint leverage differs, so it decides
    acts = next_best_actions(["PBB-C", "PBB-U"], chokepoint_weights={"PBB-U": 3.0, "PBB-C": 1.0},
                             coverage_by_hypothesis={"PBB-U": "COVERED", "PBB-C": "COVERED"},
                             prior_verdicts={"PBB-U": Verdict.RULED_OUT, "PBB-C": Verdict.RULED_OUT})
    assert _ids(acts)[0] == "PBB-U"


def test_unknown_coverage_beats_covered_even_against_higher_base_risk():
    acts = next_best_actions(["PBB-F", "PBB-C"], coverage_by_hypothesis={"PBB-F": "COVERED", "PBB-C": "UNKNOWN"})
    assert _ids(acts)[0] == "PBB-C"  # PBB-F has higher base risk (90 vs 75); coverage gap still wins the info-gain sort


def test_an_open_lead_outranks_a_ruled_out_class_despite_higher_base_risk():
    acts = next_best_actions(["PBB-U", "PBB-F"], prior_verdicts={"PBB-U": Verdict.RULED_OUT, "PBB-F": PARTIAL},
                             coverage_by_hypothesis={"PBB-U": "COVERED", "PBB-F": "COVERED"})
    assert _ids(acts)[0] == "PBB-F"  # PBB-U base risk 100 > PBB-F 90, but PBB-U is resolved -> nothing to learn


def test_ties_break_by_base_risk_then_input_order():
    acts = next_best_actions(["PBB-C", "PBB-U"])  # no signals -> equal info-gain
    assert _ids(acts) == ["PBB-U", "PBB-C"]  # PBB-U base risk 100 > PBB-C 75


def test_bounded_ranks_only_the_given_hypotheses():
    assert _ids(next_best_actions(["PBB-U"])) == ["PBB-U"]
    assert set(_ids(next_best_actions(["PBB-U", "PBB-C"]))) == {"PBB-U", "PBB-C"}  # never invents a hypothesis


def test_blocked_coverage_contributes_no_gap():
    comp = information_gain(["PBB-R"], coverage_by_hypothesis={"PBB-R": "BLOCKED"})["PBB-R"]
    assert comp["coverage_gap"] == 0.0  # cannot learn more without a new capability


def test_components_are_surfaced_and_payload_is_json_safe():
    acts = next_best_actions(["PBB-U", "PBB-C"], chokepoint_weights={"PBB-U": 3.0, "PBB-C": 1.0})
    assert set(acts[0].components) == {"coverage_gap", "chokepoint_leverage", "prior_uncertainty"}
    payload = next_best_actions_payload(acts)
    assert json.loads(json.dumps(payload)) == payload
    assert payload["next_best_action"] == "PBB-U" and "bounded" in payload["note"] and len(payload["plan"]) == 2


def test_no_signals_does_not_crash_and_still_orders():
    # no weights at all -> leverage normalisation must not divide by zero
    acts = next_best_actions(["PBB-U", "PBB-F", "PBB-C"])
    assert len(acts) == 3 and all(a.components["chokepoint_leverage"] == 0.0 for a in acts)
