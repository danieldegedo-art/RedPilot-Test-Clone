"""B39: tests for app/testing/integrity/opplan.py (deterministic engagement planner). Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.opplan import build_opplan  # noqa: E402


def _by_hyp(plan):
    return {o.hypothesis_id: o for o in plan.objectives}


def test_one_objective_per_hypothesis_ordered_by_information_gain():
    plan = build_opplan(["PBB-C", "PBB-U", "PBB-G"], total_budget=10, chokepoint_weights={"PBB-U": 3.0})
    assert {o.hypothesis_id for o in plan.objectives} == {"PBB-C", "PBB-U", "PBB-G"}  # bounded: exactly the input set
    assert plan.objectives[0].hypothesis_id == "PBB-U" and plan.objectives[0].priority_rank == 1  # highest info-gain first


def test_budget_is_conserved_with_a_floor_per_objective():
    plan = build_opplan(["PBB-U", "PBB-C", "PBB-G"], total_budget=10)
    assert plan.total_allocated() == 10
    assert all(o.budget >= 1 for o in plan.objectives)  # never starved to 0 while budget remains


def test_budget_reflects_information_gain():
    plan = build_opplan(["PBB-U", "PBB-C"], total_budget=100, chokepoint_weights={"PBB-U": 3.0})
    b = _by_hyp(plan)
    assert plan.total_allocated() == 100
    assert b["PBB-U"].budget > b["PBB-C"].budget and b["PBB-U"].budget >= 55  # the wider-leverage objective gets more


def test_generation_is_deterministic():
    a = build_opplan(["PBB-U", "PBB-C", "PBB-G"], total_budget=50, chokepoint_weights={"PBB-U": 3.0})
    b = build_opplan(["PBB-U", "PBB-C", "PBB-G"], total_budget=50, chokepoint_weights={"PBB-U": 3.0})
    assert a.version == b.version and a.to_dict() == b.to_dict()


def test_a_seeded_hypothesis_is_annotated_as_a_b36_lead_but_still_validated():
    plan = build_opplan(["PBB-U", "PBB-G"], total_budget=10, seeded={"PBB-G"})
    src = _by_hyp(plan)["PBB-G"].source
    assert "B36" in src and "must still pass" in src
    assert _by_hyp(plan)["PBB-U"].source == "configured hypothesis set"


def test_every_objective_has_abort_conditions_including_a_cleared_class_stop():
    plan = build_opplan(["PBB-U", "PBB-C"], total_budget=10)
    for o in plan.objectives:
        assert o.abort_conditions and any("RULED_OUT" in c for c in o.abort_conditions)  # stop a cleared class; never 'skip'
        assert o.decomposition_axis.startswith("per_class:")


def test_plan_is_json_safe():
    plan = build_opplan(["PBB-U", "PBB-C", "PBB-G"], total_budget=30, chokepoint_weights={"PBB-U": 2.0})
    d = plan.to_dict()
    assert json.loads(json.dumps(d)) == d and d["total_allocated"] == 30
