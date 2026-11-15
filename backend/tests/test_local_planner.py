"""B13: tests for app/testing/integrity/local_planner.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.local_planner import (  # noqa: E402
    StepAction, local_steps, plan_next, plan_payload,
)
from app.testing.integrity.findings import SPECS  # noqa: E402


def test_steps_are_parsed_only_from_the_preregistered_sequence():
    steps = local_steps("PBB-U")
    expected = len([p for p in SPECS["PBB-U"].action_sequence.split("->") if p.strip()])
    assert len(steps) == expected and expected > 1
    assert [s.index for s in steps] == list(range(expected))
    assert all(s.label for s in steps) and "pre-check" in steps[0].label


def test_proceeds_through_steps_in_order():
    assert plan_next("PBB-U", set(), local_budget=10).next_step.index == 0
    assert plan_next("PBB-U", {0}, local_budget=10).next_step.index == 1
    assert plan_next("PBB-U", {0, 1, 2}, local_budget=10).next_step.index == 3


def test_stop_signal_halts_and_does_not_skip_remaining_steps():
    total = len(local_steps("PBB-U"))
    plan = plan_next("PBB-U", {0}, local_budget=10, stop_signal=True)
    assert plan.action == StepAction.STOP and plan.next_step is None
    assert "does NOT" in plan.reason or "not skip" in plan.reason.lower()
    assert total - 1 > 0            # there WERE remaining steps -- it halted, it didn't finish


def test_budget_exhaustion_stops():
    plan = plan_next("PBB-U", {0, 1}, local_budget=2)
    assert plan.action == StepAction.STOP and plan.remaining_budget == 0
    assert "budget" in plan.reason


def test_completing_the_sequence_stops():
    all_idx = {s.index for s in local_steps("PBB-U")}
    plan = plan_next("PBB-U", all_idx, local_budget=100)
    assert plan.action == StepAction.STOP and "complete" in plan.reason


def test_invalid_completed_index_is_rejected():
    try:
        plan_next("PBB-U", {999}, local_budget=10)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_unknown_hypothesis_is_rejected():
    try:
        local_steps("NOT-A-REAL-ORACLE")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_single_step_hypothesis_and_payload_json_safe():
    steps = local_steps("PBB-OPEN")
    assert len(steps) == 1
    assert plan_next("PBB-OPEN", set(), local_budget=5).next_step.index == 0
    assert plan_next("PBB-OPEN", {0}, local_budget=5).action == StepAction.STOP
    payload = plan_payload("PBB-OPEN", set(), local_budget=5)
    assert json.loads(json.dumps(payload)) == payload
