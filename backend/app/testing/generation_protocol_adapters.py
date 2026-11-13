"""Thin, real adapters wiring state_exploration.py's existing functions
(unchanged) to the generation_protocol.py Protocols -- proof the
separation is checkable, not just aspirational. No new logic: every
method here is a one-line delegation to code that already existed before
this file.
"""
from __future__ import annotations

from typing import Any

from app.testing.invariants import AttemptRecord, check_no_illegal_transition_succeeded
from app.testing.state_exploration import explore_payment


class PaymentIllegalTransitionGenerator:
    """Adapts state_exploration.explore_payment() to ScenarioGenerator.
    generate() returns exactly exploration.illegal_transitions -- the
    same tuple of IllegalTransition objects state_machine_exploration.py
    already consumes, unchanged."""

    def generate(self) -> tuple[Any, ...]:
        return explore_payment().illegal_transitions


class RecordedAttemptExecutor:
    """A minimal, real ScenarioExecutor: given an IllegalTransition
    scenario and a pre-recorded outcome (whether the attempt succeeded --
    supplied by the caller, since THIS class does no I/O itself; a real
    HTTP-backed executor is state_machine_exploration.py's own
    _drive_to_state/_attempt pair), returns the AttemptRecord an
    evaluator needs. Exists so this protocol's executor role has a
    concrete, testable, non-HTTP implementation -- proving the role is
    genuinely swappable, not proving a new HTTP client."""

    def __init__(self, outcomes: dict[str, bool]) -> None:
        self._outcomes = outcomes

    async def execute(self, scenario: Any) -> AttemptRecord:
        return AttemptRecord(
            operation="capture" if scenario.to_state == "captured" else "attempt",
            resource_type=scenario.resource_type,
            from_state=scenario.from_state,
            to_state=scenario.to_state,
            succeeded=self._outcomes.get(scenario.id, False),
        )


class IllegalTransitionEvaluator:
    """Adapts invariants.check_no_illegal_transition_succeeded to
    ScenarioEvaluator -- the exact function every axis-1/2/4 test in this
    project already calls, wrapped in one line."""

    def evaluate(self, facts: Any) -> list[Any]:
        attempts = facts if isinstance(facts, (list, tuple)) else [facts]
        return check_no_illegal_transition_succeeded(attempts)
