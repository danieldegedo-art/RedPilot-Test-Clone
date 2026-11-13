"""Tests for generation_protocol.py: proves the three Protocols are
genuinely satisfiable and checkable, not aspirational, and that a
generator/executor/evaluator triplet can be swapped independently.
"""
from __future__ import annotations

import asyncio

from app.testing.generation_protocol import (
    ScenarioEvaluator,
    ScenarioExecutor,
    ScenarioGenerator,
    implements_full_separation,
)
from app.testing.generation_protocol_adapters import (
    IllegalTransitionEvaluator,
    PaymentIllegalTransitionGenerator,
    RecordedAttemptExecutor,
)


def test_the_real_generator_satisfies_the_protocol_by_isinstance_not_just_by_convention():
    gen = PaymentIllegalTransitionGenerator()
    assert isinstance(gen, ScenarioGenerator)
    scenarios = gen.generate()
    assert len(scenarios) == 45, "must be the same 45 this project's other tests pin for explore_payment()"
    assert all(hasattr(s, "id") for s in scenarios)


def test_the_real_evaluator_satisfies_the_protocol():
    ev = IllegalTransitionEvaluator()
    assert isinstance(ev, ScenarioEvaluator)


def test_executor_satisfies_the_protocol():
    ex = RecordedAttemptExecutor(outcomes={})
    assert isinstance(ex, ScenarioExecutor)


def test_full_triplet_together_reproduces_a_known_illegal_transition_finding():
    """End-to-end through the Protocol layer, not the concrete classes
    directly -- generator produces scenarios, an executor (told, for this
    test, that the "refunded -> captured" scenario "succeeded") produces
    a fact, the evaluator flags it. Same finding STATE-002 already tests
    by hand and state_machine_exploration.py finds via real HTTP -- here
    reproduced through the formal Protocol seam instead, to prove the
    seam actually carries the information needed end to end."""
    generator = PaymentIllegalTransitionGenerator()
    scenarios = generator.generate()
    target = next(s for s in scenarios if s.from_state == "refunded" and s.to_state == "captured")

    executor = RecordedAttemptExecutor(outcomes={target.id: True})  # "succeeded" -- the bug
    evaluator = IllegalTransitionEvaluator()
    assert implements_full_separation(generator, executor, evaluator)

    fact = asyncio.run(executor.execute(target))
    violations = evaluator.evaluate(fact)
    assert len(violations) == 1


def test_swapping_the_executor_alone_changes_the_outcome_without_touching_the_other_two():
    """The actual point of formal separation: change ONLY the executor
    (simulate the bug being FIXED -- the attempt now fails, as it should)
    and get a different, correct outcome with zero changes to the
    generator or evaluator."""
    generator = PaymentIllegalTransitionGenerator()
    target = next(s for s in generator.generate() if s.from_state == "refunded" and s.to_state == "captured")
    evaluator = IllegalTransitionEvaluator()

    fixed_executor = RecordedAttemptExecutor(outcomes={target.id: False})  # "correctly rejected"
    fact = asyncio.run(fixed_executor.execute(target))
    assert evaluator.evaluate(fact) == []


def _run(fn):
    try:
        fn()
        print(f"[PASS] {fn.__name__}")
    except AssertionError as exc:
        print(f"[FAIL] {fn.__name__}: {exc}")
        raise


if __name__ == "__main__":
    for _name, _fn in list(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _run(_fn)
    print("Alle Generator/Executor/Evaluator-Protocol-Tests bestanden.")
