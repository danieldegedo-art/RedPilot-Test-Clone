"""Tests for app.testing.state_exploration.

Runnable two ways:
  - `pytest tests/test_state_exploration.py` once requirements-dev.txt is
    installed (see repo root README / requirements-dev.txt comment).
  - `python3 tests/test_state_exploration.py` directly, with no test
    runner at all -- every test function below is a plain function using
    bare `assert`, deliberately, so this file (and the two others
    introduced alongside it: test_invariants.py, test_property_testing.py)
    can be verified in an environment where pytest itself is not
    installed. This is not a style preference: it is how these three
    files' claims were actually verified while building them, in a
    sandbox with no network access and therefore no way to `pip install`
    anything not already present. See the project's before/after report
    for what this does and does not prove.

These tests import ONLY app.testing.state_exploration, app.testing.lifecycle_model,
and app.testing.invariants -- none of which touch httpx/pydantic/fastapi -- so
they run standalone regardless of whether the rest of this project's
dependencies are installed.
"""
from __future__ import annotations

from decimal import Decimal

from app.testing import state_exploration as se
from app.testing.invariants import AttemptRecord, check_no_illegal_transition_succeeded, check_refund_sum_within_capture
from app.testing.lifecycle_model import VALID_PAYMENT_TRANSITIONS, VALID_SUBSCRIPTION_TRANSITIONS

# The (from, to) pairs and (from, a, b) race triples
# modules/state_transition_consistency.py already tests by hand today
# (STATE-002's `unusual_transitions` list and STATE-001's cancel-vs-refund
# race). Kept here explicitly, rather than parsed out of that module, so
# this comparison stays meaningful even if that module's own test list
# changes -- see state_exploration.diff_against_hand_written's docstring.
HAND_WRITTEN_ILLEGAL_PAYMENT = frozenset({("refunded", "captured")})
HAND_WRITTEN_ILLEGAL_SUBSCRIPTION = frozenset({("cancelled", "active")})
HAND_WRITTEN_RACES_PAYMENT = frozenset({("authorized", "cancelled", "refunded")})
HAND_WRITTEN_RACES_SUBSCRIPTION: frozenset = frozenset()


def test_reachability_covers_every_defined_state():
    """Every state mentioned in the transition tables must be reachable
    from the resource's real entry point -- an unreachable state would
    mean either a dead entry in the table or a missing transition into it,
    both worth flagging rather than silently exploring around."""
    pay = se.explore_payment()
    assert pay.unreachable_states == frozenset(), f"unreachable payment states: {pay.unreachable_states}"
    sub = se.explore_subscription()
    assert sub.unreachable_states == frozenset(), f"unreachable subscription states: {sub.unreachable_states}"


def test_exhaustive_counts_match_hand_computed_expectation():
    """Pinned expected counts for the CURRENT VALID_PAYMENT_TRANSITIONS /
    VALID_SUBSCRIPTION_TRANSITIONS tables (8 and 5 states respectively).
    If this test starts failing after someone edits lifecycle_model.py,
    that is not a bug in this test -- it means the state model changed and
    every number in the before/after report needs recomputing, which is
    exactly why this is pinned and asserted rather than just printed."""
    pay = se.explore_payment()
    assert len(pay.all_states) == 8
    assert pay.legal_transition_count == 11
    assert len(pay.illegal_transitions) == 45
    assert len(pay.concurrent_races) == 13

    sub = se.explore_subscription()
    assert len(sub.all_states) == 5
    assert sub.legal_transition_count == 10
    assert len(sub.illegal_transitions) == 10
    assert len(sub.concurrent_races) == 12


def test_illegal_transitions_are_exactly_the_complement_of_legal_ones():
    """Direct, from-first-principles check that enumerate_illegal_transitions
    found ALL of them and none that are actually legal: for every ordered
    pair of distinct known states, it must be legal XOR illegal, never
    both, never neither."""
    for transitions, resource_type in ((VALID_PAYMENT_TRANSITIONS, "payment"), (VALID_SUBSCRIPTION_TRANSITIONS, "subscription")):
        states = sorted(se._all_states(transitions))
        illegal_pairs = {(t.from_state, t.to_state) for t in se.enumerate_illegal_transitions(transitions, resource_type)}
        for frm in states:
            for to in states:
                if frm == to:
                    continue
                is_legal = to in transitions.get(frm, set())
                is_marked_illegal = (frm, to) in illegal_pairs
                assert is_legal != is_marked_illegal, f"{resource_type} {frm}->{to}: legal={is_legal} illegal_flag={is_marked_illegal}"


def test_concurrent_races_only_pair_up_simultaneously_legal_operations():
    """Every enumerated race's two operations must each individually be a
    legal transition from the shared starting state -- a race is only
    meaningful between two things that could each, alone, be accepted."""
    pay = se.explore_payment()
    for race in pay.concurrent_races:
        legal_targets = VALID_PAYMENT_TRANSITIONS[race.from_state]
        assert race.operation_a in legal_targets and race.operation_b in legal_targets
        assert race.operation_a != race.operation_b


def test_diff_against_hand_written_shows_current_coverage_gap():
    """Pinned, computed (not eyeballed) coverage-gap numbers: as of this
    change, 2 illegal transitions and 1 race are hand-written; exhaustive
    exploration finds 55 and 25 respectively. If someone adds more
    hand-written STATE-002 cases later, this test's HAND_WRITTEN_* sets
    above need updating to match -- that is intentional friction, not a
    bug, so the "how much is genuinely new" number never silently rots."""
    pay_diff = se.diff_against_hand_written(
        se.explore_payment(),
        hand_written_illegal=HAND_WRITTEN_ILLEGAL_PAYMENT,
        hand_written_races=HAND_WRITTEN_RACES_PAYMENT,
    )
    sub_diff = se.diff_against_hand_written(
        se.explore_subscription(),
        hand_written_illegal=HAND_WRITTEN_ILLEGAL_SUBSCRIPTION,
        hand_written_races=HAND_WRITTEN_RACES_SUBSCRIPTION,
    )
    assert pay_diff["new_illegal_count"] == 44
    assert pay_diff["new_race_count"] == 12
    assert sub_diff["new_illegal_count"] == 9
    assert sub_diff["new_race_count"] == 12


class _BuggyPaymentBackend:
    """A deliberately buggy in-process fake: capture() rejects only
    "refunded", not "requires authorized" -- so a cancelled payment can
    still be wrongly captured. Exists to prove exploration finds a REAL
    bug, not just that it enumerates a graph correctly."""

    def __init__(self) -> None:
        self.state = "authorized"

    def cancel(self) -> tuple[int, str]:
        if self.state not in ("pending", "authorized"):
            return 409, self.state
        self.state = "cancelled"
        return 200, self.state

    def capture(self) -> tuple[int, str]:
        if self.state == "refunded":  # THE BUG: should require state == "authorized"
            return 409, self.state
        self.state = "captured"
        return 200, self.state


def test_exploration_finds_a_bug_the_hand_written_case_does_not_cover():
    """Drives a deliberately buggy fake backend into the "cancelled" state
    and attempts the "capture" operation -- one of the 44 illegal payment
    transitions exhaustive exploration finds beyond STATE-002's single
    hand-written refunded->captured case. The backend wrongly allows it;
    this is exactly the kind of finding axis 1 asks for: discovered by
    exploring the state graph, not because anyone specified this exact
    scenario in advance."""
    pay = se.explore_payment()
    assert any(t.from_state == "cancelled" and t.to_state == "captured" for t in pay.illegal_transitions)

    backend = _BuggyPaymentBackend()
    backend.cancel()
    status, _ = backend.capture()
    attempt = AttemptRecord(
        operation="capture", resource_type="payment", from_state="cancelled", to_state="captured",
        succeeded=(status == 200),
    )
    violations = check_no_illegal_transition_succeeded([attempt])
    assert status == 200, "this test documents the bug existing in the fake backend; if this fails, the fake was fixed"
    assert len(violations) == 1, "the invariant must catch the illegal transition the buggy backend allowed"


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
    print("Alle state_exploration-Tests bestanden.")
