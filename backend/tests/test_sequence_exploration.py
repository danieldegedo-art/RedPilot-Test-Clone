"""Tests for app.testing.sequence_exploration. See test_state_exploration.py's
module docstring for the pytest/standalone dual-run pattern used here.
"""
from __future__ import annotations

from math import factorial

from app.testing.lifecycle_model import VALID_PAYMENT_TRANSITIONS
from app.testing.sequence_exploration import (
    MAX_EXHAUSTIVE_INTERLEAVINGS,
    enumerate_interleaving_orders,
    joint_state_space_size,
    sample_interleaving_orders,
    theoretical_interleaving_count,
)


def test_theoretical_count_matches_hand_computed_values():
    # k=2: only order is (a,b),(b,a) for the one pair -> 2
    assert theoretical_interleaving_count(2) == 2
    # k=4 (this graph's actual maximum branching factor): pinned, see report
    assert theoretical_interleaving_count(4) == 60
    assert theoretical_interleaving_count(8) == 109_592


def test_growth_is_genuinely_faster_than_the_pairwise_count():
    """The whole point: interleaving-order count must grow strictly
    faster than pairs C(k,2) as k increases -- otherwise this module adds
    complexity without adding anything genuinely different in kind."""
    from math import comb

    ratios = [theoretical_interleaving_count(k) / comb(k, 2) for k in range(2, 9)]
    assert all(b > a for a, b in zip(ratios, ratios[1:])), f"ratio to C(k,2) must keep increasing, got {ratios}"


def test_exhaustive_enumeration_is_exact_for_this_graphs_actual_branching_factor():
    """This graph's max out-degree is 4 (authorized, pending) -- well under
    MAX_EXHAUSTIVE_INTERLEAVINGS, so enumeration must be exhaustive and
    match the closed-form count exactly, not merely be "close"."""
    orders, was_exhaustive = enumerate_interleaving_orders(VALID_PAYMENT_TRANSITIONS, "payment")
    assert was_exhaustive
    expected = theoretical_interleaving_count(4) * 2 + theoretical_interleaving_count(2)  # authorized + pending + captured
    assert len(orders) == expected


def test_every_enumerated_order_is_a_permutation_of_legal_targets_only():
    orders, _ = enumerate_interleaving_orders(VALID_PAYMENT_TRANSITIONS, "payment")
    for o in orders:
        legal = VALID_PAYMENT_TRANSITIONS[o.from_state]
        assert set(o.order).issubset(legal), f"{o} contains a target not legal from {o.from_state}"
        assert len(set(o.order)) == len(o.order), f"{o} repeats a target within one ordering"
        assert len(o.order) >= 2


def test_sampling_is_deterministic_for_a_fixed_seed():
    s1 = sample_interleaving_orders(VALID_PAYMENT_TRANSITIONS, "payment", "authorized", n_samples=50, seed=7)
    s2 = sample_interleaving_orders(VALID_PAYMENT_TRANSITIONS, "payment", "authorized", n_samples=50, seed=7)
    assert s1 == s2


def test_joint_state_space_grows_exponentially_in_resource_count():
    sizes = [joint_state_space_size(8, m) for m in range(1, 7)]
    assert sizes == [8, 64, 512, 4096, 32768, 262144]
    ratios = [b / a for a, b in zip(sizes, sizes[1:])]
    assert all(abs(r - 8.0) < 1e-9 for r in ratios), "each additional resource must multiply the joint space by exactly 8"


def test_single_resource_path_depth_is_honestly_not_exponential_for_this_graph():
    """Pinned NEGATIVE result (see sequence_exploration.py's module
    docstring): this graph's path count peaks early and hits zero by
    depth 5, because every terminal state has no outgoing edges. This
    test exists so that honest finding stays checkable and doesn't
    quietly stop being true (or get quietly asserted as false) later."""

    def count_paths(transitions, start, depth):
        if depth == 0:
            return 1
        return sum(count_paths(transitions, nxt, depth - 1) for nxt in transitions.get(start, ()))

    counts = [count_paths(VALID_PAYMENT_TRANSITIONS, "pending", d) for d in range(1, 6)]
    assert counts == [4, 4, 2, 1, 0], f"expected the documented non-exponential (decaying) path count, got {counts}"


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
    print("Alle sequence_exploration-Tests bestanden.")
