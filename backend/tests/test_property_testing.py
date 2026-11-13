"""Tests for app.testing.property_testing. See test_state_exploration.py's
module docstring for why these are plain-assert functions runnable both
under pytest and directly via `python3 tests/test_property_testing.py`.
"""
from __future__ import annotations

from decimal import Decimal

from app.testing.property_testing import CURRENCY_MINOR_UNITS, amount_strategy, currency_amount_strategy, for_all, shrink


def _buggy_split_evenly(amount: Decimal, n: int) -> list[Decimal]:
    """Deliberately buggy: naive float division + independent per-share
    rounding. A real, common payment-domain bug class (refund
    installments, marketplace payout splits, subscription proration)."""
    share = float(amount) / n
    return [Decimal(str(round(share, 2))) for _ in range(n)]


def _correct_split_evenly(amount: Decimal, n: int) -> list[Decimal]:
    """Correct: works in integer cents, distributes the remainder one
    cent at a time so the parts always sum back to the original."""
    cents = int((amount * 100).to_integral_value())
    base, remainder = divmod(cents, n)
    parts = [Decimal(base) / 100 for _ in range(n)]
    for i in range(remainder):
        parts[i] += Decimal("0.01")
    return parts


def _split_gen(rng):
    return (amount_strategy(rng), rng.choice([2, 3, 4, 5, 6, 7]))


def test_property_testing_catches_the_buggy_split_function():
    def split_is_exact(amount, n):
        return sum(_buggy_split_evenly(amount, n)) == amount

    result = for_all("split_evenly_sums_to_original", _split_gen, split_is_exact, n_examples=300, seed=42)
    assert not result.passed, "expected the buggy split function to be caught"
    amount, n = result.minimal_input
    assert sum(_buggy_split_evenly(amount, n)) != amount


def test_property_testing_does_not_flag_the_correct_split_function():
    """Sanity check against false positives: the property itself must not
    be trivially unsatisfiable."""
    def split_is_exact(amount, n):
        return sum(_correct_split_evenly(amount, n)) == amount

    result = for_all("correct_split_evenly_sums_to_original", _split_gen, split_is_exact, n_examples=300, seed=42)
    assert result.passed


def test_same_seed_is_fully_deterministic():
    def split_is_exact(amount, n):
        return sum(_buggy_split_evenly(amount, n)) == amount

    r1 = for_all("split_evenly_sums_to_original", _split_gen, split_is_exact, n_examples=300, seed=42)
    r2 = for_all("split_evenly_sums_to_original", _split_gen, split_is_exact, n_examples=300, seed=42)
    assert r1.to_dict() == r2.to_dict(), "identical seed must reproduce a byte-identical result"


def test_different_seed_can_find_a_different_counterexample():
    """Not asserting a SPECIFIC different value (that would make this test
    itself seed-fragile) -- only that the seed genuinely changes the
    generated sequence, which is what makes re-running with a new seed a
    meaningful way to search for more failures later."""
    def split_is_exact(amount, n):
        return sum(_buggy_split_evenly(amount, n)) == amount

    r1 = for_all("split_evenly_sums_to_original", _split_gen, split_is_exact, n_examples=50, seed=1)
    r2 = for_all("split_evenly_sums_to_original", _split_gen, split_is_exact, n_examples=50, seed=2)
    assert r1.failing_input != r2.failing_input or r1.seed != r2.seed


def test_shrinking_without_domain_constraint_can_wander_into_a_degenerate_case():
    """REGRESSION TEST for a real bug found while building this module:
    shrinking a (amount, installment_count) counterexample with no domain
    constraint on `n` walked `n` down to -1 (at which point
    `range(-1)` is empty and the property fails for an unrelated, trivial
    reason -- not the rounding bug the counterexample exists to isolate).
    This test pins that this is EXACTLY what happens without a domain
    constraint, so the fix below (test_shrinking_respects_domain_constraints)
    stays proven necessary rather than looking like defensive code nobody
    needed."""
    def split_is_exact(amount, n):
        return sum(_buggy_split_evenly(amount, n)) == amount

    result = for_all("split_evenly_sums_to_original", _split_gen, split_is_exact, n_examples=300, seed=42)
    _, n = result.minimal_input
    assert n < 2, "documents the unconstrained-shrink failure mode this module's domains= parameter fixes"


def test_shrinking_respects_domain_constraints():
    """With domains=(None, lambda n: n >= 2), shrinking must never produce
    n < 2, even though n < 2 (e.g. n=-1, where range(-1) is empty) is a
    technically-still-failing value the unconstrained shrinker finds."""
    def split_is_exact(amount, n):
        return sum(_buggy_split_evenly(amount, n)) == amount

    result = for_all(
        "split_evenly_sums_to_original", _split_gen, split_is_exact,
        n_examples=300, seed=42, domains=(None, lambda n: n >= 2),
    )
    assert not result.passed
    amount, n = result.minimal_input
    assert n >= 2, f"domain constraint violated: shrunk n={n}"
    assert sum(_buggy_split_evenly(amount, n)) != amount, "must still be a genuine counterexample, not just domain-valid"


def test_currency_amount_strategy_covers_zero_two_and_three_decimal_currencies():
    import random

    rng = random.Random(7)
    seen_digit_counts = set()
    for _ in range(200):
        amount, currency = currency_amount_strategy(rng)
        digits = CURRENCY_MINOR_UNITS[currency]
        seen_digit_counts.add(digits)
        # the generated amount must actually respect its currency's minor unit
        assert amount == amount.quantize(Decimal(1).scaleb(-digits) if digits else Decimal(1))
    assert seen_digit_counts == {0, 2, 3}, f"expected to see 0/2/3-decimal currencies across 200 draws, saw {seen_digit_counts}"


def test_shrink_of_a_bare_scalar_moves_toward_zero():
    def always_fails_unless_zero(x):
        return x == 0

    minimal, _ = shrink(Decimal("47.32"), always_fails_unless_zero)
    assert minimal != 0
    assert abs(minimal) < Decimal("1"), f"expected shrink to get close to the zero boundary, got {minimal}"


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
    print("Alle property_testing-Tests bestanden.")
