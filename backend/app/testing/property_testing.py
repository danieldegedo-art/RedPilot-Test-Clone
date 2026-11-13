"""Minimal, dependency-free property-based testing with automatic shrinking.

WHY THIS EXISTS INSTEAD OF USING HYPOTHESIS
---------------------------------------------
Hypothesis is the standard, much more capable tool for this in the Python
ecosystem, and requirements.txt does not currently pin it. This module is
NOT a claim that hand-rolling is better than Hypothesis -- it is a
deliberately small implementation of exactly the two mechanisms axis 1
needs (seeded generation across a domain, and shrinking a failing case to
a minimal one) for the specific domain this suite cares about: amounts,
currency minor units, and rounding. Recommendation, stated plainly: if/when
network access allows `pip install hypothesis`, replace the driver below
with `@given(...)` and keep the domain-specific generators
(amount_strategy et al.) as Hypothesis strategies instead -- they were
written to make that swap easy (plain callables returning a value each
time, not tied to this file's own Property/shrink machinery).

DETERMINISM
------------
Every generator and the shrinker itself take an explicit integer `seed`
and use `random.Random(seed)` (a LOCAL instance, never the module-global
`random` -- that global has mutable process-wide state, and this suite's
"no wall-clock or ordering dependence in test outcomes" requirement rules
out anything whose behavior depends on what else in the process called
`random.*` first). The same seed always produces the same sequence of
generated values and the same shrink path -- verified in
tests/test_property_testing.py by running the same (generator, predicate,
seed) twice and diffing the two PropertyResult objects field by field.

SHRINKING ALGORITHM
---------------------
Deliberately simple (not a general delta-debugging implementation -- see
delta_debugging.py for that, used for whole test-case minimization in axis
5): for a single numeric counterexample, repeatedly try a candidate closer
to zero (binary search between zero and the current failing value, plus a
handful of "nice" values -- 0, 1, -1, the boundary of the relevant currency
minor unit) and keep whichever still fails. Stops after `max_shrink_steps`
or once no candidate in the current bracket still fails. For a tuple
counterexample, shrinks each element independently while holding the
others fixed, which is not guaranteed globally minimal (elements can
interact) but is guaranteed to never make a passing case look like a
failing one, and in practice reduces "found some 9-digit float after 500
random tries" down to the one or two values that actually matter.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Callable, Sequence

Predicate = Callable[..., bool]
Generator = Callable[["random.Random"], Any]


@dataclass
class PropertyResult:
    property_name: str
    seed: int
    n_examples: int
    passed: bool
    failing_input: Any = None
    minimal_input: Any = None
    shrink_steps: int = 0
    exception: str | None = None

    def to_dict(self) -> dict:
        return {
            "property_name": self.property_name,
            "seed": self.seed,
            "n_examples": self.n_examples,
            "passed": self.passed,
            "failing_input": _jsonable(self.failing_input),
            "minimal_input": _jsonable(self.minimal_input),
            "shrink_steps": self.shrink_steps,
            "exception": self.exception,
        }


def _jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    return value


def _holds(predicate: Predicate, value: Any) -> tuple[bool, str | None]:
    """Runs `predicate` on `value` (unpacking a tuple as *args, so a
    two-argument property can be written naturally). Returns
    (holds, exception_repr) -- a raised exception counts as the property
    NOT holding (an uncaught exception in the code under test is itself a
    finding), never as an error that stops the search."""
    try:
        args = value if isinstance(value, tuple) else (value,)
        return bool(predicate(*args)), None
    except Exception as exc:  # noqa: BLE001 - deliberate: a crash IS a failure to shrink toward
        return False, f"{type(exc).__name__}: {exc}"


def _shrink_scalar(
    value: Decimal | float | int,
    still_fails: Callable[[Any], bool],
    *,
    max_steps: int,
    valid: Callable[[Any], bool] = lambda _x: True,
) -> tuple[Any, int]:
    """Shrinks a single numeric value toward zero while `still_fails`
    stays True. `still_fails` receives a candidate REPLACEMENT for this
    scalar (already wrapped back into the full argument shape by the
    caller) and reports whether the property still fails with that
    substitution.

    `valid` gates every candidate BEFORE it is offered to `still_fails`:
    without it, shrinking can converge on a technically-still-failing but
    semantically meaningless value (found in this module's own
    verification run: shrinking an "installment count" parameter with no
    domain constraint walked it down to -1, at which point
    `range(-1)` is empty and the property fails for a trivial,
    irrelevant reason -- not the rounding bug the counterexample was
    supposed to isolate). An invalid candidate is treated exactly like a
    non-failing one: the search narrows away from it, never toward it."""
    is_decimal = isinstance(value, Decimal)
    is_int = isinstance(value, int) and not isinstance(value, bool)
    current = value
    steps = 0

    for nice in (type(value)(0), type(value)(1), type(value)(-1)):
        if steps >= max_steps:
            break
        steps += 1
        if nice != current and valid(nice) and still_fails(nice):
            current = nice

    lo, hi = (type(value)(0), current) if current > 0 else (current, type(value)(0))
    while steps < max_steps:
        if is_int:
            mid = (lo + hi) // 2
            if mid == hi or mid == lo:
                break
        else:
            mid = (lo + hi) / 2 if not is_decimal else (lo + hi) / 2
            if abs(mid - hi) < (Decimal("0.01") if is_decimal else 1e-9):
                break
        steps += 1
        if valid(mid) and still_fails(mid):
            hi = mid if abs(mid) <= abs(current) else hi
            current = mid if abs(mid) < abs(current) else current
        else:
            lo = mid
    return current, steps


def shrink(
    value: Any,
    predicate: Predicate,
    *,
    max_steps: int = 64,
    domains: Sequence[Callable[[Any], bool] | None] | None = None,
) -> tuple[Any, int]:
    """Public entry point: shrinks any failing `value` (a scalar, or a
    tuple of scalars) to a smaller one that still makes `predicate` fail,
    per-element for tuples. Returns (minimal_value, steps_taken).

    `domains`, when given, is one predicate per tuple position (use None
    for "no constraint" at a position that is meaningful across all
    reals) restricting what a shrunk value at that position is allowed to
    become -- e.g. `domains=(None, lambda n: n >= 2)` for a
    (amount, installment_count) pair where fewer than 2 installments
    isn't a meaningful case to shrink toward. Ungated shrinking of a
    parameter with real domain constraints is exactly how the -1 case
    described above happens; see tests/test_property_testing.py for that
    regression case kept as a permanent test."""

    def _domain_at(i: int) -> Callable[[Any], bool]:
        if domains is None or i >= len(domains) or domains[i] is None:
            return lambda _x: True
        return domains[i]

    if isinstance(value, tuple):
        current = list(value)
        total_steps = 0
        for i in range(len(current)):
            if not isinstance(current[i], (int, float, Decimal)) or isinstance(current[i], bool):
                continue

            def still_fails(candidate, _i=i):
                trial = list(current)
                trial[_i] = candidate
                holds, _ = _holds(predicate, tuple(trial))
                return not holds

            shrunk, steps = _shrink_scalar(current[i], still_fails, max_steps=max_steps, valid=_domain_at(i))
            current[i] = shrunk
            total_steps += steps
        return tuple(current), total_steps

    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        def still_fails(candidate):
            holds, _ = _holds(predicate, candidate)
            return not holds

        return _shrink_scalar(value, still_fails, max_steps=max_steps, valid=_domain_at(0))

    return value, 0


def for_all(
    property_name: str,
    generator: Generator,
    predicate: Predicate,
    *,
    n_examples: int = 200,
    seed: int = 42,
    max_shrink_steps: int = 64,
    domains: Sequence[Callable[[Any], bool] | None] | None = None,
) -> PropertyResult:
    """Runs `predicate` against `n_examples` values from `generator`
    (seeded, deterministic), stopping at the first failure and shrinking
    it. A "failure" is either `predicate` returning falsy or raising.
    `domains`: see `shrink()` -- pass this whenever a tuple-valued
    generator has a component that isn't meaningful across all reals
    (a count, an enum-like choice), or shrinking can wander into a
    degenerate case that fails for an unrelated, uninteresting reason."""
    rng = random.Random(seed)
    for _ in range(n_examples):
        value = generator(rng)
        holds, exc = _holds(predicate, value)
        if holds:
            continue
        minimal, steps = shrink(value, predicate, max_steps=max_shrink_steps, domains=domains)
        return PropertyResult(
            property_name=property_name,
            seed=seed,
            n_examples=n_examples,
            passed=False,
            failing_input=value,
            minimal_input=minimal,
            shrink_steps=steps,
            exception=exc,
        )
    return PropertyResult(property_name=property_name, seed=seed, n_examples=n_examples, passed=True)


# ---------------------------------------------------------------------------
# Domain generators: amounts, currency minor units, rounding-adjacent values.
# ---------------------------------------------------------------------------

# digits after the decimal point, per ISO 4217-style currency classes this
# suite is likely to encounter -- deliberately a small illustrative set,
# not the full ISO 4217 table.
CURRENCY_MINOR_UNITS = {
    "USD": 2, "EUR": 2, "GBP": 2,
    "JPY": 0, "KRW": 0,
    "BHD": 3, "KWD": 3, "OMR": 3,
}


def amount_strategy(rng: random.Random) -> Decimal:
    """One amount, drawn from a mix deliberately weighted toward the
    boundary values that hand-written tests tend to skip over in favor of
    a single round "happy path" number like 25.00: zero, the smallest
    representable unit, values just below/above common round numbers,
    and ordinary-looking random amounts, all as Decimal so a shrunk
    counterexample is exact rather than float-approximated."""
    bucket = rng.random()
    if bucket < 0.10:
        return Decimal("0.00")
    if bucket < 0.20:
        return Decimal("0.01")
    if bucket < 0.30:
        return Decimal(rng.choice(["-0.01", "-1.00", "-100.00"]))
    if bucket < 0.40:
        return Decimal(rng.choice(["9999999.99", "1000000.00"]))
    if bucket < 0.55:
        # just off a round number -- where off-by-one-cent rounding bugs live
        base = Decimal(rng.choice(["10.00", "19.99", "99.99", "100.00", "0.10"]))
        offset = Decimal(rng.choice(["0.01", "-0.01"]))
        return base + offset
    cents = rng.randint(0, 10_000_00)
    return (Decimal(cents) / Decimal(100)).quantize(Decimal("0.01"))


def currency_amount_strategy(rng: random.Random) -> tuple[Decimal, str]:
    """(amount, currency) pairs covering 0-, 2-, and 3-decimal currencies,
    so a rounding function gets exercised against minor-unit counts other
    than the 2-decimal case every hand-written test defaults to."""
    currency = rng.choice(list(CURRENCY_MINOR_UNITS.keys()))
    digits = CURRENCY_MINOR_UNITS[currency]
    if digits == 0:
        value = Decimal(rng.randint(0, 1_000_000))
    else:
        cents = rng.randint(0, 1_000_000 * (10**digits))
        value = (Decimal(cents) / Decimal(10**digits)).quantize(Decimal(1).scaleb(-digits))
    return value, currency
