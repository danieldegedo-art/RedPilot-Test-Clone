"""Reusable, composable metamorphic invariants for payment flows.

WHAT "METAMORPHIC" MEANS HERE
------------------------------
A metamorphic invariant is a property that must hold across a RELATION
between multiple observations, not a single expected value for a single
request -- "sending the same idempotent request twice must debit exactly
once" says nothing about what the response body should look like, only
that two particular observations must be consistent with each other. That
is what makes these composable: any test module, any generated scenario
(hand-written or produced by state_exploration.py / property_testing.py),
can feed its observations through the same four checks below, instead of
each module re-deriving its own one-off version of "was this refund too
big" the way modules/lifecycle_consistency.py, processing_integrity.py and
business_rule_consistency.py currently each do independently (see the
audit notes this module's introduction is based on -- those hand-written
cases stay valuable as specific, named scenarios; this module is what lets
a NEW scenario nobody wrote by hand get the same invariant checking for
free).

DESIGN: DEPENDENCY-FREE BY CONSTRUCTION
-----------------------------------------
AttemptRecord is a plain dataclass, not a ResponseEvidence/pydantic model,
specifically so this module has zero third-party dependencies and can be
unit-tested (and was -- see tests/test_invariants.py) in any environment
that can run the Python interpreter, independent of whether
httpx/pydantic/fastapi are installed. The adapter that builds AttemptRecord
values from real ResponseEvidence objects lives in
modules/metamorphic_invariants.py, which does depend on the HTTP layer,
by design -- that is the one place the two worlds meet.

Money is compared via `decimal.Decimal`, never raw `float` equality: two
floats that are "the same amount" after currency-minor-unit rounding are
frequently not bit-identical (0.1 + 0.2 != 0.3 is the canonical example),
and a payments invariant that used `==` on floats would produce false
violations on perfectly correct systems. `to_decimal` centralizes that
conversion so every invariant below rounds the same way.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Sequence

from app.testing.lifecycle_model import is_valid_transition


def to_decimal(amount: float | int | str | Decimal, minor_unit_digits: int = 2) -> Decimal:
    """Converts a raw amount to a Decimal rounded to the currency's minor
    unit (2 digits for USD/EUR-like currencies; pass 0 for JPY-like
    zero-decimal currencies, 3 for BHD-like three-decimal currencies).
    Going through `str(amount)` when given a float avoids importing the
    float's own binary imprecision into the Decimal (Decimal(0.1) is
    0.1000000000000000055511151231257827021181583404541015625;
    Decimal(str(0.1)) is 0.1)."""
    if isinstance(amount, Decimal):
        d = amount
    elif isinstance(amount, float):
        d = Decimal(str(amount))
    else:
        d = Decimal(amount)
    quantum = Decimal(1).scaleb(-minor_unit_digits) if minor_unit_digits > 0 else Decimal(1)
    return d.quantize(quantum, rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class AttemptRecord:
    """One HTTP attempt at a payment-affecting operation, reduced to the
    handful of facts the invariants below need.

    operation:            logical operation name, e.g. "create_payment",
                           "capture", "refund", "cancel".
    resource_type:        "payment" | "subscription" -- must match a key
                           lifecycle_model.py knows about for the
                           illegal-transition check to apply.
    from_state/to_state:  the state the targeted resource was in before
                           this attempt, and the state this attempt tried
                           to move it to. None when not applicable/unknown
                           (e.g. a create call with no prior state) -- the
                           illegal-transition invariant skips a record with
                           either side missing rather than guessing.
    idempotency_key:      the key the CALLER sent (not one the SUT
                           generated), so two attempts with the same key
                           represent the same logical request retried or
                           duplicated -- None if this call did not use one.
    request_amount:       the amount THIS attempt asked to move (a refund's
                           requested amount, a capture's requested amount);
                           None for operations with no amount (cancel).
    succeeded:            whether the SUT reported success (2xx) for this
                           specific attempt.
    resulting_resource_id: the id the SUT says this attempt affected or
                           created. Two "successful" attempts with the same
                           idempotency key but DIFFERENT resulting ids is
                           itself a violation (see check_idempotent_replay).
    """

    operation: str
    resource_type: str = "payment"
    from_state: str | None = None
    to_state: str | None = None
    idempotency_key: str | None = None
    request_amount: float | int | str | Decimal | None = None
    succeeded: bool = False
    resulting_resource_id: str | None = None


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    message: str
    evidence: tuple[AttemptRecord, ...]

    def to_dict(self) -> dict:
        return {
            "invariant_id": self.invariant_id,
            "message": self.message,
            "evidence": [a.operation for a in self.evidence],
        }


# ---------------------------------------------------------------------------
# Invariant 1: idempotent replay -> exactly one underlying resource/debit.
# ---------------------------------------------------------------------------


def check_idempotent_replay(attempts: Sequence[AttemptRecord]) -> list[InvariantViolation]:
    """Groups attempts by (operation, idempotency_key). Within a group of
    size > 1, every SUCCESSFUL attempt must report the SAME
    resulting_resource_id -- i.e. the operation happened exactly once,
    however many times the caller sent (or the network duplicated) the
    request. Does not require the key to be present -- an operation this
    suite never sent an idempotency key for is simply never grouped, since
    there is nothing here to detect "on retry with no key" (that risk is
    real but is a design question about the SUT's API contract, not
    something this invariant can evaluate)."""
    groups: dict[tuple[str, str], list[AttemptRecord]] = {}
    for attempt in attempts:
        if attempt.idempotency_key is None:
            continue
        groups.setdefault((attempt.operation, attempt.idempotency_key), []).append(attempt)

    violations = []
    for (operation, key), group in groups.items():
        if len(group) < 2:
            continue
        successful_ids = {a.resulting_resource_id for a in group if a.succeeded and a.resulting_resource_id}
        if len(successful_ids) > 1:
            violations.append(
                InvariantViolation(
                    invariant_id="idempotent_replay",
                    message=(
                        f"{len(group)} attempts at '{operation}' shared idempotency key {key!r} but "
                        f"produced {len(successful_ids)} distinct resource ids ({sorted(successful_ids)}) "
                        "instead of exactly one."
                    ),
                    evidence=tuple(group),
                )
            )
    return violations


# ---------------------------------------------------------------------------
# Invariant 2: sum of refunds must never exceed the captured amount.
# ---------------------------------------------------------------------------


def check_refund_sum_within_capture(
    captured_amount: float | int | str | Decimal,
    refund_attempts: Sequence[AttemptRecord],
    *,
    minor_unit_digits: int = 2,
) -> list[InvariantViolation]:
    """Sum of the request_amount of every SUCCESSFUL refund attempt on one
    resource must be <= the amount that was actually captured on it.
    Rounds every amount to the currency's minor unit before summing, so a
    system that is correct to the cent doesn't get flagged for float
    representation noise."""
    cap = to_decimal(captured_amount, minor_unit_digits)
    successful = [a for a in refund_attempts if a.succeeded and a.request_amount is not None]
    total = sum((to_decimal(a.request_amount, minor_unit_digits) for a in successful), Decimal(0))
    if total > cap:
        return [
            InvariantViolation(
                invariant_id="refund_sum_within_capture",
                message=(
                    f"Successful refunds sum to {total} which exceeds the captured amount {cap} "
                    f"by {total - cap}."
                ),
                evidence=tuple(successful),
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Invariant 3: an attempt whose (from_state -> to_state) is illegal per the
# canonical lifecycle model must not have succeeded. Deliberately reuses
# lifecycle_model.is_valid_transition rather than re-deriving "what's
# illegal" a second time -- this is the same relationship
# state_exploration.py has with lifecycle_model.py, and the same
# "one canonical definition" rationale pattern_library.py's own docstring
# already established elsewhere in this codebase.
# ---------------------------------------------------------------------------


def check_no_illegal_transition_succeeded(attempts: Sequence[AttemptRecord]) -> list[InvariantViolation]:
    violations = []
    for attempt in attempts:
        if attempt.from_state is None or attempt.to_state is None:
            continue
        if not attempt.succeeded:
            continue
        if not is_valid_transition(attempt.from_state, attempt.to_state, attempt.resource_type):
            violations.append(
                InvariantViolation(
                    invariant_id="no_illegal_transition_succeeded",
                    message=(
                        f"{attempt.resource_type} '{attempt.operation}' succeeded while moving from "
                        f"'{attempt.from_state}' to '{attempt.to_state}', which the lifecycle model does "
                        "not allow."
                    ),
                    evidence=(attempt,),
                )
            )
    return violations


# ---------------------------------------------------------------------------
# Invariant 4: ledger total must equal the sum of its transactions.
# ---------------------------------------------------------------------------


def check_ledger_consistency(
    ledger_total: float | int | str | Decimal,
    transactions: Sequence[float | int | str | Decimal],
    *,
    minor_unit_digits: int = 2,
) -> list[InvariantViolation]:
    total_reported = to_decimal(ledger_total, minor_unit_digits)
    total_computed = sum((to_decimal(t, minor_unit_digits) for t in transactions), Decimal(0))
    if total_reported != total_computed:
        return [
            InvariantViolation(
                invariant_id="ledger_consistency",
                message=(
                    f"Ledger reports total {total_reported} but the {len(transactions)} recorded "
                    f"transactions sum to {total_computed} (difference {total_reported - total_computed})."
                ),
                evidence=(),
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Composition: run every invariant that has enough context to run.
# ---------------------------------------------------------------------------

ALL_ATTEMPT_INVARIANTS = (check_idempotent_replay, check_no_illegal_transition_succeeded)


def run_attempt_invariants(attempts: Sequence[AttemptRecord]) -> list[InvariantViolation]:
    """Runs every invariant that only needs a list of AttemptRecord (no
    extra context like a captured amount or ledger total) and flattens the
    results -- the "just run everything on this scenario" entry point a
    generated-scenario runner (state_exploration.py's HTTP-facing
    counterpart) calls once per scenario."""
    violations: list[InvariantViolation] = []
    for check in ALL_ATTEMPT_INVARIANTS:
        violations.extend(check(attempts))
    return violations
