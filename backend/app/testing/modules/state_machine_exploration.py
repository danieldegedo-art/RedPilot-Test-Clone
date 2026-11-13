"""State Machine Exploration Module -- the HTTP-facing counterpart to
app.testing.state_exploration's pure graph algorithms.

WHY THIS FILE IS SEPARATE FROM state_exploration.py
------------------------------------------------------
state_exploration.py enumerates a graph; it cannot know which concrete
endpoint reaches which state on any given target -- that mapping is
target-specific domain knowledge (see EndpointMap's own docstring: "every
payment platform names its routes differently"). This module is that
mapping, plus the driving/attempting/evaluating loop, generalized from
the exact pattern modules/state_transition_consistency.py's
_run_unusual_transition_check already establishes for its two
hand-written cases -- this module runs the SAME kind of check, generated
exhaustively instead of hand-picked.

WHAT "PROVIDER-AGNOSTIC" ACTUALLY MEANS HERE (READ BEFORE ASSUMING THIS
"JUST WORKS" AGAINST ANY TARGET)
-------------------------------------------------------------------------
EndpointMap's built-in default vocabulary (app/testing/endpoints.py) has
create_payment, get_payment and create_refund for payments -- NOT a
separate capture_payment or cancel_payment. That is an honest fact about
the vocabulary as it ships today, not a gap in this module: plenty of
real payment APIs (Stripe's PaymentIntents included) DO expose capture
and cancel as their own calls, and a target that does needs those two
operations added via the exact mechanism this project already uses for
target-specific extension elsewhere (see additional_webhook_security.py's
provider-config pattern):

    endpoints = EndpointMap(overrides={
        "capture_payment": EndpointSpec("POST", "/api/v1/payments/{payment_id}/capture"),
        "cancel_payment": EndpointSpec("POST", "/api/v1/payments/{payment_id}/cancel"),
    })

Without that override, this module does not guess a URL -- it SKIPS
every scenario that needs an unconfigured operation and records exactly
why (same "don't guess, skip with a stated reason" principle
checkout_provider_testing.py's STRIPE-001 boundary already established).
Against the unmodified default vocabulary alone, only the
create/refund-shaped slice of the lifecycle is exercised; against a
target with capture_payment/cancel_payment configured, the full lifecycle
is. Both are reported separately below -- see get_last_run_scope_report.

VERIFIED, AND HOW
------------------
Against a real local reference target (see the project's before/after
report and shims/reference_target.py, both outside this package -- the
target and the httpx/pydantic shims used to verify this file are
verification infrastructure, not shipped product code) over real TCP
sockets, with capture_payment/cancel_payment configured via override.
Not verified against a real payment provider, and not verified with the
real httpx/pydantic packages (unavailable, offline sandbox) -- see the
report for exactly what that does and does not prove.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.invariants import AttemptRecord, check_no_illegal_transition_succeeded, check_refund_sum_within_capture
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult
from app.testing.lifecycle_model import VALID_PAYMENT_TRANSITIONS
from app.testing.state_exploration import ExplorationResult, explore_payment, reachable_states

# (canonical operation name, extra body fields) needed to ATTEMPT moving a
# resource TO this state. "refund_amount_fraction" is filled in by the
# caller (1.0 for a full refund reaching "refunded", 0.5 for a partial one
# reaching "partially_refunded") since it depends on the resource's
# captured amount, not a fixed body value.
ATTEMPT_OPERATION: dict[str, tuple[str, dict[str, Any]]] = {
    "captured": ("capture_payment", {}),
    "cancelled": ("cancel_payment", {}),
    "refunded": ("create_refund", {"refund_amount_fraction": 1.0}),
    "partially_refunded": ("create_refund", {"refund_amount_fraction": 0.5}),
}

# Ordered list of (operation, extra body fields) to drive a freshly
# created payment INTO a given state, used as this module's "from_state"
# setup. "authorized" needs no steps: create_payment's response is
# already the entry point every VALID_PAYMENT_TRANSITIONS key assumes.
ENTRY_RECIPE: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "authorized": [],
    "captured": [ATTEMPT_OPERATION["captured"]],
    "cancelled": [ATTEMPT_OPERATION["cancelled"]],
    "refunded": [ATTEMPT_OPERATION["captured"], ATTEMPT_OPERATION["refunded"]],
    "partially_refunded": [ATTEMPT_OPERATION["captured"], ATTEMPT_OPERATION["partially_refunded"]],
}


class StateMachineExplorationModule(BaseTestModule):
    """Runs every illegal-transition and concurrent-race scenario
    state_exploration.explore_payment() can find, that this run's
    EndpointMap has the operations to actually attempt. Category/name
    follow the same TestResult shape every other module in this package
    produces -- nothing downstream (reporting, the dashboard, coverage
    mapping) needs to know this module's cases were generated rather than
    hand-written."""

    module_id = "state_machine_exploration"
    display_name = "State Machine Exploration"
    category = TestCategory.STATE_TRANSITION_CONSISTENCY

    def __init__(self, context: Any, emit: Any) -> None:
        super().__init__(context, emit)
        self._skipped: list[dict[str, str]] = []

    def _get_endpoints(self):
        return self.context.endpoints

    def build_refund_body(self, payment_id: str, amount: float) -> dict[str, Any]:
        """The one piece of this module that assumed a specific request
        shape rather than going through EndpointMap: create_refund's
        default endpoint (POST /api/v1/refunds) expects the payment id
        AND the amount in the JSON body, and this project's own default
        target uses the field names "paymentId" (amount) and dollars, not
        cents. A provider with different field names, a different unit
        (cents), or the id in the URL instead of the body needs ONLY to
        override this one method -- no change to state_exploration.py,
        invariants.py, or anything else in this file. Found and fixed as
        part of proving the "one interface, nothing else" claim against a
        second, deliberately different reference target (see the
        project's before/after report) -- this method didn't exist before
        that check, and the hardcoded body below was the actual, real
        exception to that claim until it did.
        """
        return {"paymentId": payment_id, "amount": round(amount, 2)}

    def build_create_payment_body(self, amount: float) -> dict[str, Any]:
        """Same rationale as build_refund_body, for create_payment's body
        shape -- found at the same time, for the same reason (Provider
        B's amountCents-in-cents convention doesn't match this default)."""
        return {"amount": amount}

    def _resolvable(self, operation: str) -> bool:
        """True if `operation` is either in the built-in default
        vocabulary or explicitly configured via EndpointMap(overrides=).
        Mirrors EndpointMap.get's own lookup order rather than
        re-deriving it, so this check can never disagree with what a
        real call would actually resolve to."""
        ep = self._get_endpoints()
        return operation in ep.overrides or operation in ep._defaults

    async def run(self) -> None:
        exploration = explore_payment()
        # Bounded by the SAME module_concurrency setting runner.py already
        # uses to bound how many independent MODULES run in parallel
        # (see registry.py's batch_execution_order) -- reused here rather
        # than introducing a second, separate concurrency knob, since both
        # answer the same underlying question: how much concurrent load
        # against the target is acceptable right now. Safe because every
        # scenario below creates and drives its OWN fresh payment; nothing
        # is shared across scenarios (contrast with the state RACE tests,
        # which deliberately share one payment WITHIN a single scenario).
        limit = max(1, getattr(self.context.settings, "module_concurrency", 4))
        semaphore = asyncio.Semaphore(limit)
        await self._run_illegal_transitions(exploration, semaphore)
        await self._run_concurrent_races(exploration, semaphore)

    # -- Setup: create a payment and drive it to a given state -----------

    async def _create_payment(self, amount: float = 100.00) -> tuple[str | None, ResponseEvidence]:
        ep = self._get_endpoints()
        _, resp = await self.context.http.request(
            ep.create_payment.method, ep.create_payment.path, json_body=self.build_create_payment_body(amount)
        )
        payment_id = None
        if resp.status_code < 300 and isinstance(resp.body, dict):
            payment_id = resp.body.get("id") or resp.body.get("payment_id")
        return payment_id, resp

    async def _attempt(self, payment_id: str, operation: str, extra: dict[str, Any]) -> tuple[RequestEvidence, ResponseEvidence, str | None]:
        """Fires one operation attempt against `payment_id`. Returns
        (request, response, error) -- error is set (and request/response
        are best-effort placeholders) when `operation` isn't resolvable,
        so callers can record a clear skip reason instead of crashing."""
        if not self._resolvable(operation):
            placeholder_req = RequestEvidence(method="?", url=f"<{operation} not configured>")
            placeholder_resp = ResponseEvidence(error=f"'{operation}' not configured in EndpointMap")
            return placeholder_req, placeholder_resp, f"'{operation}' is not in EndpointMap's default vocabulary and no override is configured"

        ep = self._get_endpoints()
        spec = ep.get(operation)
        path = spec.path.format(payment_id=payment_id)
        body: dict[str, Any] = {}
        if operation == "create_refund":
            amount = extra.get("_captured_amount", 0.0) * extra.get("refund_amount_fraction", 1.0)
            body = self.build_refund_body(payment_id, amount)
        req, resp = await self.context.http.request(spec.method, path, json_body=body if body else None)
        return req, resp, None

    async def _drive_to_state(self, target_state: str) -> tuple[str | None, float, str | None]:
        """Creates a payment and applies ENTRY_RECIPE[target_state] in
        order. Returns (payment_id, captured_amount, error)."""
        payment_id, create_resp = await self._create_payment()
        if payment_id is None:
            return None, 0.0, f"setup failed: create_payment returned {create_resp.status_code}"
        captured_amount = 100.00
        for operation, extra in ENTRY_RECIPE.get(target_state, []):
            _, resp, error = await self._attempt(payment_id, operation, {**extra, "_captured_amount": captured_amount})
            if error:
                return None, 0.0, f"setup skipped: {error}"
            if resp.status_code >= 300:
                return None, 0.0, f"setup failed: '{operation}' returned {resp.status_code} while driving to '{target_state}'"
        return payment_id, captured_amount, None

    # -- Illegal transitions ------------------------------------------------

    async def _run_illegal_transitions(self, exploration: ExplorationResult, semaphore: asyncio.Semaphore) -> None:
        candidates = [t for t in exploration.illegal_transitions if t.to_state in ATTEMPT_OPERATION and t.from_state in ENTRY_RECIPE]

        async def bounded(i: int, illegal) -> None:
            async with semaphore:
                await self._run_one_illegal_transition(f"STATE-EXPL-{i:03d}", illegal)

        await asyncio.gather(*(bounded(i, illegal) for i, illegal in enumerate(candidates, start=1)))

    async def _run_one_illegal_transition(self, test_case_id: str, illegal) -> None:
        started = datetime.now(timezone.utc)
        operation, extra = ATTEMPT_OPERATION[illegal.to_state]

        if not self._resolvable(operation):
            self._skipped.append({"case": illegal.id, "reason": f"'{operation}' not configured"})
            return

        payment_id, captured_amount, setup_error = await self._drive_to_state(illegal.from_state)
        if setup_error:
            self._skipped.append({"case": illegal.id, "reason": setup_error})
            return

        req, resp, error = await self._attempt(payment_id, operation, {**extra, "_captured_amount": captured_amount})
        if error:
            self._skipped.append({"case": illegal.id, "reason": error})
            return

        attempt = AttemptRecord(
            operation=operation, resource_type="payment",
            from_state=illegal.from_state, to_state=illegal.to_state,
            succeeded=(resp.status_code < 300),
        )
        violations = check_no_illegal_transition_succeeded([attempt])
        finished = datetime.now(timezone.utc)

        await self.emit(
            TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=f"Illegal transition rejected: {illegal.from_state} -> {illegal.to_state}",
                description=(
                    f"Generated by exhaustive state-space exploration (not hand-specified): attempts to move a "
                    f"payment from '{illegal.from_state}' to '{illegal.to_state}' via '{operation}', which "
                    f"lifecycle_model.VALID_PAYMENT_TRANSITIONS does not allow from that state."
                ),
                input_parameters={"from_state": illegal.from_state, "to_state": illegal.to_state, "operation": operation},
                expected=f"Request rejected (4xx/409) -- '{illegal.from_state}' -> '{illegal.to_state}' is not a legal transition.",
                actual=f"HTTP {resp.status_code}" + (" -- transition WRONGLY accepted" if violations else " -- correctly rejected"),
                status=ResultStatus.FAIL if violations else ResultStatus.PASS,
                request=req,
                response=resp,
                recommendation=None if not violations else (
                    f"'{operation}' must verify the resource's current state is a legal source state for this "
                    f"transition before applying it (reject with 409/422 otherwise)."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- Concurrent races -------------------------------------------------

    async def _run_concurrent_races(self, exploration: ExplorationResult, semaphore: asyncio.Semaphore) -> None:
        candidates = [
            r for r in exploration.concurrent_races
            if r.operation_a in ATTEMPT_OPERATION and r.operation_b in ATTEMPT_OPERATION and r.from_state in ENTRY_RECIPE
        ]

        async def bounded(i: int, race) -> None:
            async with semaphore:
                await self._run_one_race(f"STATE-EXPL-RACE-{i:03d}", race)

        await asyncio.gather(*(bounded(i, race) for i, race in enumerate(candidates, start=1)))

    async def _run_one_race(self, test_case_id: str, race) -> None:
        started = datetime.now(timezone.utc)
        op_a, extra_a = ATTEMPT_OPERATION[race.operation_a]
        op_b, extra_b = ATTEMPT_OPERATION[race.operation_b]

        if not (self._resolvable(op_a) and self._resolvable(op_b)):
            self._skipped.append({"case": race.id, "reason": f"'{op_a}' or '{op_b}' not configured"})
            return

        payment_id, captured_amount, setup_error = await self._drive_to_state(race.from_state)
        if setup_error:
            self._skipped.append({"case": race.id, "reason": setup_error})
            return

        (req_a, resp_a, err_a), (req_b, resp_b, err_b) = await asyncio.gather(
            self._attempt(payment_id, op_a, {**extra_a, "_captured_amount": captured_amount}),
            self._attempt(payment_id, op_b, {**extra_b, "_captured_amount": captured_amount}),
        )
        if err_a or err_b:
            self._skipped.append({"case": race.id, "reason": err_a or err_b})
            return

        attempts = [
            AttemptRecord(operation=op_a, resource_type="payment", succeeded=resp_a.status_code < 300,
                          request_amount=captured_amount * extra_a.get("refund_amount_fraction", 0) if op_a == "create_refund" else None),
            AttemptRecord(operation=op_b, resource_type="payment", succeeded=resp_b.status_code < 300,
                          request_amount=captured_amount * extra_b.get("refund_amount_fraction", 0) if op_b == "create_refund" else None),
        ]
        successes = sum(1 for a in attempts if a.succeeded)
        violations = list(check_no_illegal_transition_succeeded(attempts))
        if op_a == "create_refund" and op_b == "create_refund":
            # Both operations are refunds (e.g. a full-refund vs a
            # partial-refund race from the same "captured" state): the
            # precise violation is an over-refund, not merely "more than
            # one succeeded" (two PARTIAL refunds can both legitimately
            # succeed as long as their sum stays within the captured
            # amount).
            violations += check_refund_sum_within_capture(captured_amount, attempts)
            mutually_exclusive = False
        else:
            # NOT mutually exclusive purely because both are legal exits
            # from the same from_state -- that was this module's first,
            # WRONG assumption (see the project's before/after report:
            # running this exact check against the reference target
            # produced a false positive on "captured vs refunded from
            # authorized", because a successful capture legitimately
            # ENABLES a subsequent refund; they aren't competing
            # alternatives, one is a prerequisite for the other). The
            # correct test: two outcomes are mutually exclusive only if
            # NEITHER is reachable from the other in the lifecycle graph
            # -- if operation_b's target is reachable from
            # operation_a's target (or vice versa), succeeding at one can
            # legitimately unlock the other, so "at most one may succeed"
            # does not apply.
            a_enables_b = race.operation_b in reachable_states(VALID_PAYMENT_TRANSITIONS, race.operation_a)
            b_enables_a = race.operation_a in reachable_states(VALID_PAYMENT_TRANSITIONS, race.operation_b)
            mutually_exclusive = not (a_enables_b or b_enables_a)
        too_many_succeeded = mutually_exclusive and successes > 1
        finished = datetime.now(timezone.utc)

        status = ResultStatus.FAIL if (violations or too_many_succeeded) else ResultStatus.PASS
        expected = (
            "At most one of the two concurrent operations succeeds."
            if mutually_exclusive
            else "Both may succeed (one legitimately enables the other), but never in a way that violates another "
                 "invariant (e.g. refund totals must never exceed the captured amount)."
        )
        await self.emit(
            TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=f"Concurrent race: {race.operation_a} vs {race.operation_b} from {race.from_state}",
                description=(
                    f"Generated by exhaustive state-space exploration: fires '{op_a}' and '{op_b}' concurrently "
                    f"(asyncio.gather, real interleaving) against a payment in state '{race.from_state}'. "
                    + ("These are mutually-exclusive outcomes." if mutually_exclusive else
                       "One outcome can legitimately enable the other (not mutually exclusive).")
                ),
                input_parameters={"from_state": race.from_state, "operation_a": op_a, "operation_b": op_b},
                expected=expected,
                actual=f"a={resp_a.status_code} b={resp_b.status_code} ({successes} succeeded)",
                status=status,
                request=req_a,
                response=resp_a,
                recommendation=None if status == ResultStatus.PASS else (
                    "Use row-level locking or optimistic concurrency control on this resource's state/balance "
                    "fields so two concurrent requests cannot both read a pre-write value."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    def get_last_run_scope_report(self) -> dict[str, Any]:
        """How much of the exhaustive graph this run actually attempted
        versus skipped for lack of a configured operation -- the honest
        "what this proves" counterpart to state_exploration's raw counts.
        """
        return {"skipped": list(self._skipped), "skipped_count": len(self._skipped)}
