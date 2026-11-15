"""Lifecycle Consistency Module.

No detailed spec was given for this module beyond its name. Where
Integration exercises the payment/subscription lifecycle's HAPPY-PATH
sequence end-to-end, this module targets the lifecycle's EDGE
transitions: repeated terminal operations, operations attempted on a
reference that never reached the state they require, and whether a
resource's status reads the same way from every endpoint that reports it.
Runs LAST in the module order (see registry.py) since it deliberately
takes the test account's subscription through a real cancellation -- the
same kind of deliberate, real state change Integration's own refund flow
already performs on the test account -- and nothing later in the same run
should be surprised by that.

  LIFECYCLE-001: Double cancellation. Creates a subscription, cancels it,
    then cancels it again. A repeated terminal operation on an
    already-terminal resource should be rejected, or answered
    idempotently (still reporting a cancelled-consistent status) -- never
    with a 5xx suggesting the second call wasn't handled at all, and
    never by reporting a status that looks reactivated.

  LIFECYCLE-002: Refund of a payment reference that never existed. This
    suite has no reliable way to make a *real* payment fail (every module
    uses a single fixed success token, `tok_test_visa_valid` -- there's no
    established "declined card" convention to reuse, see negative.py), so
    rather than inventing one, this case targets the same underlying
    principle more directly: a refund request naming a payment id that
    was never created has nothing to refund and should be rejected.

  LIFECYCLE-003: Double refund of an already-refunded payment. Creates a
    payment, refunds it (expected to succeed), then refunds the SAME
    payment again. A payment with nothing left to refund should reject a
    second refund, not process it again.

  LIFECYCLE-004: Cross-endpoint status consistency. After LIFECYCLE-001's
    cancellation, re-reads the subscription's status via the dedicated
    get_subscription endpoint AND via every account-management GET route
    Recon's FunctionMap discovered, checking all of them agree it's
    cancelled -- catching the common bug class where one write path
    updates a record a *different* read path doesn't consult.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import TestResult
from app.testing.recon.function_mapper import FunctionCategory, FunctionMap

_STATUS_LIKE_KEYS: tuple[str, ...] = ("status", "subscription_status", "subscriptionStatus", "plan_status", "planStatus", "state")
_ACTIVE_LOOKING_VALUES = {"active", "activated", "trialing", "trial"}
_CANCELLED_LOOKING_VALUES = {"cancelled", "canceled", "inactive", "expired", "ended"}


def _extract_id(body: Any, *keys: str) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in keys:
        if body.get(key):
            return body[key]
    return None


def _find_status_like_field(body: Any) -> tuple[str, str] | None:
    if not isinstance(body, dict):
        return None
    for key in _STATUS_LIKE_KEYS:
        value = body.get(key)
        if isinstance(value, str) and value:
            return key, value.lower()
    return None


class LifecycleConsistencyModule(BaseTestModule):
    module_id = "lifecycle_consistency"
    display_name = "Lifecycle Consistency"
    category = TestCategory.LIFECYCLE_CONSISTENCY

    async def run(self) -> None:
        cancelled_subscription_id = await self._case_double_cancellation()
        await self._case_refund_nonexistent_payment()
        await self._case_double_refund()
        await self._case_cross_endpoint_status_consistency(cancelled_subscription_id)

    # -- LIFECYCLE-001 ---------------------------------------------------

    async def _case_double_cancellation(self) -> str | None:
        ep = self.context.endpoints
        flow_id = f"lifecycle-cancel-{uuid.uuid4().hex[:8]}"
        subscription_payload = self.resolve_payload({
            "planId": "plan_standard_monthly",
            "customerEmail": "qa-lifecycle@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"flow_id": flow_id},
        })

        started = datetime.now(timezone.utc)
        _, create_resp = await self.context.http.request(ep.create_subscription.method, ep.create_subscription.path, json_body=subscription_payload)
        subscription_id = _extract_id(create_resp.body, "id", "subscriptionId", "subscription_id")

        if create_resp.error is not None or subscription_id is None:
            await self._emit_lifecycle_result(
                test_case_id="LIFECYCLE-001",
                name="Double cancellation",
                description=(
                    "Creates a subscription, cancels it, then cancels it again -- a repeated terminal operation "
                    "should be rejected or answered idempotently, never with a server error or a status that "
                    "looks reactivated."
                ),
                input_parameters=subscription_payload,
                expected="A subscription is created and its id can be extracted for the cancellation steps.",
                actual=f"Transport error creating the subscription: {create_resp.error}"
                if create_resp.error is not None
                else f"HTTP {create_resp.status_code} - could not extract a subscription id from the creation response, so cancellation could not be tested.",
                status=ResultStatus.ERROR if create_resp.error is not None else ResultStatus.INFO,
                request=None,
                response=create_resp,
                started=started,
            )
            return None

        cancel_spec = ep.cancel_subscription
        cancel_path = cancel_spec.path.format(subscription_id=subscription_id)
        _, first_cancel = await self.context.http.request(cancel_spec.method, cancel_path)
        second_req, second_cancel = await self.context.http.request(cancel_spec.method, cancel_path)
        finished = datetime.now(timezone.utc)

        if first_cancel.error is not None or first_cancel.status_code not in (200, 201, 204):
            status = ResultStatus.INFO
            actual = f"The first cancellation did not clearly succeed (HTTP {first_cancel.status_code}), so a second, repeated cancellation isn't a meaningful test here."
        elif second_cancel.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error on the second cancellation: {second_cancel.error}"
        elif second_cancel.status_code is not None and second_cancel.status_code >= 500:
            status = ResultStatus.FAIL
            actual = f"The second cancellation returned HTTP {second_cancel.status_code} - a repeated terminal operation crashed the server instead of being handled cleanly."
        elif second_cancel.status_code is not None and 400 <= second_cancel.status_code < 500:
            status = ResultStatus.PASS
            actual = f"The second cancellation was rejected (HTTP {second_cancel.status_code}) - the subscription was already cancelled."
        elif second_cancel.status_code is not None and 200 <= second_cancel.status_code < 300:
            status_field = _find_status_like_field(second_cancel.body)
            if status_field is None:
                status = ResultStatus.INFO
                actual = f"The second cancellation returned HTTP {second_cancel.status_code} with no recognizable status field in the body - can't confirm the subscription still reads as cancelled."
            elif status_field[1] in _ACTIVE_LOOKING_VALUES:
                status = ResultStatus.FAIL
                actual = f"The second cancellation returned HTTP {second_cancel.status_code} with {status_field[0]}='{status_field[1]}' - the subscription appears to have been REACTIVATED by a repeated cancel call."
            else:
                status = ResultStatus.PASS
                actual = f"The second cancellation returned HTTP {second_cancel.status_code} with {status_field[0]}='{status_field[1]}' - idempotent no-op; re-cancelling an already-cancelled subscription is safe."
        else:
            status = ResultStatus.WARNING
            actual = f"The second cancellation returned an unexpected HTTP {second_cancel.status_code}."

        await self._emit_lifecycle_result(
            test_case_id="LIFECYCLE-001",
            name="Double cancellation",
            description=(
                "Creates a subscription, cancels it, then cancels it again -- a repeated terminal operation "
                "should be rejected or answered idempotently, never with a server error or a status that looks "
                "reactivated."
            ),
            input_parameters={"subscription_id": subscription_id},
            expected="The second cancellation is rejected, or succeeds idempotently while still reporting a cancelled-consistent status.",
            actual=actual,
            status=status,
            request=second_req,
            response=second_cancel,
            started=started,
            finished=finished,
            recommendation=None
            if status in (ResultStatus.PASS, ResultStatus.INFO)
            else "Guard the cancellation handler against repeated calls on an already-cancelled subscription: return a clean 4xx or an idempotent no-op, never a 5xx or a reactivated status.",
        )
        return subscription_id

    # -- LIFECYCLE-002 ---------------------------------------------------

    async def _case_refund_nonexistent_payment(self) -> None:
        ep = self.context.endpoints
        fake_payment_id = f"pay_qa_lifecycle_nonexistent_{uuid.uuid4().hex[:16]}"
        # NOT resolved: fake_payment_id must never accidentally become a
        # real, discovered payment id -- the entire test is that this
        # reference was never created.
        payload = {"paymentId": fake_payment_id, "reason": "qa_lifecycle_test"}

        started = datetime.now(timezone.utc)
        req, resp = await self.context.http.request(ep.create_refund.method, ep.create_refund.path, json_body=payload)
        finished = datetime.now(timezone.utc)

        if resp.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error: {resp.error}"
        elif resp.status_code is not None and 400 <= resp.status_code < 500:
            status, actual = ResultStatus.PASS, f"HTTP {resp.status_code} - refund of a payment reference that was never created was correctly rejected."
        elif resp.status_code is not None and resp.status_code >= 500:
            status, actual = ResultStatus.FAIL, f"HTTP {resp.status_code} - server error instead of a clean rejection for a non-existent payment reference."
        elif resp.status_code is not None and 200 <= resp.status_code < 300:
            status = ResultStatus.FAIL
            actual = f"HTTP {resp.status_code} - a refund was processed for a payment id that this suite never created ({fake_payment_id}). The refund endpoint does not appear to validate that the referenced payment exists."
        else:
            status, actual = ResultStatus.WARNING, f"HTTP {resp.status_code} - unexpected response; could not classify."

        await self._emit_lifecycle_result(
            test_case_id="LIFECYCLE-002",
            name="Refund of a non-existent payment reference",
            description=(
                "Requests a refund for a fabricated payment id that was never created and checks it's rejected -- "
                "a refund target must exist and have actually succeeded before it can have anything refunded from it."
            ),
            input_parameters=payload,
            expected="HTTP 4xx - the payment reference is not found / not refundable.",
            actual=actual,
            status=status,
            request=req,
            response=resp,
            started=started,
            finished=finished,
            recommendation=None if status == ResultStatus.PASS else "Validate that a refund's paymentId references a payment that exists and reached a succeeded/captured state before processing the refund.",
        )

    # -- LIFECYCLE-003 ---------------------------------------------------

    async def _case_double_refund(self) -> None:
        ep = self.context.endpoints
        flow_id = f"lifecycle-refund-{uuid.uuid4().hex[:8]}"
        payment_payload = self.resolve_payload({
            "amount": 22.00,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-lifecycle@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"flow_id": flow_id},
        })

        started = datetime.now(timezone.utc)
        _, payment_resp = await self.context.http.request(ep.create_payment.method, ep.create_payment.path, json_body=payment_payload)
        payment_id = _extract_id(payment_resp.body, "id", "paymentId", "payment_id")

        if payment_resp.error is not None or payment_id is None:
            await self._emit_lifecycle_result(
                test_case_id="LIFECYCLE-003",
                name="Double refund of an already-refunded payment",
                description="Refunds a payment, then attempts to refund the same payment again -- a payment with nothing left to refund should reject a second refund.",
                input_parameters=payment_payload,
                expected="A payment is created and its id can be extracted for the refund steps.",
                actual=f"Transport error creating the payment: {payment_resp.error}"
                if payment_resp.error is not None
                else f"HTTP {payment_resp.status_code} - could not extract a payment id, so the double-refund scenario could not be set up.",
                status=ResultStatus.ERROR if payment_resp.error is not None else ResultStatus.INFO,
                request=None,
                response=payment_resp,
                started=started,
            )
            return

        refund_payload = {"paymentId": payment_id, "reason": "qa_lifecycle_test"}  # NOT resolved: chained id from this flow's own payment above
        _, first_refund = await self.context.http.request(ep.create_refund.method, ep.create_refund.path, json_body=refund_payload)
        second_req, second_refund = await self.context.http.request(ep.create_refund.method, ep.create_refund.path, json_body=refund_payload)
        finished = datetime.now(timezone.utc)

        if first_refund.error is not None or first_refund.status_code not in (200, 201):
            status = ResultStatus.INFO
            actual = f"The first refund did not clearly succeed (HTTP {first_refund.status_code}), so a second refund attempt isn't a meaningful test here."
        elif second_refund.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error on the second refund: {second_refund.error}"
        elif second_refund.status_code is not None and 400 <= second_refund.status_code < 500:
            status, actual = ResultStatus.PASS, f"The second refund of the same payment was rejected (HTTP {second_refund.status_code}) - nothing left to refund."
        elif second_refund.status_code is not None and second_refund.status_code >= 500:
            status, actual = ResultStatus.FAIL, f"The second refund returned HTTP {second_refund.status_code} - a repeated refund crashed the server instead of being cleanly rejected."
        elif second_refund.status_code is not None and 200 <= second_refund.status_code < 300:
            status = ResultStatus.FAIL
            actual = f"The second refund of payment {payment_id} returned HTTP {second_refund.status_code} - the payment appears to have been refunded twice."
        else:
            status, actual = ResultStatus.WARNING, f"The second refund returned an unexpected HTTP {second_refund.status_code}."

        await self._emit_lifecycle_result(
            test_case_id="LIFECYCLE-003",
            name="Double refund of an already-refunded payment",
            description="Refunds a payment, then attempts to refund the same payment again -- a payment with nothing left to refund should reject a second refund, not process it again.",
            input_parameters={"payment_id": payment_id},
            expected="The second refund of the same payment is rejected.",
            actual=actual,
            status=status,
            request=second_req,
            response=second_refund,
            started=started,
            finished=finished,
            recommendation=None if status in (ResultStatus.PASS, ResultStatus.INFO) else "Track the refunded (or remaining refundable) amount on a payment and reject a refund request that would exceed it.",
        )

    # -- LIFECYCLE-004 ---------------------------------------------------

    async def _case_cross_endpoint_status_consistency(self, cancelled_subscription_id: str | None) -> None:
        if cancelled_subscription_id is None:
            await self._emit_lifecycle_result(
                test_case_id="LIFECYCLE-004",
                name="Cross-endpoint status consistency",
                description="Checks that every account-management route Recon discovered agrees a cancelled subscription actually reads as cancelled.",
                input_parameters={},
                expected="N/A - informational.",
                actual="Skipped: LIFECYCLE-001 did not produce a cancelled subscription id to check consistency against.",
                status=ResultStatus.INFO,
            )
            return

        ep = self.context.endpoints
        get_spec = ep.get_subscription
        started = datetime.now(timezone.utc)
        canonical_req, canonical_resp = await self.context.http.request(get_spec.method, get_spec.path.format(subscription_id=cancelled_subscription_id))
        canonical_field = _find_status_like_field(canonical_resp.body)

        function_map = self.context.shared_state.get("function_map")
        other_routes = []
        if isinstance(function_map, FunctionMap):
            other_routes = [r for r in function_map.by_category(FunctionCategory.ACCOUNT_MANAGEMENT) if r.method == "GET" and r.path != get_spec.path]

        findings: list[str] = []
        inconsistent = False
        checked_any_other = False

        if canonical_field is None:
            findings.append(f"get_subscription ({get_spec.path}): HTTP {canonical_resp.status_code}, no recognizable status field - can't establish a baseline to compare against.")
        else:
            findings.append(f"get_subscription ({get_spec.path}): {canonical_field[0]}='{canonical_field[1]}'.")

        for route in other_routes:
            _, resp = await self.context.http.request(route.method, route.path)
            field = _find_status_like_field(resp.body)
            if field is None:
                continue
            checked_any_other = True
            findings.append(f"{route.method} {route.path}: {field[0]}='{field[1]}'.")
            if field[1] in _ACTIVE_LOOKING_VALUES:
                inconsistent = True

        finished = datetime.now(timezone.utc)

        if canonical_field is None:
            status = ResultStatus.INFO
        elif canonical_field[1] not in _CANCELLED_LOOKING_VALUES:
            status = ResultStatus.INFO
            findings.append("get_subscription itself doesn't report a recognizably cancelled value, so cross-endpoint consistency can't be meaningfully evaluated this run.")
        elif not checked_any_other:
            status = ResultStatus.INFO
            findings.append("No other discovered account-management route exposed a comparable status field this run.")
        elif inconsistent:
            status = ResultStatus.FAIL
        else:
            status = ResultStatus.PASS

        await self._emit_lifecycle_result(
            test_case_id="LIFECYCLE-004",
            name="Cross-endpoint status consistency",
            description=(
                "Re-reads a just-cancelled subscription's status via get_subscription AND via every "
                "account-management GET route Recon's FunctionMap discovered, checking they all agree it's "
                "cancelled -- catching the case where one write path updates a record a different read path "
                "doesn't consult."
            ),
            input_parameters={"subscription_id": cancelled_subscription_id, "other_routes_checked": len(other_routes)},
            expected="Every route reporting this subscription's status agrees it is cancelled.",
            actual=" ".join(findings),
            status=status,
            request=canonical_req,
            response=canonical_resp,
            started=started,
            finished=finished,
            recommendation=None if status != ResultStatus.FAIL else "At least one other endpoint still reports this subscription as active/trialing after cancellation - confirm every read path consults the same source of truth as the cancellation write path (e.g. no separate cache or denormalized column left stale).",
        )

    # -- shared emit helper ------------------------------------------------

    async def _emit_lifecycle_result(
        self,
        *,
        test_case_id: str,
        name: str,
        description: str,
        input_parameters: dict[str, Any],
        expected: str,
        actual: str,
        status: ResultStatus,
        request=None,
        response=None,
        started: datetime | None = None,
        finished: datetime | None = None,
        recommendation: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        started = started or now
        finished = finished or now
        await self.emit(
            TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=name,
                description=description,
                input_parameters=input_parameters,
                expected=expected,
                actual=actual,
                status=status,
                request=request,
                response=response,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )
