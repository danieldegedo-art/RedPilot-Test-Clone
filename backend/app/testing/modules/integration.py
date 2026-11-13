"""Integration Test Module.

Exercises complete, multi-step payment flows end-to-end rather than single
requests in isolation:

  - Checkout flow: View product -> Cart -> Checkout -> Payment -> Subscription activation
  - Refund flow: Original payment -> Refund request -> Refund processed -> Notification

Every step is emitted as its own TestResult with full request/response
evidence, so a failure at step 3 of 5 is exactly as visible as a
single-request test failure anywhere else in the suite.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from app.testing.base import BaseTestModule
from app.testing.endpoints import EndpointSpec
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import ResponseEvidence, TestResult
from app.testing.webhook_polling import poll_webhook_sink


class IntegrationTestModule(BaseTestModule):
    module_id = "integration"
    display_name = "Integration Test Module"
    category = TestCategory.INTEGRATION

    async def run(self) -> None:
        await self._flow_checkout_to_subscription()
        await self._flow_payment_to_refund()

    async def _step(
        self,
        *,
        test_case_id: str,
        name: str,
        description: str,
        expected: str,
        flow_id: str,
        method: str = "GET",
        path: str = "",
        input_parameters: dict[str, Any] | None = None,
        succeed_if: Callable[[ResponseEvidence], bool] = lambda resp: resp.status_code in (200, 201),
        skip: bool = False,
    ) -> tuple[TestResult, bool]:
        """Runs one step of a multi-step flow: sends the request (unless
        skipped), evaluates it, emits + returns (TestResult, succeeded)."""
        started = datetime.now(timezone.utc)
        merged_params = {"flow_id": flow_id, **(input_parameters or {})}

        if skip:
            result = TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=name,
                description=description,
                input_parameters=merged_params,
                expected=expected,
                actual="Skipped: a prior required step in this flow did not succeed.",
                status=ResultStatus.INFO,
                started_at=started,
                finished_at=started,
                duration_ms=0.0,
            )
            await self.emit(result)
            return result, False

        req, resp = await self.context.http.request(method, path, json_body=input_parameters)
        finished = datetime.now(timezone.utc)

        if resp.error is not None:
            status, actual, ok = ResultStatus.ERROR, f"Transport error: {resp.error}", False
        elif succeed_if(resp):
            status, actual, ok = ResultStatus.PASS, f"HTTP {resp.status_code} - step completed.", True
        else:
            status, actual, ok = ResultStatus.FAIL, f"HTTP {resp.status_code} - step did not complete as expected.", False

        result = TestResult(
            test_case_id=test_case_id,
            category=self.category,
            name=name,
            description=description,
            input_parameters=merged_params,
            expected=expected,
            actual=actual,
            status=status,
            request=req,
            response=resp,
            recommendation=None if ok else f"Investigate step '{name}' in flow {flow_id} - see request/response evidence above.",
            started_at=started,
            finished_at=finished,
            duration_ms=(finished - started).total_seconds() * 1000,
        )
        await self.emit(result)
        return result, ok

    @staticmethod
    def _extract_id(body: Any, *keys: str) -> str | None:
        if not isinstance(body, dict):
            return None
        for key in keys:
            if body.get(key):
                return body[key]
        return None

    # -- Flow 1: View product -> Cart -> Checkout -> Payment -> Subscription ---

    async def _flow_checkout_to_subscription(self) -> None:
        flow_id = f"checkout-flow-{uuid.uuid4().hex[:8]}"
        ep = self.context.endpoints

        await self._step(
            test_case_id="INTEG-001",
            name="View product",
            description="Step 1/5: retrieves the product catalog to confirm the product being purchased is available.",
            method=ep.list_products.method,
            path=ep.list_products.path,
            expected="HTTP 200 with a list of available products.",
            succeed_if=lambda resp: resp.status_code == 200,
            flow_id=flow_id,
        )

        await self._step(
            test_case_id="INTEG-002",
            name="Add to cart",
            description="Step 2/5: adds the product to a cart/session.",
            method=ep.create_cart.method,
            path=ep.create_cart.path,
            input_parameters=self.resolve_payload({"productId": "prod_standard_plan", "quantity": 1}),
            expected="HTTP 200/201 confirming the item was added.",
            flow_id=flow_id,
        )

        await self._step(
            test_case_id="INTEG-003",
            name="Create checkout session",
            description="Step 3/5: initiates checkout for the cart contents.",
            method=ep.create_checkout_session.method,
            path=ep.create_checkout_session.path,
            input_parameters=self.resolve_payload({"productId": "prod_standard_plan", "quantity": 1}),
            expected="HTTP 200/201 with a checkout/session reference.",
            flow_id=flow_id,
        )

        payment_payload = self.resolve_payload({
            "amount": 49.99,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-integration@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"flow_id": flow_id},
        })
        _, payment_ok = await self._step(
            test_case_id="INTEG-004",
            name="Submit payment",
            description="Step 4/5: submits payment for the checkout session.",
            method=ep.create_payment.method,
            path=ep.create_payment.path,
            input_parameters=payment_payload,
            expected="HTTP 200/201 with a succeeded payment.",
            succeed_if=lambda resp: resp.status_code in (200, 201)
            and isinstance(resp.body, dict)
            and resp.body.get("status") in ("succeeded", "completed", "success", "paid", "approved"),
            flow_id=flow_id,
        )

        subscription_payload = self.resolve_payload({
            "planId": "plan_standard_monthly",
            "customerEmail": "qa-integration@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"flow_id": flow_id},
        })
        await self._step(
            test_case_id="INTEG-005",
            name="Subscription activates",
            description="Step 5/5: creates the subscription tied to this purchase and confirms it activates.",
            method=ep.create_subscription.method,
            path=ep.create_subscription.path,
            input_parameters=subscription_payload,
            expected="HTTP 200/201 with status 'active', 'activated', or 'trialing'.",
            succeed_if=lambda resp: resp.status_code in (200, 201)
            and isinstance(resp.body, dict)
            and resp.body.get("status") in ("active", "activated", "trialing"),
            skip=not payment_ok,
            flow_id=flow_id,
        )

    # -- Flow 2: Original payment -> Refund request -> Refund processed -> Notification ---

    async def _flow_payment_to_refund(self) -> None:
        flow_id = f"refund-flow-{uuid.uuid4().hex[:8]}"
        ep = self.context.endpoints

        payment_payload = self.resolve_payload({
            "amount": 29.99,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-refund@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"qa_correlation_id": flow_id},
        })
        payment_result, payment_ok = await self._step(
            test_case_id="INTEG-006",
            name="Original payment",
            description="Step 1/4: submits the payment that will be refunded.",
            method=ep.create_payment.method,
            path=ep.create_payment.path,
            input_parameters=payment_payload,
            expected="HTTP 200/201 with a succeeded payment.",
            succeed_if=lambda resp: resp.status_code in (200, 201)
            and isinstance(resp.body, dict)
            and resp.body.get("status") in ("succeeded", "completed", "success", "paid", "approved"),
            flow_id=flow_id,
        )

        payment_id = self._extract_id(payment_result.response.body if payment_result.response else None, "id", "paymentId", "payment_id")

        refund_result, refund_ok = await self._step(
            test_case_id="INTEG-007",
            name="Refund request",
            description="Step 2/4: requests a full refund of the original payment.",
            method=ep.create_refund.method,
            path=ep.create_refund.path,
            # NOT resolved: paymentId here is this flow's own just-created
            # payment id (chained from step 1), not a default that Recon's
            # discoveries should ever replace.
            input_parameters={"paymentId": payment_id, "reason": "qa_integration_test"},
            expected="HTTP 200/201 with the refund accepted for processing.",
            skip=not payment_ok or payment_id is None,
            flow_id=flow_id,
        )

        refund_id = self._extract_id(refund_result.response.body if refund_result.response else None, "id", "refundId", "refund_id")

        if refund_id:
            get_refund_spec: EndpointSpec = ep.get_refund
            await self._step(
                test_case_id="INTEG-008",
                name="Refund processed",
                description="Step 3/4: retrieves the refund to confirm it reached a completed/processed state.",
                method=get_refund_spec.method,
                path=get_refund_spec.path.format(refund_id=refund_id),
                expected="HTTP 200 with status 'succeeded'/'completed'/'processed'.",
                succeed_if=lambda resp: resp.status_code == 200
                and isinstance(resp.body, dict)
                and resp.body.get("status") in ("succeeded", "completed", "processed"),
                flow_id=flow_id,
            )
        else:
            await self._step(
                test_case_id="INTEG-008",
                name="Refund processed",
                description="Step 3/4: retrieves the refund to confirm it reached a completed/processed state.",
                expected="HTTP 200 with status 'succeeded'/'completed'/'processed'.",
                skip=True,
                flow_id=flow_id,
            )

        if refund_ok:
            notified = await poll_webhook_sink(self.context.run_id, flow_id, timeout_seconds=15)
        else:
            notified = False

        if not refund_ok:
            actual, status, recommendation = "Skipped: refund did not complete successfully.", ResultStatus.INFO, None
        elif notified:
            actual, status, recommendation = "Webhook received at the local sink.", ResultStatus.PASS, None
        else:
            actual = (
                "No webhook received at the local sink within 15s (may mean the staging environment's webhook "
                "URL is not pointed at this suite - see README - rather than a real failure)."
            )
            status = ResultStatus.WARNING
            recommendation = (
                "Point the staging environment's webhook endpoint at "
                f"http://<this-machine>:8420/api/v1/webhook-sink/{self.context.run_id} to verify refund "
                "notifications automatically."
            )

        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="INTEG-009",
                category=self.category,
                name="Refund notification sent",
                description="Step 4/4: confirms a refund-related webhook is delivered after the refund is processed.",
                input_parameters={"flow_id": flow_id},
                expected="A webhook event referencing this flow is received within 15 seconds of the refund completing.",
                actual=actual,
                status=status,
                recommendation=recommendation,
                started_at=now,
                finished_at=datetime.now(timezone.utc),
                duration_ms=0.0,
            )
        )
