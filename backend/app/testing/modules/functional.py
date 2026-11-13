"""Functional Test Module (Positive Testing).

Verifies that valid transactions are processed correctly: a well-formed
payment succeeds, the response is well-formed, the transaction is
retrievable afterwards (persisted), a webhook is delivered, and a valid
subscription activates.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory, TestScope
from app.testing.models import ResponseEvidence, TestResult
from app.testing.webhook_polling import poll_webhook_sink


class FunctionalTestModule(BaseTestModule):
    module_id = "functional"
    display_name = "Functional Test Module (Positive Testing)"
    category = TestCategory.FUNCTIONAL

    async def run(self) -> None:
        payment_id = await self._case_valid_payment_succeeds()
        await self._case_response_format_and_status()
        if payment_id:
            await self._case_transaction_recorded(payment_id)
        await self._case_webhook_notification()
        if self.context.scope != TestScope.SMOKE:
            await self._case_subscription_activation()

    def _base_payment_payload(self, correlation_id: str) -> dict:
        return self.resolve_payload({
            "amount": 49.99,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-functional@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"qa_correlation_id": correlation_id},
        })

    @staticmethod
    def _evaluate_payment_success(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
        body_status = resp.body.get("status") if isinstance(resp.body, dict) else None
        succeeded = resp.status_code in (200, 201) and body_status in (
            "succeeded", "completed", "success", "paid", "approved",
        )
        if succeeded:
            return ResultStatus.PASS, f"HTTP {resp.status_code} - body status='{body_status}'"
        return ResultStatus.FAIL, f"HTTP {resp.status_code} - body status='{body_status}'"

    async def _case_valid_payment_succeeds(self) -> str | None:
        spec = self.context.endpoints.create_payment
        payload = self._base_payment_payload(str(uuid.uuid4()))

        result = await self.execute_case(
            test_case_id="FUNC-001",
            name="Valid payment is accepted",
            description="Submits a payment with all valid, well-formed parameters and expects it to succeed.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 200/201 with a success status in the response body.",
            evaluate=self._evaluate_payment_success,
            recommendation=(
                "Confirm the create-payment endpoint path and payload shape match your API "
                "(override via EndpointMap) and that the staging environment has a working test "
                "payment method configured."
            ),
        )
        if result.status == ResultStatus.PASS.value and isinstance(result.response.body, dict):
            body = result.response.body
            return body.get("id") or body.get("paymentId") or body.get("payment_id")
        return None

    async def _case_response_format_and_status(self) -> None:
        spec = self.context.endpoints.create_payment
        payload = self._base_payment_payload(str(uuid.uuid4()))

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code not in (200, 201):
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - expected 200/201"
            if not isinstance(resp.body, dict):
                return ResultStatus.FAIL, "Response body is not a JSON object"
            id_like = {f for f in ("id", "paymentId", "payment_id") if f in resp.body}
            if not id_like or "status" not in resp.body:
                return ResultStatus.WARNING, f"HTTP {resp.status_code} but no id/status field found in body: {list(resp.body.keys())}"
            content_type = resp.headers.get("content-type", "")
            if "application/json" not in content_type.lower():
                return ResultStatus.WARNING, f"HTTP {resp.status_code}, valid body, but Content-Type is '{content_type}' not application/json"
            return ResultStatus.PASS, f"HTTP {resp.status_code}, JSON body with fields: {list(resp.body.keys())}"

        await self.execute_case(
            test_case_id="FUNC-002",
            name="Response format and status code are correct",
            description="Verifies a successful payment returns a JSON body with an id/status field and the correct Content-Type.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 200/201, Content-Type: application/json, body includes an id and status field.",
            evaluate=evaluate,
            recommendation="Ensure successful responses always include an id field and set Content-Type: application/json explicitly.",
        )

    async def _case_transaction_recorded(self, payment_id: str) -> None:
        spec = self.context.endpoints.get_payment
        path = spec.path.format(payment_id=payment_id)
        started = datetime.now(timezone.utc)
        req, resp = await self.context.http.request(spec.method, path)
        finished = datetime.now(timezone.utc)

        if resp.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error: {resp.error}"
        elif resp.status_code == 200 and isinstance(resp.body, dict) and (
            resp.body.get("id") == payment_id or resp.body.get("paymentId") == payment_id
        ):
            status, actual = ResultStatus.PASS, f"HTTP {resp.status_code} - transaction {payment_id} retrievable and recorded"
        else:
            status, actual = ResultStatus.FAIL, f"HTTP {resp.status_code} - transaction {payment_id} could not be verified via {path}"

        await self.emit(
            TestResult(
                test_case_id="FUNC-003",
                category=self.category,
                name="Transaction is recorded",
                description="After a successful payment, retrieves it by id to confirm it was persisted with matching details.",
                input_parameters={"payment_id": payment_id},
                expected=f"GET {spec.path} returns HTTP 200 with the same payment id.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=None if status == ResultStatus.PASS else (
                    "Confirm the get-payment endpoint is configured in EndpointMap and that successful "
                    "payments are persisted before the create-payment response is returned (not async-only)."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    async def _case_webhook_notification(self) -> None:
        """Best-effort webhook verification: triggers a payment tagged with a
        correlation id, then polls the local webhook sink for a short window.
        Requires the staging environment's webhook URL to be pointed at this
        backend's /api/v1/webhook-sink/{run_id} endpoint (see README)."""
        spec = self.context.endpoints.create_payment
        correlation_id = str(uuid.uuid4())
        payload = self.resolve_payload(self._base_payment_payload(correlation_id))

        started = datetime.now(timezone.utc)
        req, resp = await self.context.http.request(spec.method, spec.path, json_body=payload)

        received = False
        if resp.error is None and resp.status_code in (200, 201):
            received = await poll_webhook_sink(self.context.run_id, correlation_id, timeout_seconds=15)
        finished = datetime.now(timezone.utc)

        if resp.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error creating payment: {resp.error}"
        elif resp.status_code not in (200, 201):
            status, actual = ResultStatus.FAIL, f"Payment creation failed (HTTP {resp.status_code}); webhook not tested."
        elif received:
            status, actual = ResultStatus.PASS, "Webhook received at the local sink within 15s, correlation id matched."
        else:
            status, actual = ResultStatus.WARNING, (
                "No webhook received at the local sink within 15s. This may mean the staging "
                "environment's webhook URL is not pointed at this suite, rather than a real failure."
            )

        await self.emit(
            TestResult(
                test_case_id="FUNC-004",
                category=self.category,
                name="Webhook notification is sent",
                description="Confirms a payment.succeeded-style webhook is delivered after a successful payment.",
                input_parameters=payload,
                expected="A webhook event referencing this payment is received within 15 seconds.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=None if status == ResultStatus.PASS else (
                    "Point the staging environment's webhook endpoint at "
                    f"http://<this-machine>:8420/api/v1/webhook-sink/{self.context.run_id} for this test "
                    "to verify delivery automatically."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    async def _case_subscription_activation(self) -> None:
        spec = self.context.endpoints.create_subscription
        payload = self.resolve_payload({
            "planId": "plan_standard_monthly",
            "customerEmail": "qa-functional@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
        })

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            body_status = resp.body.get("status") if isinstance(resp.body, dict) else None
            if resp.status_code in (200, 201) and body_status in ("active", "activated", "trialing"):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - subscription status='{body_status}'"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - subscription status='{body_status}'"

        await self.execute_case(
            test_case_id="FUNC-005",
            name="Subscription activates for a valid payment",
            description="Creates a subscription with a valid payment method and expects it to activate immediately (or enter trial).",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 200/201 with status 'active', 'activated', or 'trialing'.",
            evaluate=evaluate,
            recommendation="Confirm the subscription endpoint activates synchronously, or exposes a status field the client can poll if activation is async.",
        )
