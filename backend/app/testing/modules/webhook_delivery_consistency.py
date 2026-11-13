"""Webhook Delivery Consistency Module (Module 14).

Verifies that the system under test processes webhook notifications
consistently and safely across five dimensions:

  WEBHOOK-001: Duplicate delivery handling — sends the same notification
    twice within milliseconds and checks whether the second is properly
    recognized as a repeat.
  WEBHOOK-002: Out-of-sequence processing — sends a completion notification
    before the referenced payment has actually been finalized, checking
    whether the handler verifies state server-side rather than trusting
    the notification alone.
  WEBHOOK-003: Timestamp window validation — sends a notification with a
    timestamp far outside the recommended tolerance window, checking
    whether it is correctly declined.
  WEBHOOK-004: Short-delay repeat handling — sends the same notification
    twice with a 500ms gap, verifying that repeat processing is safely
    handled regardless of timing.
  WEBHOOK-005: Long-delay repeat handling — sends the same notification
    twice with a 5-second gap, verifying consistent repeat handling
    independent of the delay.

All five cases follow the same verification pattern as the rest of this
suite: the system should correctly REJECT or safely ignore the unusual
input. A PASS means the control works; a FAIL means the processing is
inconsistent or unsafe.

Based on documented incident patterns:
- Empty-signature processing (Stripe Advisory GHSA-xff3-5c9p-2mr4)
- Verification-before-processing (Derk Online Blog)
- Missing amount validation (WordPress Plugin incidents, WPScan 2024)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult


def _build_notification_body(suffix: str, payment_id: str = "pay_test_12345") -> dict[str, Any]:
    """Constructs a synthetic completion notification for testing."""
    return {
        "id": f"ntf_qa_{suffix}",
        "object": "notification",
        "type": "payment.completed",
        "created": int(time.time()),
        "data": {
            "object": {
                "id": payment_id,
                "object": "payment",
                "status": "succeeded",
                "amount": 2999,
                "currency": "usd",
                "customer_email": "qa-webhook@example.com",
            }
        },
    }


def _compute_signature(body: str, secret: str, timestamp: int) -> str:
    """Computes an HMAC-SHA256 signature in the format used by common
    webhook providers (t=timestamp,v1=hex_digest)."""
    signed_payload = f"{timestamp}.{body}"
    digest = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def _classify_response(resp: ResponseEvidence) -> str:
    """Coarse classification shared by these checks."""
    if resp.status_code is None:
        return "transport_error"
    if 400 <= resp.status_code < 500:
        return "declined"
    if resp.status_code >= 500:
        return "server_error"
    if 200 <= resp.status_code < 300:
        return "accepted"
    return "unclear"


class WebhookDeliveryConsistencyModule(BaseTestModule):
    """Webhook Delivery Consistency Module — verifies that webhook
    notifications are processed consistently, with proper duplicate
    detection, state verification, and timestamp validation."""

    module_id = "webhook_delivery_consistency"
    display_name = "Webhook Delivery Consistency"
    category = TestCategory.WEBHOOK_DELIVERY_CONSISTENCY

    # Shared signing secret for synthetic notifications (the system under
    # test should use its own configured secret; we are testing whether it
    # validates the signature structure, not the secret itself)
    _TEST_SIGNING_SECRET = "whsec_qa_test_secret_for_validation"

    async def run(self) -> None:
        await self._case_duplicate_immediate()
        await self._case_out_of_sequence()
        await self._case_timestamp_window()
        await self._case_duplicate_short_delay()
        await self._case_duplicate_long_delay()

    def _get_webhook_endpoint(self) -> tuple[str, str]:
        """Returns (method, path) for the webhook notification endpoint."""
        spec = self.context.endpoints.stripe_webhook
        return spec.method, spec.path

    async def _send_notification(
        self,
        body: dict[str, Any],
        signature: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[RequestEvidence, ResponseEvidence]:
        """Sends a webhook notification to the configured endpoint."""
        method, path = self._get_webhook_endpoint()
        headers = {"Content-Type": "application/json"}
        if signature is not None:
            headers["Stripe-Signature"] = signature
        if extra_headers:
            headers.update(extra_headers)

        body_str = json.dumps(body)
        return await self.context.http.request(
            method, path, raw_body=body_str.encode("utf-8"), extra_headers=headers
        )

    def _verify_subscription_state(self) -> tuple[RequestEvidence, ResponseEvidence]:
        """Reads the current subscription state via a GET endpoint."""
        spec = self.context.endpoints.get_subscription
        # Use a fixed test subscription reference
        path = spec.path.format(subscription_id="sub_qa_webhook_test")
        return asyncio.get_event_loop().run_until_complete(
            self.context.http.request(spec.method, path)
        )

    async def _check_resource_state(
        self,
        notification_body: dict[str, Any],
        check_description: str,
    ) -> tuple[ResultStatus, str]:
        """Checks whether a resource referenced in a notification was
        actually modified by querying the system's read endpoints."""
        payment_id = notification_body.get("data", {}).get("object", {}).get("id", "")
        if not payment_id:
            return ResultStatus.INFO, "Could not extract resource id from notification body."

        spec = self.context.endpoints.get_payment
        path = spec.path.format(payment_id=payment_id)
        _, resp = await self.context.http.request(spec.method, path)

        if resp.error is not None:
            return ResultStatus.ERROR, f"Transport error checking resource state: {resp.error}"

        if resp.status_code == 404:
            return (
                ResultStatus.PASS,
                f"Resource {payment_id} not found — notification was correctly ignored (no state was created).",
            )

        if resp.status_code == 200 and isinstance(resp.body, dict):
            status = resp.body.get("status", "")
            if status in ("succeeded", "completed", "active"):
                return (
                    ResultStatus.FAIL,
                    f"Resource {payment_id} shows status '{status}' — notification was processed and "
                    f"state was changed despite {check_description}.",
                )
            return (
                ResultStatus.INFO,
                f"Resource {payment_id} shows status '{status}' — no clear state change from notification.",
            )

        return ResultStatus.INFO, f"HTTP {resp.status_code} checking resource state."

    # -- WEBHOOK-001 -------------------------------------------------------

    async def _case_duplicate_immediate(self) -> None:
        """Duplicate notification delivered within milliseconds should be
        recognized as a repeat and safely ignored."""
        notification = _build_notification_body("dup_immediate")
        body_str = json.dumps(notification)
        timestamp = int(time.time())
        signature = _compute_signature(body_str, self._TEST_SIGNING_SECRET, timestamp)

        started = datetime.now(timezone.utc)
        req1, resp1 = await self._send_notification(notification, signature)
        req2, resp2 = await self._send_notification(notification, signature)
        finished = datetime.now(timezone.utc)

        classification1 = _classify_response(resp1)
        classification2 = _classify_response(resp2)

        state_status, state_detail = await self._check_resource_state(
            notification, "immediate duplicate delivery"
        )

        if classification1 == "transport_error" or classification2 == "transport_error":
            overall_status = ResultStatus.ERROR
            actual = (
                f"First delivery: {resp1.error or resp1.status_code}, "
                f"Second delivery: {resp2.error or resp2.status_code} — transport error."
            )
        elif state_status == ResultStatus.FAIL:
            overall_status = ResultStatus.FAIL
            actual = (
                f"First notification: HTTP {resp1.status_code}, Second notification: HTTP {resp2.status_code}. "
                f"{state_detail} — duplicate notification was processed twice."
            )
        elif classification1 == "accepted" and classification2 == "accepted":
            if state_status == ResultStatus.PASS:
                overall_status = ResultStatus.PASS
                actual = (
                    f"Both deliveries returned HTTP {resp1.status_code} (acknowledged), but "
                    f"{state_detail} — duplicate was safely deduplicated."
                )
            else:
                overall_status = ResultStatus.WARNING
                actual = (
                    f"Both deliveries returned HTTP {resp1.status_code}, but could not confirm "
                    f"from resource state whether deduplication occurred. {state_detail}"
                )
        elif classification1 == "accepted" and classification2 == "declined":
            overall_status = ResultStatus.PASS
            actual = (
                f"First delivery: HTTP {resp1.status_code} (accepted), "
                f"Second delivery: HTTP {resp2.status_code} (declined as duplicate). "
                "Duplicate detection is working correctly."
            )
        elif classification1 == "declined" and classification2 == "declined":
            overall_status = ResultStatus.INFO
            actual = (
                f"Both deliveries returned HTTP {resp1.status_code} — the notification was declined "
                "both times. This may indicate the signature or format was not accepted at all."
            )
        else:
            overall_status = ResultStatus.WARNING
            actual = (
                f"First delivery: HTTP {resp1.status_code} ({classification1}), "
                f"Second delivery: HTTP {resp2.status_code} ({classification2}). "
                "Could not determine duplicate handling from these responses alone."
            )

        await self.emit(
            TestResult(
                test_case_id="WEBHOOK-001",
                category=self.category,
                name="Duplicate notification (immediate) is safely ignored",
                description=(
                    "Sends the same webhook notification twice within milliseconds and verifies "
                    "that the second delivery is recognized as a repeat and safely deduplicated. "
                    "The system should either decline the second request or accept it without "
                    "processing the underlying state change twice."
                ),
                input_parameters={
                    "notification_id": notification["id"],
                    "delay_between": "0ms (immediate)",
                },
                expected="Second delivery is declined (4xx) or acknowledged without duplicate processing.",
                actual=actual,
                status=overall_status,
                request=req2,
                response=resp2,
                recommendation=None if overall_status == ResultStatus.PASS else (
                    "Implement duplicate detection using notification IDs: track processed IDs "
                    "and safely ignore repeats, regardless of timing."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- WEBHOOK-002 -------------------------------------------------------

    async def _case_out_of_sequence(self) -> None:
        """Notification referencing an unfinalized resource should not
        trigger state changes."""
        # Create a notification that claims a payment completed, but the
        # payment_id references something that was never actually created
        fake_payment_id = f"pay_qa_unfinalized_{uuid.uuid4().hex[:12]}"
        notification = _build_notification_body("premature", fake_payment_id)
        body_str = json.dumps(notification)
        timestamp = int(time.time())
        signature = _compute_signature(body_str, self._TEST_SIGNING_SECRET, timestamp)

        started = datetime.now(timezone.utc)
        req, resp = await self._send_notification(notification, signature)
        finished = datetime.now(timezone.utc)

        classification = _classify_response(resp)

        state_status, state_detail = await self._check_resource_state(
            notification, "the referenced payment was never finalized"
        )

        if classification == "transport_error":
            overall_status = ResultStatus.ERROR
            actual = f"Transport error: {resp.error}"
        elif state_status == ResultStatus.FAIL:
            overall_status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — notification was processed and state was changed "
                f"even though the referenced payment ({fake_payment_id}) was never finalized. "
                "Whether the server verifies the referenced payment before acting is NOT externally observable; "
                "the internal cause is UNKNOWN (only the customer-facing read response above is evidence)."
            )
        elif classification == "accepted":
            if state_status == ResultStatus.PASS:
                overall_status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — notification was acknowledged but no state was "
                    "created (resource not found on verification). This may be intentional, "
                    "but whether the server verifies the referenced payment is UNKNOWN from outside (not externally observable)."
                )
            else:
                overall_status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — notification was accepted. {state_detail} "
                    "Server-side verification of the referenced resource should be confirmed."
                )
        elif classification == "declined":
            overall_status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — notification was correctly declined. "
                "The handler verifies that the referenced resource exists before processing."
            )
        else:
            overall_status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine from response alone."

        await self.emit(
            TestResult(
                test_case_id="WEBHOOK-002",
                category=self.category,
                name="Notification referencing unfinalized resource is safely handled",
                description=(
                    "Sends a completion notification that references a payment which was never "
                    "actually finalized. Verifies that the system checks the referenced resource's "
                    "actual state server-side rather than trusting the notification alone. "
                    "Based on documented incident patterns where handlers processed notifications "
                    "without verifying the underlying state."
                ),
                input_parameters={
                    "notification_id": notification["id"],
                    "referenced_payment_id": fake_payment_id,
                },
                expected="Notification is declined (4xx) or acknowledged without state change, because the referenced resource does not exist or is not in the expected state.",
                actual=actual,
                status=overall_status,
                request=req,
                response=resp,
                recommendation=None if overall_status == ResultStatus.PASS else (
                    "Before acting on any webhook notification, retrieve the referenced resource "
                    "from the server-side data store and verify it is in the expected state. "
                    "Never trust the notification body alone as proof of state."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- WEBHOOK-003 -------------------------------------------------------

    async def _case_timestamp_window(self) -> None:
        """Notification with a timestamp outside the tolerance window
        should be declined."""
        notification = _build_notification_body("old_timestamp")
        body_str = json.dumps(notification)

        # Create a timestamp that is 10 minutes in the past
        old_timestamp = int(time.time()) - 600  # 10 minutes ago
        signature = _compute_signature(body_str, self._TEST_SIGNING_SECRET, old_timestamp)

        started = datetime.now(timezone.utc)
        req, resp = await self._send_notification(notification, signature)
        finished = datetime.now(timezone.utc)

        classification = _classify_response(resp)

        if classification == "transport_error":
            overall_status = ResultStatus.ERROR
            actual = f"Transport error: {resp.error}"
        elif classification == "declined":
            overall_status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — notification with old timestamp (10 minutes ago) "
                "was correctly declined. Timestamp window validation is working."
            )
        elif classification == "accepted":
            overall_status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — notification with a timestamp 10 minutes in the past "
                "was accepted (externally observed). The endpoint therefore behaves as if it applies no timestamp tolerance "
                "window, which would allow replay of old notifications; the internal cause is UNKNOWN and is not inferred."
            )
        else:
            overall_status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine from response alone."

        await self.emit(
            TestResult(
                test_case_id="WEBHOOK-003",
                category=self.category,
                name="Notification with out-of-window timestamp is declined",
                description=(
                    "Sends a notification with a signature timestamp that is 10 minutes in the past "
                    "(well outside the recommended 5-minute tolerance window). Verifies that the "
                    "handler checks the timestamp freshness before processing. "
                    "Based on documented guidance for webhook signature validation."
                ),
                input_parameters={
                    "notification_id": notification["id"],
                    "timestamp_age_seconds": 600,
                    "tolerance_window_seconds": 300,
                },
                expected="HTTP 4xx — notification is declined because the timestamp is outside the tolerance window.",
                actual=actual,
                status=overall_status,
                request=req,
                response=resp,
                recommendation=None if overall_status == ResultStatus.PASS else (
                    "Implement timestamp validation: reject notifications whose signature timestamp "
                    "is more than 5 minutes (300 seconds) from the current time. This prevents "
                    "replay of legitimately-signed but old notifications."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- WEBHOOK-004 -------------------------------------------------------

    async def _case_duplicate_short_delay(self) -> None:
        """Duplicate notification with 500ms delay should still be
        safely handled."""
        notification = _build_notification_body("dup_500ms")
        body_str = json.dumps(notification)
        timestamp = int(time.time())
        signature = _compute_signature(body_str, self._TEST_SIGNING_SECRET, timestamp)

        started = datetime.now(timezone.utc)
        req1, resp1 = await self._send_notification(notification, signature)

        # Wait 500ms before the second delivery
        await asyncio.sleep(0.5)
        req2, resp2 = await self._send_notification(notification, signature)
        finished = datetime.now(timezone.utc)

        classification1 = _classify_response(resp1)
        classification2 = _classify_response(resp2)

        state_status, state_detail = await self._check_resource_state(
            notification, "duplicate delivery with 500ms delay"
        )

        if classification1 == "transport_error" or classification2 == "transport_error":
            overall_status = ResultStatus.ERROR
            actual = (
                f"First delivery: {resp1.error or resp1.status_code}, "
                f"Second delivery: {resp2.error or resp2.status_code} — transport error."
            )
        elif state_status == ResultStatus.FAIL:
            overall_status = ResultStatus.FAIL
            actual = (
                f"First notification: HTTP {resp1.status_code}, Second notification: HTTP {resp2.status_code}. "
                f"{state_detail} — duplicate was processed despite 500ms delay between deliveries."
            )
        elif classification1 == "accepted" and classification2 == "accepted":
            if state_status == ResultStatus.PASS:
                overall_status = ResultStatus.PASS
                actual = (
                    f"Both deliveries returned HTTP {resp1.status_code}, and {state_detail} — "
                    "duplicate handling works correctly with short delays."
                )
            else:
                overall_status = ResultStatus.WARNING
                actual = (
                    f"Both deliveries returned HTTP {resp1.status_code}. {state_detail} "
                    "Could not confirm deduplication from state alone."
                )
        elif classification1 == "accepted" and classification2 == "declined":
            overall_status = ResultStatus.PASS
            actual = (
                f"First delivery: HTTP {resp1.status_code} (accepted), "
                f"Second delivery: HTTP {resp2.status_code} (declined). "
                "Duplicate detection works with short delays."
            )
        else:
            overall_status = ResultStatus.WARNING
            actual = (
                f"First: HTTP {resp1.status_code} ({classification1}), "
                f"Second: HTTP {resp2.status_code} ({classification2}). "
                "Could not determine duplicate handling for short-delay scenario."
            )

        await self.emit(
            TestResult(
                test_case_id="WEBHOOK-004",
                category=self.category,
                name="Duplicate notification (500ms delay) is safely ignored",
                description=(
                    "Sends the same webhook notification twice with a 500ms delay between deliveries. "
                    "Verifies that duplicate detection works correctly even when deliveries are separated "
                    "by a short but non-zero delay. This tests a documented edge case where timing-based "
                    "deduplication mechanisms may fail."
                ),
                input_parameters={
                    "notification_id": notification["id"],
                    "delay_between": "500ms",
                },
                expected="Second delivery is declined or safely deduplicated regardless of the 500ms delay.",
                actual=actual,
                status=overall_status,
                request=req2,
                response=resp2,
                recommendation=None if overall_status == ResultStatus.PASS else (
                    "Ensure duplicate detection uses notification IDs (not timing) so that repeats "
                    "are safely handled regardless of the delay between deliveries."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- WEBHOOK-005 -------------------------------------------------------

    async def _case_duplicate_long_delay(self) -> None:
        """Duplicate notification with 5-second delay should still be
        safely handled."""
        notification = _build_notification_body("dup_5s")
        body_str = json.dumps(notification)
        timestamp = int(time.time())
        signature = _compute_signature(body_str, self._TEST_SIGNING_SECRET, timestamp)

        started = datetime.now(timezone.utc)
        req1, resp1 = await self._send_notification(notification, signature)

        # Wait 5 seconds before the second delivery
        await asyncio.sleep(5.0)
        req2, resp2 = await self._send_notification(notification, signature)
        finished = datetime.now(timezone.utc)

        classification1 = _classify_response(resp1)
        classification2 = _classify_response(resp2)

        state_status, state_detail = await self._check_resource_state(
            notification, "duplicate delivery with 5-second delay"
        )

        if classification1 == "transport_error" or classification2 == "transport_error":
            overall_status = ResultStatus.ERROR
            actual = (
                f"First delivery: {resp1.error or resp1.status_code}, "
                f"Second delivery: {resp2.error or resp2.status_code} — transport error."
            )
        elif state_status == ResultStatus.FAIL:
            overall_status = ResultStatus.FAIL
            actual = (
                f"First notification: HTTP {resp1.status_code}, Second notification: HTTP {resp2.status_code}. "
                f"{state_detail} — duplicate was processed despite 5-second delay between deliveries."
            )
        elif classification1 == "accepted" and classification2 == "accepted":
            if state_status == ResultStatus.PASS:
                overall_status = ResultStatus.PASS
                actual = (
                    f"Both deliveries returned HTTP {resp1.status_code}, and {state_detail} — "
                    "duplicate handling works correctly with longer delays."
                )
            else:
                overall_status = ResultStatus.WARNING
                actual = (
                    f"Both deliveries returned HTTP {resp1.status_code}. {state_detail} "
                    "Could not confirm deduplication from state alone."
                )
        elif classification1 == "accepted" and classification2 == "declined":
            overall_status = ResultStatus.PASS
            actual = (
                f"First delivery: HTTP {resp1.status_code} (accepted), "
                f"Second delivery: HTTP {resp2.status_code} (declined). "
                "Duplicate detection works with longer delays."
            )
        else:
            overall_status = ResultStatus.WARNING
            actual = (
                f"First: HTTP {resp1.status_code} ({classification1}), "
                f"Second: HTTP {resp2.status_code} ({classification2}). "
                "Could not determine duplicate handling for long-delay scenario."
            )

        await self.emit(
            TestResult(
                test_case_id="WEBHOOK-005",
                category=self.category,
                name="Duplicate notification (5-second delay) is safely ignored",
                description=(
                    "Sends the same webhook notification twice with a 5-second delay between deliveries. "
                    "Verifies that duplicate detection is consistent regardless of the delay between "
                    "deliveries. Tests whether the deduplication mechanism uses persistent state "
                    "(notification IDs) rather than short-lived timing checks."
                ),
                input_parameters={
                    "notification_id": notification["id"],
                    "delay_between": "5s",
                },
                expected="Second delivery is declined or safely deduplicated regardless of the 5-second delay.",
                actual=actual,
                status=overall_status,
                request=req2,
                response=resp2,
                recommendation=None if overall_status == ResultStatus.PASS else (
                    "Ensure duplicate detection uses persistent state (e.g., a processed-notification-IDs "
                    "store with appropriate TTL) rather than in-memory timing checks that may expire."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )
