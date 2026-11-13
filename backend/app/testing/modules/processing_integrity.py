"""Processing Integrity Module (AICPA SOC2 CC7.1).

No detailed spec was given for this module beyond its name -- unlike
Role-Based Access Verification, which had exact test cases specified. The
three cases below were chosen to cover AICPA's Processing Integrity
criteria (processing is complete, valid, accurate, and correctly
deduplicated) at points this suite doesn't already test elsewhere:

  - ROLE-002 (role_based_access) already tests whether payment/subscription
    STATUS fields can be forged via mass assignment across every route.
    This module instead tests whether payment PROCESSING ITSELF -- a
    legitimate call to the real payment-creation endpoint -- is complete,
    accurate, and correctly deduplicated on retry.
  - EdgeCase's "webhook replay" case already tests idempotency at the
    WEBHOOK-DELIVERY level (the server receiving the same Stripe event
    twice). PROC-001 below tests the client-REQUEST level equivalent: does
    retrying the same payment-creation call (a very real scenario --
    client timeouts, mobile network drops) double-charge.

  PROC-001: Idempotency key replay. Sends an identical payment-creation
    request twice with the same Idempotency-Key header (Stripe's own
    convention, https://stripe.com/docs/api/idempotent_requests) and
    checks whether both resolve to the SAME resource id.

  PROC-002: Round-trip amount/currency fidelity. Creates a payment with a
    specific amount+currency, then re-fetches that exact resource with a
    separate GET (not just trusting the creation response) and confirms
    the persisted record still shows what was submitted.

  PROC-003: Duplicate submission without an idempotency key. Documents
    (INFO/WARNING, not FAIL by itself) whether two identical, key-less
    submissions create two separate charges -- many systems intentionally
    leave double-submit protection to the client, so this is audit-record
    exposure information rather than an asserted compliance gap.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import TestResult


def _extract_id(body: Any, *keys: str) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in keys:
        if body.get(key):
            return body[key]
    return None


def _amounts_match(persisted: Any, expected: Any, tolerance: float = 0.01) -> bool:
    try:
        expected_amount = float(expected)
    except (TypeError, ValueError):
        return False
    if isinstance(persisted, bool):
        return False
    if isinstance(persisted, (int, float)):
        return abs(float(persisted) - expected_amount) < tolerance
    if isinstance(persisted, str):
        try:
            return abs(float(persisted) - expected_amount) < tolerance
        except ValueError:
            return False
    return False


class ProcessingIntegrityModule(BaseTestModule):
    module_id = "processing_integrity"
    display_name = "Processing Integrity (SOC2 CC7.1)"
    category = TestCategory.PROCESSING_INTEGRITY

    async def run(self) -> None:
        await self._case_idempotency_replay()
        await self._case_roundtrip_fidelity()
        await self._case_duplicate_submission()

    def _base_payload(self, test_case_id: str, amount: float) -> dict[str, Any]:
        return self.resolve_payload({
            "amount": amount,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-processing-integrity@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"qa_test_case": test_case_id},
        })

    # -- PROC-001 -------------------------------------------------------

    async def _case_idempotency_replay(self) -> None:
        ep = self.context.endpoints
        idempotency_key = f"qa-idem-{uuid.uuid4().hex[:20]}"
        payload = self._base_payload("PROC-001", 19.99)

        started = datetime.now(timezone.utc)
        _, resp1 = await self.context.http.request(
            ep.create_payment.method, ep.create_payment.path, json_body=payload, extra_headers={"Idempotency-Key": idempotency_key}
        )
        req2, resp2 = await self.context.http.request(
            ep.create_payment.method, ep.create_payment.path, json_body=payload, extra_headers={"Idempotency-Key": idempotency_key}
        )
        finished = datetime.now(timezone.utc)

        id1 = _extract_id(resp1.body, "id", "paymentId", "payment_id")
        id2 = _extract_id(resp2.body, "id", "paymentId", "payment_id")

        if resp1.error is not None or resp2.error is not None:
            status = ResultStatus.ERROR
            actual = f"Transport error: {resp1.error or resp2.error}"
        elif id1 is None or id2 is None:
            status = ResultStatus.INFO
            actual = (
                f"Could not extract a resource id from one or both responses (HTTP {resp1.status_code} / "
                f"HTTP {resp2.status_code}) - idempotency could not be evaluated this way."
            )
        elif id1 == id2:
            status = ResultStatus.PASS
            actual = f"Both requests, sent with the same Idempotency-Key, resolved to the same resource id ({id1}) - retries are correctly deduplicated."
        else:
            status = ResultStatus.WARNING
            actual = (
                f"The two requests, sent with the identical Idempotency-Key header, returned two DIFFERENT "
                f"resource ids ({id1} vs {id2}). This endpoint does not appear to honor the idempotency key - a "
                "client retry (timeout, mobile network drop) risks a duplicate charge."
            )

        await self.emit(
            TestResult(
                test_case_id="PROC-001",
                category=self.category,
                name="Idempotency key replay",
                description=(
                    "Sends an identical payment-creation request twice with the same Idempotency-Key header and "
                    "checks whether the second response references the same resource as the first, or creates a "
                    "second, independent one -- CC7.1: processing must remain complete and accurate even when a "
                    "client legitimately retries the same request."
                ),
                input_parameters={**payload, "idempotency_key": idempotency_key},
                expected="Both requests resolve to the same resource id.",
                actual=actual,
                status=status,
                request=req2,
                response=resp2,
                recommendation=None
                if status in (ResultStatus.PASS, ResultStatus.INFO)
                else "Honor the Idempotency-Key header on payment-creation endpoints: on a repeated key within its retention window, return the original resource instead of creating a new one.",
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- PROC-002 -------------------------------------------------------

    async def _case_roundtrip_fidelity(self) -> None:
        ep = self.context.endpoints
        payload = self._base_payload("PROC-002", 27.53)
        # Read amount/currency back OUT of the resolved payload rather than
        # trusting the 27.53 literal above -- resolve_payload may have
        # substituted a real discovered value, and the round-trip check
        # below must compare against whatever was actually sent.
        amount, currency = payload["amount"], payload["currency"]

        started = datetime.now(timezone.utc)
        create_req, create_resp = await self.context.http.request(ep.create_payment.method, ep.create_payment.path, json_body=payload)
        payment_id = _extract_id(create_resp.body, "id", "paymentId", "payment_id")

        if create_resp.error is not None or payment_id is None:
            finished = datetime.now(timezone.utc)
            await self.emit(
                TestResult(
                    test_case_id="PROC-002",
                    category=self.category,
                    name="Round-trip amount/currency fidelity",
                    description=(
                        "Creates a payment with a specific amount/currency, then re-fetches that exact resource "
                        "with a separate GET and confirms the persisted record matches what was submitted -- "
                        "CC7.1: what's stored must match what was processed, not just what the creation response "
                        "echoed back."
                    ),
                    input_parameters=payload,
                    expected="A payment is created and its id can be extracted for the follow-up read.",
                    actual=f"Transport error creating the payment: {create_resp.error}"
                    if create_resp.error is not None
                    else f"HTTP {create_resp.status_code} - could not extract a resource id from the creation response, so round-trip fidelity could not be evaluated.",
                    status=ResultStatus.ERROR if create_resp.error is not None else ResultStatus.INFO,
                    request=create_req,
                    response=create_resp,
                    started_at=started,
                    finished_at=finished,
                    duration_ms=(finished - started).total_seconds() * 1000,
                )
            )
            return

        get_spec = ep.get_payment
        read_req, read_resp = await self.context.http.request(get_spec.method, get_spec.path.format(payment_id=payment_id))
        finished = datetime.now(timezone.utc)

        if read_resp.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error re-fetching the created payment: {read_resp.error}"
        elif read_resp.status_code != 200 or not isinstance(read_resp.body, dict):
            status = ResultStatus.WARNING
            actual = f"HTTP {read_resp.status_code} re-fetching payment {payment_id} - could not independently confirm the persisted amount/currency."
        else:
            persisted_amount = read_resp.body.get("amount")
            persisted_currency = read_resp.body.get("currency")
            amount_ok = _amounts_match(persisted_amount, amount)
            currency_ok = isinstance(persisted_currency, str) and persisted_currency.upper() == currency.upper()
            if amount_ok and currency_ok:
                status = ResultStatus.PASS
                actual = f"Re-fetched payment {payment_id} shows amount={persisted_amount}, currency={persisted_currency} - matches exactly what was submitted."
            else:
                status = ResultStatus.FAIL
                actual = (
                    f"Re-fetched payment {payment_id} shows amount={persisted_amount!r}, "
                    f"currency={persisted_currency!r} - does not match what was submitted (amount={amount}, "
                    f"currency={currency})."
                )

        await self.emit(
            TestResult(
                test_case_id="PROC-002",
                category=self.category,
                name="Round-trip amount/currency fidelity",
                description=(
                    "Creates a payment with a specific amount/currency, then re-fetches that exact resource with "
                    "a separate GET and confirms the persisted record matches what was submitted -- CC7.1: what's "
                    "stored must match what was processed, not just what the creation response echoed back."
                ),
                input_parameters=payload,
                expected=f"GET on the created payment returns amount={amount}, currency={currency}.",
                actual=actual,
                status=status,
                request=read_req,
                response=read_resp,
                recommendation=None
                if status in (ResultStatus.PASS, ResultStatus.WARNING)
                else "Confirm the amount/currency stored on the resource always matches what was submitted at creation - re-fetch and compare rather than trusting only the creation response.",
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- PROC-003 -------------------------------------------------------

    async def _case_duplicate_submission(self) -> None:
        ep = self.context.endpoints
        payload = self._base_payload("PROC-003", 15.00)

        started = datetime.now(timezone.utc)
        _, resp1 = await self.context.http.request(ep.create_payment.method, ep.create_payment.path, json_body=payload)
        req2, resp2 = await self.context.http.request(ep.create_payment.method, ep.create_payment.path, json_body=payload)
        finished = datetime.now(timezone.utc)

        id1 = _extract_id(resp1.body, "id", "paymentId", "payment_id")
        id2 = _extract_id(resp2.body, "id", "paymentId", "payment_id")
        succeeded1 = resp1.status_code in (200, 201) and id1 is not None
        succeeded2 = resp2.status_code in (200, 201) and id2 is not None

        if resp1.error is not None or resp2.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error: {resp1.error or resp2.error}"
        elif succeeded1 and succeeded2 and id1 != id2:
            status = ResultStatus.WARNING
            actual = (
                f"Two identical requests with no idempotency key both succeeded, creating two separate payments "
                f"({id1}, {id2}). This may be intentional if duplicate-submission protection is left to the "
                "client (e.g. disabling the submit button after the first click) -- documented here for the "
                "audit record, not asserted as a compliance gap by itself."
            )
        elif succeeded1 and succeeded2 and id1 == id2:
            status, actual = ResultStatus.PASS, f"Both identical submissions resolved to the same resource id ({id1}) - deduplicated even without an idempotency key."
        elif succeeded1 and not succeeded2:
            status, actual = ResultStatus.PASS, f"The second identical submission was rejected (HTTP {resp2.status_code}) while the first succeeded ({id1})."
        else:
            status = ResultStatus.INFO
            actual = f"Could not evaluate duplicate-submission behavior from these responses (HTTP {resp1.status_code} / HTTP {resp2.status_code})."

        await self.emit(
            TestResult(
                test_case_id="PROC-003",
                category=self.category,
                name="Duplicate submission without an idempotency key",
                description=(
                    "Sends an identical payment-creation request twice with NO idempotency key -- the scenario "
                    "an accidental double-click or naive client retry produces -- and documents whether this "
                    "creates two separate charges."
                ),
                input_parameters=payload,
                expected="N/A - this case documents behavior; see `actual` for whether duplicate submissions were deduplicated.",
                actual=actual,
                status=status,
                request=req2,
                response=resp2,
                recommendation=None
                if status in (ResultStatus.PASS, ResultStatus.INFO)
                else "If two identical, key-less submissions creating separate charges is not intentional, add natural-key deduplication (e.g. same customer + amount + product within a short window) or require an idempotency key on this endpoint.",
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )
