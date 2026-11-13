"""Edge Case Module.

Verifies the system handles boundary and adversarial-shaped input
gracefully: extreme/precision price values, unicode and oversized text
fields, concurrent identical checkout requests (race conditions), and
webhook replay (idempotency).
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult


class EdgeCaseTestModule(BaseTestModule):
    module_id = "edge_case"
    display_name = "Edge Case Module"
    category = TestCategory.EDGE_CASE

    async def run(self) -> None:
        spec = self.context.endpoints.create_payment
        # Resolved ONCE, here -- see negative.py's identical comment: every
        # case below spreads this template and overrides only the ONE
        # field it's deliberately testing, always after this resolution,
        # so the deliberate value always wins.
        base_payload = self.resolve_payload({
            "amount": 10.00,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-edge@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
        })

        await self._case_price_overflow(spec, base_payload)
        await self._case_price_precision(spec, base_payload)
        await self._case_unicode_parameters(spec, base_payload)
        await self._case_long_string_field(spec, base_payload)
        await self._case_concurrent_checkout_requests(spec, base_payload)
        await self._case_webhook_replay()

    # -- Overflow / precision -------------------------------------------------

    async def _case_price_overflow(self, spec, base_payload: dict) -> None:
        huge_amount = 999999999999999.99  # far beyond any realistic price; probes integer/float overflow handling

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code is not None and resp.status_code >= 500:
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - an oversized amount crashed the server instead of being validated."
            if resp.status_code is not None and 400 <= resp.status_code < 500:
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected as out of range."
            if resp.status_code in (200, 201):
                recorded = resp.body.get("amount") if isinstance(resp.body, dict) else None
                try:
                    matches = recorded is not None and abs(float(recorded) - huge_amount) < 0.01
                except (TypeError, ValueError):
                    matches = False
                if matches:
                    return ResultStatus.WARNING, f"HTTP {resp.status_code} - accepted and recorded correctly ({recorded}); confirm this amount is actually chargeable at your gateway."
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - accepted, but the recorded amount ({recorded}) does not match what was submitted; possible overflow/precision loss."
            return ResultStatus.WARNING, f"HTTP {resp.status_code} - unexpected response to an oversized amount."

        await self.execute_case(
            test_case_id="EDGE-001",
            name="Very large price value (overflow)",
            description=f"Submits an extreme amount ({huge_amount}) to probe integer/float overflow handling.",
            method=spec.method,
            path=spec.path,
            input_parameters={**base_payload, "amount": huge_amount},
            expected="HTTP 4xx rejecting the amount as out of range, OR HTTP 2xx with the exact amount recorded unchanged.",
            evaluate=evaluate,
            recommendation="Enforce a maximum chargeable amount server-side and validate it before any numeric processing that could overflow or lose precision.",
        )

    async def _case_price_precision(self, spec, base_payload: dict) -> None:
        payload = {**base_payload, "amount": 0.001}  # sub-cent

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code is not None and resp.status_code >= 500:
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - sub-cent amount crashed the server."
            if resp.status_code is not None and 400 <= resp.status_code < 500:
                return ResultStatus.PASS, f"HTTP {resp.status_code} - sub-cent amount correctly rejected (most gateways operate in whole cents)."
            if resp.status_code in (200, 201):
                return ResultStatus.WARNING, f"HTTP {resp.status_code} - sub-cent amount was accepted; confirm your gateway can actually settle this, most cannot."
            return ResultStatus.WARNING, f"HTTP {resp.status_code} - unexpected response to a sub-cent amount."

        await self.execute_case(
            test_case_id="EDGE-002",
            name="Sub-cent price precision",
            description="Submits amount=0.001 (a tenth of a cent) to probe rounding/precision handling.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 4xx rejecting an amount below the smallest chargeable unit, or clearly documented rounding behavior.",
            evaluate=evaluate,
            recommendation="Validate amounts to the currency's minor unit (e.g. cents for USD) server-side; most card networks cannot settle fractional-cent charges.",
        )

    # -- Unicode / oversized fields --------------------------------------------

    async def _case_unicode_parameters(self, spec, base_payload: dict) -> None:
        unicode_note = "\u00dcnic\u00f8de T\u00e9st \U0001F600 \u4e2d\u6587 \u0645\u062b\u0627\u0644"  # accented + emoji + CJK + Arabic
        payload = {**base_payload, "metadata": {"note": unicode_note}}

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code is not None and resp.status_code >= 500:
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - unicode input crashed the server."
            if resp.status_code in (200, 201, 400, 422):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - unicode input handled without a server error."
            return ResultStatus.WARNING, f"HTTP {resp.status_code} - unexpected response to unicode input."

        await self.execute_case(
            test_case_id="EDGE-003",
            name="Unicode in parameters",
            description="Submits unicode (accented characters, CJK, Arabic, emoji) in a metadata field and expects it handled without a server error.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 2xx (accepted and stored correctly) or a clean 4xx validation error - never a 5xx.",
            evaluate=evaluate,
            recommendation="Ensure all text fields and the database layer are UTF-8 end-to-end; a 5xx here usually indicates an encoding assumption breaking somewhere in the stack.",
        )

    async def _case_long_string_field(self, spec, base_payload: dict) -> None:
        long_value = "A" * 10000
        payload = {**base_payload, "metadata": {"note": long_value}}

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code is not None and resp.status_code >= 500:
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - an oversized field crashed the server instead of being validated/rejected."
            if resp.status_code in (200, 201, 400, 413, 422):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - oversized field handled without a server error."
            return ResultStatus.WARNING, f"HTTP {resp.status_code} - unexpected response to an oversized field."

        await self.execute_case(
            test_case_id="EDGE-004",
            name="Long string in a metadata field",
            description=f"Submits a {len(long_value)}-character value in a free-text field and expects graceful handling.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 2xx (accepted, possibly truncated per documented limits) or HTTP 400/413/422 - never a 5xx or a hang.",
            evaluate=evaluate,
            recommendation="Enforce and document a maximum field length server-side; reject oversized input with 400/413 rather than truncating silently or erroring.",
        )

    # -- Race condition ---------------------------------------------------------

    async def _case_concurrent_checkout_requests(self, spec, base_payload: dict) -> None:
        concurrency = 5
        payload = {**base_payload, "amount": 12.34, "metadata": {"qa_race_test": "true"}}

        started = datetime.now(timezone.utc)
        responses = await asyncio.gather(
            *[self.context.http.request(spec.method, spec.path, json_body=payload) for _ in range(concurrency)]
        )
        finished = datetime.now(timezone.utc)
        response_evidences = [resp for _, resp in responses]

        successes = [r for r in response_evidences if r.error is None and r.status_code in (200, 201)]
        server_errors = [r for r in response_evidences if r.error is None and r.status_code is not None and r.status_code >= 500]
        transport_errors = [r for r in response_evidences if r.error is not None]

        success_ids: set = set()
        for r in successes:
            if isinstance(r.body, dict):
                success_ids.add(r.body.get("id") or r.body.get("paymentId") or r.body.get("payment_id"))

        if server_errors or transport_errors:
            status = ResultStatus.FAIL
            actual = (
                f"{len(successes)}/{concurrency} succeeded, {len(server_errors)} server error(s), "
                f"{len(transport_errors)} transport error(s) under concurrent load."
            )
            recommendation = "The endpoint errored under concurrent load - investigate for unhandled exceptions (e.g. DB constraint races) before addressing idempotency."
        elif len(successes) <= 1:
            status = ResultStatus.PASS
            actual = f"{len(successes)}/{concurrency} identical concurrent requests succeeded - duplicate submissions were rejected or serialized."
            recommendation = None
        elif len(success_ids) == 1:
            status = ResultStatus.PASS
            actual = f"{len(successes)}/{concurrency} requests returned HTTP 2xx but all resolved to the same payment id - idempotent handling confirmed."
            recommendation = None
        else:
            status = ResultStatus.WARNING
            actual = (
                f"{len(successes)}/{concurrency} identical concurrent requests each succeeded as SEPARATE "
                f"payments ({len(success_ids)} distinct ids). Confirm this is intentional (not a double-charge risk)."
            )
            recommendation = (
                "Require an idempotency key on payment creation (hash of cart/session, or client-generated UUID) "
                "and reject/dedupe repeated requests sharing the same key within a short window."
            )

        await self.emit(
            TestResult(
                test_case_id="EDGE-005",
                category=self.category,
                name="Concurrent identical checkout requests (race condition)",
                description=f"Fires {concurrency} identical payment requests simultaneously (no idempotency key) and checks whether the system prevents duplicate processing.",
                input_parameters=payload,
                expected="At most one request succeeds, or all successes resolve to the same payment id (idempotent handling).",
                actual=actual,
                status=status,
                request=RequestEvidence(method=spec.method, url=f"{self.context.base_url}{spec.path}", headers={}, body=payload),
                response=ResponseEvidence(
                    status_code=None,
                    body={"responses": [{"status_code": r.status_code, "error": r.error} for r in response_evidences]},
                    elapsed_ms=(finished - started).total_seconds() * 1000,
                ),
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- Webhook replay -----------------------------------------------------------

    async def _case_webhook_replay(self) -> None:
        spec = self.context.endpoints.webhook_test
        event_id = f"evt_qa_replay_{uuid.uuid4().hex[:12]}"
        payload = {
            "id": event_id,
            "type": "payment.succeeded",
            "data": {"amount": 19.99, "currency": "USD", "productId": "prod_standard_plan"},
        }

        started = datetime.now(timezone.utc)
        _, resp1 = await self.context.http.request(spec.method, spec.path, json_body=payload)
        req2, resp2 = await self.context.http.request(spec.method, spec.path, json_body=payload)
        finished = datetime.now(timezone.utc)

        duplicate_flag_keys = ("duplicate", "already_processed", "idempotent_replay")

        if resp1.error is not None or resp2.error is not None:
            status = ResultStatus.ERROR
            actual = f"Transport error(s): first={resp1.error}, second={resp2.error}"
            recommendation = None
        elif resp1.status_code not in (200, 201, 202) or resp2.status_code not in (200, 201, 202):
            status = ResultStatus.WARNING
            actual = (
                f"First delivery HTTP {resp1.status_code}, replay HTTP {resp2.status_code} - one or both were "
                "not acknowledged with 2xx (webhook senders typically expect acks even for duplicates, to avoid "
                "endless retries)."
            )
            recommendation = "Acknowledge every webhook delivery attempt with 2xx once received, even if it turns out to be a duplicate; do the dedupe check internally, not via the HTTP status."
        elif isinstance(resp2.body, dict) and any(str(resp2.body.get(k, "")).lower() in ("true", "duplicate", "already_processed") for k in duplicate_flag_keys):
            status = ResultStatus.PASS
            actual = f"Replay acknowledged (HTTP {resp2.status_code}) and explicitly flagged as a duplicate in the response body."
            recommendation = None
        else:
            status = ResultStatus.WARNING
            actual = (
                f"Both deliveries returned HTTP 2xx (first={resp1.status_code}, replay={resp2.status_code}) with "
                "no explicit duplicate indicator in the response. Could not confirm from the HTTP response alone "
                "whether the replay was deduplicated server-side."
            )
            recommendation = (
                "Track processed webhook event ids (or a hash of the payload) and short-circuit any repeat "
                "delivery before it triggers side effects like activating a subscription a second time. Verify "
                "manually that this replay produced no duplicate side effect."
            )

        await self.emit(
            TestResult(
                test_case_id="EDGE-006",
                category=self.category,
                name="Webhook replay is handled idempotently",
                description=f"Sends the same webhook event ({event_id}) twice in a row and checks whether the duplicate delivery is safely ignored.",
                input_parameters=payload,
                expected="Both deliveries return HTTP 2xx; the replay is either explicitly flagged as a duplicate or otherwise produces no additional side effect.",
                actual=actual,
                status=status,
                request=req2,
                response=resp2,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )
