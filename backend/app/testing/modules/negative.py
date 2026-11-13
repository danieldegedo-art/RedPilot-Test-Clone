"""Negative Test Module (Parameter Validation).

Verifies invalid parameters are properly rejected: zero/negative price,
minimum valid price accepted, invalid productId, expired session token,
malformed JSON, missing required parameters.
"""
from __future__ import annotations

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory, TestScope
from app.testing.models import ResponseEvidence


def _is_client_error(resp: ResponseEvidence) -> bool:
    return resp.status_code is not None and 400 <= resp.status_code < 500


class NegativeTestModule(BaseTestModule):
    module_id = "negative"
    display_name = "Negative Test Module (Parameter Validation)"
    category = TestCategory.NEGATIVE

    async def run(self) -> None:
        spec = self.context.endpoints.create_payment
        # Resolved ONCE, here, against Recon's discovered values -- every
        # case below spreads this template and then overrides the ONE
        # field it's deliberately testing (amount=0, a bad productId, ...).
        # Since that override always comes after the spread, it always
        # wins regardless of what real value resolution put in the
        # template -- resolving later, per-case, would risk clobbering the
        # deliberate value back to something valid. See base.py.
        base_payload = self.resolve_payload({
            "amount": 25.00,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-negative@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
        })

        # Price validation is the highest-value negative test -- always run,
        # even at Smoke scope.
        await self._case_zero_price(spec, base_payload)
        await self._case_negative_price(spec, base_payload)
        await self._case_minimum_valid_price(spec, base_payload)

        if self.context.scope == TestScope.SMOKE:
            return

        await self._case_invalid_product_id(spec, base_payload)
        await self._case_expired_session_token(spec, base_payload)
        await self._case_malformed_json(spec)
        await self._case_missing_required_params(spec, base_payload)

    async def _case_zero_price(self, spec, base_payload: dict) -> None:
        payload = {**base_payload, "amount": 0}

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if _is_client_error(resp):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - zero-amount payment was NOT rejected"

        await self.execute_case(
            test_case_id="NEG-001",
            name="Zero price is rejected",
            description="Submits a payment with amount=0 and expects the API to reject it as an invalid amount.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 4xx with a validation error referencing the amount field.",
            evaluate=evaluate,
            recommendation="Add server-side validation to reject amount <= 0 before reaching the payment gateway. Never rely on client-side validation alone.",
        )

    async def _case_negative_price(self, spec, base_payload: dict) -> None:
        payload = {**base_payload, "amount": -5}

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if _is_client_error(resp):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - negative-amount payment was NOT rejected"

        await self.execute_case(
            test_case_id="NEG-002",
            name="Negative price is rejected",
            description="Submits a payment with amount=-5 and expects the API to reject it.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 4xx with a validation error referencing the amount field.",
            evaluate=evaluate,
            recommendation="Reject negative amounts server-side. A negative amount reaching the gateway could result in a credit to the payer instead of a charge.",
        )

    async def _case_minimum_valid_price(self, spec, base_payload: dict) -> None:
        payload = {**base_payload, "amount": 0.01}

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code in (200, 201):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - accepted"
            if _is_client_error(resp):
                return ResultStatus.WARNING, f"HTTP {resp.status_code} - minimum valid amount was rejected; confirm your gateway's real minimum"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - minimum valid amount was not accepted"

        await self.execute_case(
            test_case_id="NEG-003",
            name="Minimum valid price (0.01) is accepted",
            description="Submits a payment with amount=0.01 and expects the API to accept it as the minimum valid charge.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 200/201 - payment accepted.",
            evaluate=evaluate,
            recommendation="Confirm the gateway's minimum chargeable amount (some processors require a higher floor, e.g. $0.50) and align server-side validation with it.",
        )

    async def _case_invalid_product_id(self, spec, base_payload: dict) -> None:
        payload = {**base_payload, "productId": "prod_does_not_exist_xyz123"}

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code in (400, 404, 422):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - invalid productId was not rejected"

        await self.execute_case(
            test_case_id="NEG-004",
            name="Invalid productId is rejected",
            description="Submits a payment referencing a productId that does not exist and expects a 400/404/422.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 400/404/422 with an error indicating the product was not found.",
            evaluate=evaluate,
            recommendation="Validate productId against the product catalog before attempting to charge; do not silently fall back to a default price.",
        )

    async def _case_expired_session_token(self, spec, base_payload: dict) -> None:
        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code in (401, 403):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected"
            if _is_client_error(resp):
                return ResultStatus.WARNING, f"HTTP {resp.status_code} - request was rejected but not with 401/403"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - expired token was NOT rejected"

        await self.execute_case(
            test_case_id="NEG-005",
            name="Expired session token is rejected",
            description="Submits a payment using a synthetic, clearly-expired bearer token and expects a 401/403.",
            method=spec.method,
            path=spec.path,
            input_parameters=base_payload,
            headers={"Authorization": "Bearer QA-TEST-EXPIRED-TOKEN-1970-01-01"},
            expected="HTTP 401 Unauthorized (or 403 Forbidden).",
            evaluate=evaluate,
            recommendation="Return 401 (not 403) for expired/invalid credentials, and verify token expiry server-side on every authenticated request, not only at issuance.",
        )

    async def _case_malformed_json(self, spec) -> None:
        broken_json = b'{"amount": 25.00, "currency": "USD", "productId": "prod_standard_plan"'  # missing closing brace

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code == 400:
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected"
            if _is_client_error(resp):
                return ResultStatus.WARNING, f"HTTP {resp.status_code} - rejected, but not with the expected 400"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - malformed JSON was NOT rejected"

        await self.execute_case(
            test_case_id="NEG-006",
            name="Malformed JSON body is rejected",
            description="Submits a request body with invalid JSON syntax (missing closing brace) and expects HTTP 400.",
            method=spec.method,
            path=spec.path,
            input_parameters={"note": "malformed JSON payload - see request evidence for the exact raw body sent"},
            raw_body=broken_json,
            expected="HTTP 400 Bad Request with a JSON parse error.",
            evaluate=evaluate,
            recommendation="Ensure the request body parser returns 400 (not 500) on invalid JSON, and does not leak a stack trace or internal file paths in the response body.",
        )

    async def _case_missing_required_params(self, spec, base_payload: dict) -> None:
        payload = {k: v for k, v in base_payload.items() if k != "productId"}

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if _is_client_error(resp):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected"
            return ResultStatus.FAIL, f"HTTP {resp.status_code} - missing-field request was not rejected"

        await self.execute_case(
            test_case_id="NEG-007",
            name="Missing required parameter is rejected",
            description="Omits the required 'productId' field and expects a 400 validation error naming the missing field.",
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 400 with an error identifying 'productId' as missing.",
            evaluate=evaluate,
            recommendation="Return 400 with a field-level error for every required parameter; avoid a generic 500 on missing fields.",
        )
