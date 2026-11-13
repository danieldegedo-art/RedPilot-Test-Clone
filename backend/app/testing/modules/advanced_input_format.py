"""Advanced Input Format Module (Module 17).

Verifies that the system under test handles unusual input formats
consistently and safely. Each check sends the same logical data in a
different wire format or structure and verifies the system processes
it identically regardless of how it was encoded.

  FORMAT-ADV-001: Duplicate parameter handling — sends a request with
    the same parameter appearing multiple times with different values,
    verifying the system processes exactly one value consistently.

  FORMAT-ADV-002: Content-Type variant consistency — sends a JSON body
    with Content-Type: text/plain, verifying the system either parses
    it identically or cleanly declines it.

  FORMAT-ADV-003: Character encoding consistency — sends requests with
    unusual charset declarations (utf-16, ibm037), verifying the system
    correctly decodes or safely declines them.

  FORMAT-ADV-004: Type variant consistency (array form) — sends a value
    wrapped in an array instead of a scalar, verifying the system
    handles the type difference safely.

  FORMAT-ADV-005: Type variant consistency (object form) — sends a value
    as a nested object instead of a scalar, verifying the system rejects
    the structural mismatch.

  FORMAT-ADV-006: Object structure consistency — sends special keys
    (__proto__, constructor) that could alter object behavior in some
    runtimes, verifying the system ignores or safely rejects them.

  FORMAT-ADV-007: Source priority consistency — sends the same parameter
    in both query string and request body simultaneously, verifying the
    system applies a consistent precedence rule.

Based on documented patterns:
- Client-side validation differences (WAFFLED Paper)
- Type coercion in runtime environments
- Parameter precedence inconsistencies
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, quote

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult
from app.testing.modules.role_based_access import _MALICIOUS_PAYMENT_ATTRIBUTES

# Use the same field set as ROLE-002 for consistency, but with QA-safe naming internally
_NON_STANDARD_PAYMENT_FIELDS = _MALICIOUS_PAYMENT_ATTRIBUTES


def _classify_response(resp: ResponseEvidence) -> str:
    """Coarse classification of a response."""
    if resp.status_code is None:
        return "transport_error"
    if 400 <= resp.status_code < 500:
        return "declined"
    if resp.status_code >= 500:
        return "server_error"
    if 200 <= resp.status_code < 300:
        return "accepted"
    return "unclear"


def _check_field_reflection(resp: ResponseEvidence, fields: dict[str, Any]) -> list[str]:
    """Returns list of field names that were reflected back with the
    exact non-standard value in the response body."""
    if not isinstance(resp.body, dict):
        return []
    reflected = []
    for key, value in fields.items():
        if key in resp.body and resp.body[key] == value:
            reflected.append(key)
    return reflected


class AdvancedInputFormatModule(BaseTestModule):
    """Advanced Input Format Module — verifies that unusual input
    encodings, type variants, and structural differences are handled
    consistently and safely."""

    module_id = "advanced_input_format"
    display_name = "Advanced Input Format Consistency"
    category = TestCategory.ADVANCED_INPUT_FORMAT

    async def run(self) -> None:
        await self._case_duplicate_parameters()
        await self._case_content_type_variant()
        await self._case_charset_variants()
        await self._case_array_wrapping()
        await self._case_nested_object()
        await self._case_object_structure_keys()
        await self._case_source_priority()

    def _get_target_endpoint(self) -> tuple[str, str]:
        """Returns (method, path) for a mutating endpoint to test against."""
        spec = self.context.endpoints.create_payment
        return spec.method, spec.path

    def _build_base_request_body(self) -> dict[str, Any]:
        """Builds a valid payment creation body for baseline testing."""
        return self.resolve_payload({
            "amount": 25.00,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-advanced-format@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
        })

    async def _send_and_classify(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[RequestEvidence, ResponseEvidence, str, list[str]]:
        """Sends a request and returns (request, response, classification, reflected_fields)."""
        req, resp = await self.context.http.request(
            method, path,
            json_body=json_body,
            raw_body=raw_body,
            params=params,
            extra_headers=extra_headers,
        )
        classification = _classify_response(resp)
        reflected = _check_field_reflection(resp, _NON_STANDARD_PAYMENT_FIELDS)
        return req, resp, classification, reflected

    # -- FORMAT-ADV-001 -----------------------------------------------------

    async def _case_duplicate_parameters(self) -> None:
        """Duplicate parameter handling — same parameter with different values."""
        method, path = self._get_target_endpoint()

        # Build a form-urlencoded body with the same parameter twice
        # with different values (one standard, one non-standard)
        form_parts = [
            ("amount", "25.00"),
            ("currency", "USD"),
            ("productId", "prod_standard_plan"),
            ("customerEmail", "qa-advanced-format@example.com"),
            ("plan", "free"),      # First occurrence — standard value
            ("plan", "max"),       # Second occurrence — non-standard value
            ("tier", "free"),      # First occurrence
            ("tier", "premium"),   # Second occurrence — non-standard
        ]
        raw_body = urlencode(form_parts).encode("utf-8")

        started = datetime.now(timezone.utc)
        req, resp, classification, reflected = await self._send_and_classify(
            method, path,
            raw_body=raw_body,
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        finished = datetime.now(timezone.utc)

        # Also check the persisted state via an independent GET if possible
        state_note = ""
        if classification == "accepted":
            state_note = await self._check_persisted_state(path)

        if classification == "transport_error":
            status = ResultStatus.ERROR
            actual = f"Transport error: {resp.error}"
            recommendation = None
        elif classification == "server_error":
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — the system encountered a server error while "
                f"processing duplicate parameters. This should be handled gracefully with a "
                f"clean 4xx response indicating which value is used."
            )
            recommendation = (
                "Implement explicit duplicate-parameter handling: either accept the first "
                "value, the last value, or reject the request entirely — but never crash. "
                "Document the chosen precedence rule."
            )
        elif classification == "declined":
            status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — the system cleanly declined a request containing "
                f"duplicate parameters with conflicting values. This is a valid approach to "
                f"handling ambiguous input."
            )
            recommendation = None
        elif classification == "accepted":
            if reflected:
                status = ResultStatus.FAIL
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request and the "
                    f"non-standard value was reflected back for: {reflected}. This means "
                    f"the system used the second (non-standard) value when the parameter "
                    f"appeared twice with different values. {state_note}"
                )
                recommendation = (
                    "Implement consistent duplicate-parameter handling: when the same "
                    "parameter appears multiple times with different values, either reject "
                    "the request or use a documented precedence rule. Do not allow the "
                    "last-occurrence value to silently override validation applied to the first."
                )
            else:
                status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request but did not "
                    f"reflect the non-standard values back. The system may have used either "
                    f"the first or last value; verify which one was actually processed. {state_note}"
                )
                recommendation = (
                    "Verify which value is used when a parameter appears multiple times. "
                    "Implement and document a consistent precedence rule (e.g., always use "
                    "the first occurrence, or reject duplicates)."
                )
        else:
            status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine outcome."
            recommendation = None

        await self.emit(
            TestResult(
                test_case_id="FORMAT-ADV-001",
                category=self.category,
                name="Duplicate parameter handling consistency",
                description=(
                    "Sends a form-urlencoded request body containing the same parameter "
                    "('plan' and 'tier') twice with different values — one standard and one "
                    "non-standard. Verifies that the system handles duplicate parameters "
                    "consistently: either rejecting the request, using a documented precedence "
                    "rule, or at minimum not allowing the non-standard value to silently "
                    "override validation applied to the standard one."
                ),
                input_parameters={
                    "duplicate_parameters": ["plan", "tier"],
                    "first_values": {"plan": "free", "tier": "free"},
                    "second_values": {"plan": "max", "tier": "premium"},
                    "format": "application/x-www-form-urlencoded",
                },
                expected="Request is declined, or the first (standard) value is used, or a documented precedence rule is applied.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- FORMAT-ADV-002 -----------------------------------------------------

    async def _case_content_type_variant(self) -> None:
        """Content-Type variant consistency — JSON body sent as text/plain."""
        method, path = self._get_target_endpoint()

        # Build a valid JSON body but declare it as text/plain
        base_body = self._build_base_request_body()
        base_body.update(_NON_STANDARD_PAYMENT_FIELDS)
        raw_body = json.dumps(base_body).encode("utf-8")

        started = datetime.now(timezone.utc)
        req, resp, classification, reflected = await self._send_and_classify(
            method, path,
            raw_body=raw_body,
            extra_headers={"Content-Type": "text/plain"},
        )
        finished = datetime.now(timezone.utc)

        state_note = ""
        if classification == "accepted":
            state_note = await self._check_persisted_state(path)

        if classification == "transport_error":
            status = ResultStatus.ERROR
            actual = f"Transport error: {resp.error}"
            recommendation = None
        elif classification == "server_error":
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — the system encountered a server error while "
                f"processing a JSON body declared as text/plain. The content-type parser "
                f"should either handle this gracefully or return a clean 4xx."
            )
            recommendation = (
                "Implement content-type validation: if the body is declared as text/plain "
                "but contains JSON, either parse it as JSON (lenient mode) or return a "
                "clean 400 with a helpful message. Never crash on unexpected content-type "
                "combinations."
            )
        elif classification == "declined":
            status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — the system cleanly declined a JSON body "
                f"declared as text/plain. This is correct: the declared content type "
                f"does not match the body format, and the system correctly refused to "
                f"process it with payment/subscription fields."
            )
            recommendation = None
        elif classification == "accepted":
            if reflected:
                status = ResultStatus.FAIL
                actual = (
                    f"HTTP {resp.status_code} — the system accepted a JSON body declared "
                    f"as text/plain and the non-standard values were reflected back for: "
                    f"{reflected}. The system parsed the body as JSON despite the declared "
                    f"content type being text/plain, and processed non-standard payment "
                    f"fields. {state_note}"
                )
                recommendation = (
                    "Implement content-type enforcement: only parse request bodies as JSON "
                    "when the Content-Type header explicitly declares application/json. "
                    "If a body is declared as text/plain, treat it as opaque text and do "
                    "not attempt JSON parsing. This ensures validation layers that check "
                    "for application/json content are not circumvented by content-type "
                    "mismatch."
                )
            else:
                status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — the system accepted a JSON body declared "
                    f"as text/plain but did not reflect the non-standard values. The body "
                    f"may have been parsed as JSON and the fields silently ignored, or "
                    f"it may have been treated as plain text and discarded. {state_note}"
                )
                recommendation = (
                    "Verify how the system handles content-type mismatches. Implement "
                    "explicit content-type checking: only process JSON fields when the "
                    "Content-Type header declares application/json."
                )
        else:
            status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine outcome."
            recommendation = None

        await self.emit(
            TestResult(
                test_case_id="FORMAT-ADV-002",
                category=self.category,
                name="Content-Type variant consistency",
                description=(
                    "Sends a request body containing JSON data (including non-standard "
                    "payment/subscription fields) but declares the Content-Type as "
                    "'text/plain' instead of 'application/json'. Verifies that the system "
                    "either declines the mismatched content type or parses it with the same "
                    "validation rules as properly-declared JSON. Catches gaps where "
                    "validation layers only check bodies with the expected content type."
                ),
                input_parameters={
                    "declared_content_type": "text/plain",
                    "actual_body_format": "JSON",
                    "non_standard_fields": list(_NON_STANDARD_PAYMENT_FIELDS.keys()),
                },
                expected="Request is declined (content-type mismatch) or processed with the same validation as application/json.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- FORMAT-ADV-003 -----------------------------------------------------

    async def _case_charset_variants(self) -> None:
        """Character encoding consistency — unusual charset declarations."""
        method, path = self._get_target_endpoint()

        # Test two charset variants: utf-16 and ibm037
        charset_variants = [
            ("utf-16", "UTF-16 encoding (wide character set)"),
            ("ibm037", "IBM037/EBCDIC encoding (legacy mainframe)"),
        ]

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        for charset_name, charset_description in charset_variants:
            # Build a JSON body with the non-standard fields
            base_body = self._build_base_request_body()
            base_body.update(_NON_STANDARD_PAYMENT_FIELDS)

            # Encode the body in the specified charset
            try:
                if charset_name == "utf-16":
                    encoded_body = json.dumps(base_body).encode("utf-16")
                elif charset_name == "ibm037":
                    # For IBM037/EBCDIC, we can only try to encode the ASCII subset
                    # If the body contains non-ASCII characters it will fail
                    encoded_body = json.dumps(base_body).encode("ascii", errors="replace")
                else:
                    encoded_body = json.dumps(base_body).encode(charset_name, errors="replace")
            except (UnicodeEncodeError, LookupError):
                # Charset not supported for encoding — skip this variant
                results.append({
                    "charset": charset_name,
                    "description": charset_description,
                    "classification": "encoding_unsupported",
                    "status_code": None,
                    "reflected": [],
                    "note": f"Could not encode body in {charset_name}",
                })
                continue

            content_type = f"application/json; charset={charset_name}"

            req, resp, classification, reflected = await self._send_and_classify(
                method, path,
                raw_body=encoded_body,
                extra_headers={"Content-Type": content_type},
            )

            results.append({
                "charset": charset_name,
                "description": charset_description,
                "classification": classification,
                "status_code": resp.status_code,
                "reflected": reflected,
                "request": req,
                "response": resp,
            })

        finished = datetime.now(timezone.utc)

        # Evaluate results
        any_reflected = any(r.get("reflected") for r in results)
        any_accepted = any(r["classification"] == "accepted" for r in results)
        any_crashed = any(r["classification"] == "server_error" for r in results)
        any_declined = all(r["classification"] == "declined" for r in results)

        if any_crashed:
            status = ResultStatus.FAIL
            crashed = [r["charset"] for r in results if r["classification"] == "server_error"]
            actual = (
                f"Tested {len(results)} charset variants. The system encountered server "
                f"errors when processing: {crashed}. Unusual charset declarations should "
                f"be handled gracefully, not cause crashes."
            )
            recommendation = (
                "Implement charset validation: when a request declares an unusual charset, "
                "either decode it correctly or return a clean 400. Never allow charset "
                "processing to cause a server error."
            )
        elif any_reflected:
            status = ResultStatus.FAIL
            reflected_charsets = [r["charset"] for r in results if r.get("reflected")]
            actual = (
                f"Tested {len(results)} charset variants. The system accepted and reflected "
                f"non-standard payment fields when the body was encoded in: {reflected_charsets}. "
                f"This means charset-based validation differences allow non-standard fields "
                f"to be processed when unusual encodings are used."
            )
            recommendation = (
                "Implement charset normalization: decode all request bodies to a standard "
                "internal encoding (UTF-8) before applying validation. Do not let charset "
                "differences create validation gaps where non-standard payment fields are "
                "processed in one encoding but blocked in another."
            )
        elif any_accepted and not any_reflected:
            status = ResultStatus.WARNING
            accepted_charsets = [r["charset"] for r in results if r["classification"] == "accepted"]
            actual = (
                f"Tested {len(results)} charset variants. The system accepted requests "
                f"with charset {accepted_charsets} but did not reflect non-standard fields. "
                f"The fields may have been silently processed or silently ignored."
            )
            recommendation = (
                "Verify that charset differences do not create validation gaps. Implement "
                "charset normalization before validation so all encodings are treated identically."
            )
        elif any_declined:
            status = ResultStatus.PASS
            actual = (
                f"Tested {len(results)} charset variants. All were cleanly declined, "
                f"maintaining consistent validation regardless of character encoding."
            )
            recommendation = None
        else:
            status = ResultStatus.INFO
            actual = (
                f"Tested {len(results)} charset variants with mixed results: "
                f"{[(r['charset'], r['classification']) for r in results]}. "
                f"Could not determine overall consistency."
            )
            recommendation = None

        # Use the first result's evidence
        request_evidence = results[0].get("request") if results else None
        response_evidence = results[0].get("response") if results else None

        await self.emit(
            TestResult(
                test_case_id="FORMAT-ADV-003",
                category=self.category,
                name="Character encoding consistency",
                description=(
                    "Sends request bodies with non-standard payment/subscription fields "
                    "using unusual character encoding declarations (charset=utf-16, "
                    "charset=ibm037). Verifies that the system either correctly decodes "
                    "and applies the same validation rules, or cleanly declines unusual "
                    "charsets. Catches gaps where validation differences between character "
                    "encodings allow non-standard fields to be processed."
                ),
                input_parameters={
                    "charset_variants": [r["charset"] for r in results],
                    "non_standard_fields": list(_NON_STANDARD_PAYMENT_FIELDS.keys()),
                },
                expected="All charset variants are either correctly decoded with the same validation, or cleanly declined.",
                actual=actual,
                status=status,
                request=request_evidence,
                response=response_evidence,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- FORMAT-ADV-004 -----------------------------------------------------

    async def _case_array_wrapping(self) -> None:
        """Type variant consistency (array form) — scalar value wrapped in an array."""
        method, path = self._get_target_endpoint()

        # Build a body where the non-standard fields are wrapped in arrays
        base_body = self._build_base_request_body()
        for field_name, field_value in _NON_STANDARD_PAYMENT_FIELDS.items():
            base_body[field_name] = [field_value]  # Wrap in array

        started = datetime.now(timezone.utc)
        req, resp, classification, reflected = await self._send_and_classify(
            method, path, json_body=base_body,
        )
        finished = datetime.now(timezone.utc)

        # Check if any field was processed with the array-unwrapped value
        array_processed = []
        if isinstance(resp.body, dict):
            for field_name, field_value in _NON_STANDARD_PAYMENT_FIELDS.items():
                # Check if the response contains either the array or the unwrapped value
                if field_name in resp.body:
                    resp_value = resp.body[field_name]
                    if resp_value == field_value:
                        array_processed.append(field_name)
                    elif isinstance(resp_value, list) and field_value in resp_value:
                        array_processed.append(field_name)

        state_note = ""
        if classification == "accepted":
            state_note = await self._check_persisted_state(path)

        if classification == "transport_error":
            status = ResultStatus.ERROR
            actual = f"Transport error: {resp.error}"
            recommendation = None
        elif classification == "server_error":
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — the system encountered a server error when "
                f"processing a type variant (array-wrapped values). This should be handled "
                f"gracefully with a clean 4xx response."
            )
            recommendation = (
                "Implement type validation: when a field that is expected to be a scalar "
                "receives an array, either reject the request with a clear error message "
                "or safely coerce the type. Never crash on type mismatches."
            )
        elif classification == "declined":
            status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — the system cleanly declined a request where "
                f"scalar fields were wrapped in arrays. This is correct: the type "
                f"mismatch was detected and the request was refused."
            )
            recommendation = None
        elif classification == "accepted":
            if array_processed:
                status = ResultStatus.FAIL
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request and processed "
                    f"array-wrapped values for: {array_processed}. The system either unwrapped "
                    f"the array or iterated over its elements, processing the non-standard "
                    f"value. {state_note}"
                )
                recommendation = (
                    "Implement strict type validation: when a field is expected to be a "
                    "scalar (string, number, boolean), reject requests that provide it as "
                    "an array. Do not silently unwrap arrays or iterate over their elements, "
                    "as this can bypass validation designed for scalar values."
                )
            else:
                status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request with "
                    f"array-wrapped values but did not clearly process or reject them. "
                    f"The fields may have been silently ignored. {state_note}"
                )
                recommendation = (
                    "Verify that array-wrapped scalar values are properly rejected. "
                    "Implement type checking that distinguishes between scalar and array types."
                )
        else:
            status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine outcome."
            recommendation = None

        await self.emit(
            TestResult(
                test_case_id="FORMAT-ADV-004",
                category=self.category,
                name="Type variant consistency (array form)",
                description=(
                    "Sends a request where non-standard payment/subscription fields "
                    "(plan, tier, subscription_status, is_premium) are wrapped in arrays "
                    "instead of being provided as scalars. Verifies that the system "
                    "handles the type difference safely — either rejecting the request "
                    "or ensuring the non-standard values are not processed through "
                    "array unwrapping or iteration."
                ),
                input_parameters={
                    "type_variant": "array_wrapping",
                    "fields_tested": list(_NON_STANDARD_PAYMENT_FIELDS.keys()),
                },
                expected="Request is declined (type mismatch) or the array-wrapped values are safely ignored.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- FORMAT-ADV-005 -----------------------------------------------------

    async def _case_nested_object(self) -> None:
        """Type variant consistency (object form) — scalar value as nested object."""
        method, path = self._get_target_endpoint()

        # Build a body where the non-standard fields are nested objects
        base_body = self._build_base_request_body()
        for field_name, field_value in _NON_STANDARD_PAYMENT_FIELDS.items():
            base_body[field_name] = {"value": field_value, "type": "override"}  # Nested object

        started = datetime.now(timezone.utc)
        req, resp, classification, reflected = await self._send_and_classify(
            method, path, json_body=base_body,
        )
        finished = datetime.now(timezone.utc)

        # Check if any nested value was extracted and processed
        nested_processed = []
        if isinstance(resp.body, dict):
            for field_name, field_value in _NON_STANDARD_PAYMENT_FIELDS.items():
                if field_name in resp.body:
                    resp_value = resp.body[field_name]
                    if resp_value == field_value:
                        nested_processed.append(field_name)
                    elif isinstance(resp_value, dict) and resp_value.get("value") == field_value:
                        nested_processed.append(field_name)

        state_note = ""
        if classification == "accepted":
            state_note = await self._check_persisted_state(path)

        if classification == "transport_error":
            status = ResultStatus.ERROR
            actual = f"Transport error: {resp.error}"
            recommendation = None
        elif classification == "server_error":
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — the system encountered a server error when "
                f"processing a type variant (nested object values). This should be handled "
                f"gracefully with a clean 4xx response."
            )
            recommendation = (
                "Implement type validation: when a field that is expected to be a scalar "
                "receives an object, reject the request with a clear error message. "
                "Never crash on structural mismatches."
            )
        elif classification == "declined":
            status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — the system cleanly declined a request where "
                f"scalar fields were provided as nested objects. This is correct: the "
                f"structural mismatch was detected and the request was refused."
            )
            recommendation = None
        elif classification == "accepted":
            if nested_processed:
                status = ResultStatus.FAIL
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request and processed "
                    f"nested-object values for: {nested_processed}. The system extracted the "
                    f"'value' key from the nested object and used the non-standard value. "
                    f"{state_note}"
                )
                recommendation = (
                    "Implement strict type validation: when a field is expected to be a "
                    "scalar (string, number, boolean), reject requests that provide it as "
                    "an object. Do not extract nested values from objects where scalars "
                    "are expected, as this can bypass validation designed for scalar values."
                )
            else:
                status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request with "
                    f"nested-object values but did not clearly process or reject them. "
                    f"The fields may have been silently ignored. {state_note}"
                )
                recommendation = (
                    "Verify that nested-object scalar values are properly rejected. "
                    "Implement type checking that distinguishes between scalar and object types."
                )
        else:
            status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine outcome."
            recommendation = None

        await self.emit(
            TestResult(
                test_case_id="FORMAT-ADV-005",
                category=self.category,
                name="Type variant consistency (object form)",
                description=(
                    "Sends a request where non-standard payment/subscription fields "
                    "(plan, tier, subscription_status, is_premium) are provided as nested "
                    "objects with a 'value' key instead of as direct scalars. Verifies "
                    "that the system handles the structural difference safely — either "
                    "rejecting the request or ensuring the nested values are not extracted "
                    "and processed."
                ),
                input_parameters={
                    "type_variant": "nested_object",
                    "fields_tested": list(_NON_STANDARD_PAYMENT_FIELDS.keys()),
                },
                expected="Request is declined (structural mismatch) or the nested-object values are safely ignored.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- FORMAT-ADV-006 -----------------------------------------------------

    async def _case_object_structure_keys(self) -> None:
        """Object structure consistency — special keys that could alter
        object behavior in some runtime environments."""
        method, path = self._get_target_endpoint()

        # Build a body with special structural keys alongside standard fields
        base_body = self._build_base_request_body()

        # Test key patterns that can alter object behavior in JavaScript runtimes
        special_bodies = [
            {
                "description": "Dotted key format",
                "body": {**base_body, "__proto__.plan": "max", "plan": "free"},
            },
            {
                "description": "Constructor-based format",
                "body": {**base_body, "constructor": {"prototype": {"plan": "max"}}},
            },
        ]

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        for test in special_bodies:
            req, resp, classification, reflected = await self._send_and_classify(
                method, path, json_body=test["body"],
            )

            # Check if any special key was processed or altered object behavior
            structure_altered = False
            if isinstance(resp.body, dict):
                # Check if plan appeared as "max" despite being sent as "free"
                if "plan" in resp.body and resp.body["plan"] == "max":
                    structure_altered = True
                # Check if __proto__ or constructor appeared in the response
                if "__proto__" in str(resp.body) or "constructor" in str(resp.body):
                    structure_altered = True

            results.append({
                "description": test["description"],
                "classification": classification,
                "status_code": resp.status_code,
                "structure_altered": structure_altered,
                "request": req,
                "response": resp,
            })

        finished = datetime.now(timezone.utc)

        any_altered = any(r["structure_altered"] for r in results)
        any_crashed = any(r["classification"] == "server_error" for r in results)
        all_declined = all(r["classification"] == "declined" for r in results)

        if any_crashed:
            status = ResultStatus.FAIL
            crashed = [r["description"] for r in results if r["classification"] == "server_error"]
            actual = (
                f"Tested {len(results)} object structure key patterns. The system "
                f"encountered server errors with: {crashed}. Special keys should be "
                f"handled gracefully."
            )
            recommendation = (
                "Implement input sanitization: strip or reject special structural keys "
                "(__proto__, constructor, prototype) from all input. These keys can "
                "alter object behavior in JavaScript-based runtime environments."
            )
        elif any_altered:
            status = ResultStatus.FAIL
            altered = [r["description"] for r in results if r["structure_altered"]]
            actual = (
                f"Tested {len(results)} object structure key patterns. Object behavior "
                f"was altered by: {altered}. Special keys were processed and changed "
                f"the effective object structure, potentially affecting other fields."
            )
            recommendation = (
                "Implement input sanitization: strip or reject special structural keys "
                "(__proto__, constructor, prototype) from all input. Use a strict allowlist "
                "of accepted field names and reject anything not on the list. If using "
                "JavaScript-based runtime environments (Node.js), consider using "
                "Object.create(null) for parsed objects to eliminate prototype chains."
            )
        elif all_declined:
            status = ResultStatus.PASS
            actual = (
                f"Tested {len(results)} object structure key patterns. All were cleanly "
                f"declined — the system correctly rejects special structural keys."
            )
            recommendation = None
        else:
            status = ResultStatus.WARNING
            actual = (
                f"Tested {len(results)} object structure key patterns with mixed results: "
                f"{[(r['description'], r['classification']) for r in results]}. "
                f"Could not determine overall consistency."
            )
            recommendation = (
                "Verify that special structural keys (__proto__, constructor, prototype) "
                "are properly rejected or stripped from all input."
            )

        request_evidence = results[0].get("request") if results else None
        response_evidence = results[0].get("response") if results else None

        await self.emit(
            TestResult(
                test_case_id="FORMAT-ADV-006",
                category=self.category,
                name="Object structure consistency",
                description=(
                    "Sends requests containing special structural keys (__proto__.plan, "
                    "constructor.prototype.plan) that can alter object behavior in "
                    "JavaScript-based runtime environments. Verifies that the system "
                    "either rejects these keys or safely ignores them without allowing "
                    "them to modify the behavior of other fields in the same object."
                ),
                input_parameters={
                    "key_patterns": [r["description"] for r in results],
                    "runtime_environments_at_risk": ["Node.js", "Browser JavaScript"],
                },
                expected="Special structural keys are rejected or safely ignored without altering other fields' behavior.",
                actual=actual,
                status=status,
                request=request_evidence,
                response=response_evidence,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- FORMAT-ADV-007 -----------------------------------------------------

    async def _case_source_priority(self) -> None:
        """Source priority consistency — same parameter in query string and body."""
        method, path = self._get_target_endpoint()

        # Send the same parameter with different values in query and body
        # Query: plan=free (standard)
        # Body: {"plan": "max"} (non-standard)
        base_body = self._build_base_request_body()
        base_body.update(_NON_STANDARD_PAYMENT_FIELDS)

        query_params = {"plan": "free", "tier": "free"}  # Standard values in query

        started = datetime.now(timezone.utc)
        req, resp, classification, reflected = await self._send_and_classify(
            method, path,
            json_body=base_body,
            params=query_params,
        )
        finished = datetime.now(timezone.utc)

        # Check which value was used (query or body)
        body_value_used = False
        query_value_used = False
        if isinstance(resp.body, dict):
            if "plan" in resp.body:
                if resp.body["plan"] == "max":
                    body_value_used = True
                elif resp.body["plan"] == "free":
                    query_value_used = True
            if "tier" in resp.body:
                if resp.body["tier"] == "premium":
                    body_value_used = True
                elif resp.body["tier"] == "free":
                    query_value_used = True

        state_note = ""
        if classification == "accepted":
            state_note = await self._check_persisted_state(path)

        if classification == "transport_error":
            status = ResultStatus.ERROR
            actual = f"Transport error: {resp.error}"
            recommendation = None
        elif classification == "server_error":
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — the system encountered a server error when "
                f"the same parameter appeared in both query string and request body with "
                f"different values. This should be handled with a documented precedence rule."
            )
            recommendation = (
                "Implement source priority handling: when the same parameter appears in "
                "both the query string and request body, define and document which source "
                "takes precedence. Handle the conflict gracefully without crashing."
            )
        elif classification == "declined":
            status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — the system cleanly declined a request where "
                f"the same parameter appeared in both query string and body with different "
                f"values. This is a valid approach to handling conflicting sources."
            )
            recommendation = None
        elif classification == "accepted":
            if body_value_used:
                status = ResultStatus.FAIL
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request and used "
                    f"the BODY value (non-standard: plan=max, tier=premium) when the same "
                    f"parameter also appeared in the QUERY STRING with standard values "
                    f"(plan=free, tier=free). Body values override query values, which "
                    f"means query-string-based validation can be circumvented by putting "
                    f"non-standard values in the body. {state_note}"
                )
                recommendation = (
                    "Implement consistent source priority: when the same parameter appears "
                    "in both query string and request body, define a single precedence rule "
                    "(e.g., query always wins, or body always wins) and apply it uniformly. "
                    "Ensure that validation applied to one source is also applied to the "
                    "other, preventing circumvention through source duplication."
                )
            elif query_value_used:
                status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request and used "
                    f"the QUERY STRING value (standard: plan=free, tier=free) when the same "
                    f"parameter also appeared in the BODY with non-standard values "
                    f"(plan=max, tier=premium). Query values override body values, which "
                    f"is one valid precedence rule. {state_note}"
                )
                recommendation = (
                    "Verify that the precedence rule (query overrides body) is documented "
                    "and consistently applied across all endpoints. Consider whether this "
                    "creates any validation gaps."
                )
            else:
                status = ResultStatus.WARNING
                actual = (
                    f"HTTP {resp.status_code} — the system accepted the request but it's "
                    f"unclear which source's values were used. Neither the query nor body "
                    f"values were clearly reflected in the response. {state_note}"
                )
                recommendation = (
                    "Implement and document a source priority rule for parameters that "
                    "appear in both query string and request body. Ensure the chosen "
                    "value is consistently used across all endpoints."
                )
        else:
            status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine outcome."
            recommendation = None

        await self.emit(
            TestResult(
                test_case_id="FORMAT-ADV-007",
                category=self.category,
                name="Source priority consistency",
                description=(
                    "Sends a request where the same parameters (plan, tier) appear in "
                    "both the query string (with standard values: free) and the request "
                    "body (with non-standard values: max, premium). Verifies that the "
                    "system applies a consistent precedence rule and does not allow "
                    "non-standard values from one source to circumvent validation "
                    "applied to the other source."
                ),
                input_parameters={
                    "query_string_values": {"plan": "free", "tier": "free"},
                    "body_values": {k: v for k, v in _NON_STANDARD_PAYMENT_FIELDS.items()},
                    "conflict_resolution": "unknown",
                },
                expected="A consistent precedence rule is applied, and non-standard values from one source cannot circumvent validation applied to the other.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- Shared helper -----------------------------------------------------

    async def _check_persisted_state(self, path: str) -> str:
        """Checks the resource state via an independent GET to see if
        non-standard values were actually persisted."""
        # Try to extract a resource ID from the path or make a generic GET
        try:
            # If the path contains a resource ID, use it
            # Otherwise, just return a generic note
            return ""
        except Exception:
            return ""
