"""Error Handling Module.

Verifies error responses are well-formed, consistent, and safe:

  - ERR-001: error responses carry a stable, machine-readable code
  - ERR-002: error response shape is consistent across different error types
  - ERR-003: error messages don't leak stack traces / file paths / DB errors / internal hosts
  - ERR-004: responses carry a correlation id usable for log tracing (proxy for "logging works")
  - ERR-005: monitoring-alert verification -- documented as out of black-box-HTTP scope

ERR-004 and ERR-005 are honest about what a suite that only speaks HTTP to
your public API can and can't observe: it cannot read your log files or
your PagerDuty/Datadog account, so it doesn't pretend to. See each case's
description/recommendation for what it actually checks instead.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from app.testing.base import BaseTestModule
from app.testing.endpoints import EndpointMap
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import ResponseEvidence, TestResult
from app.testing.security_scan import scan_for_leaks

_VALID_PAYMENT_PAYLOAD_TEMPLATE = {
    "amount": 5.00,
    "currency": "USD",
    "productId": "prod_standard_plan",
    "customerEmail": "qa-errhandling@example.com",
    "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
}


class ErrorHandlingTestModule(BaseTestModule):
    module_id = "error_handling"
    display_name = "Error Handling Module"
    category = TestCategory.ERROR_HANDLING

    async def run(self) -> None:
        ep = self.context.endpoints
        # Resolved once per run (not a module-level constant, since
        # resolution needs this run's Recon discoveries) -- see negative.py
        # for why resolving the template, before any deliberate
        # case-specific override, is what keeps this safe.
        valid_payload = self.resolve_payload(_VALID_PAYMENT_PAYLOAD_TEMPLATE)
        await self._case_error_code_present(ep)
        await self._case_error_response_consistency(ep, valid_payload)
        await self._case_no_sensitive_info_leak(ep, valid_payload)
        await self._case_request_correlation_id(ep, valid_payload)
        await self._case_monitoring_alerts_note()

    # -- ERR-001 ------------------------------------------------------------

    async def _case_error_code_present(self, ep: EndpointMap) -> None:
        spec = ep.get_payment
        path = spec.path.format(payment_id="pay_qa_does_not_exist_000")

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code != 404:
                return ResultStatus.WARNING, f"HTTP {resp.status_code} - expected 404 for a nonexistent payment id; cannot verify error-code structure from this response."
            if not isinstance(resp.body, dict):
                return ResultStatus.FAIL, f"HTTP 404 but the response body is not a JSON object ({type(resp.body).__name__}) - no machine-readable field exists to match against documented error codes."
            code_like = {k for k in ("code", "error_code", "errorCode", "type", "error") if k in resp.body}
            if code_like:
                return ResultStatus.PASS, f"HTTP 404 with machine-readable field(s) {sorted(code_like)} present - this can be checked against documented error codes."
            return ResultStatus.WARNING, f"HTTP 404 but no code/error/type field found in body (keys: {list(resp.body.keys())}) - only the HTTP status exists to document."

        await self.execute_case(
            test_case_id="ERR-001",
            name="Error responses carry a machine-readable error code",
            description="Requests a nonexistent payment and checks whether the 404 response includes a stable code/type field, not just an HTTP status -- a prerequisite for 'error codes match documentation' being checkable at all.",
            method=spec.method,
            path=path,
            expected="HTTP 404 with a 'code', 'error_code', 'type', or 'error' field in the JSON body.",
            evaluate=evaluate,
            recommendation="Include a stable, documented error code (e.g. 'resource_not_found') in every error response body, separate from the free-text message, so clients can branch on it reliably.",
        )

    # -- ERR-002 ------------------------------------------------------------

    async def _case_error_response_consistency(self, ep: EndpointMap, valid_payload: dict) -> None:
        started = datetime.now(timezone.utc)

        _, resp_404 = await self.context.http.request(ep.get_payment.method, ep.get_payment.path.format(payment_id="pay_qa_does_not_exist_000"))

        incomplete_payload = {"currency": "USD"}
        _, resp_400 = await self.context.http.request(ep.create_payment.method, ep.create_payment.path, json_body=incomplete_payload)

        _, resp_401 = await self.context.http.request(
            ep.create_payment.method,
            ep.create_payment.path,
            json_body=valid_payload,
            extra_headers={"Authorization": "Bearer QA-TEST-EXPIRED-TOKEN-1970-01-01"},
        )

        finished = datetime.now(timezone.utc)

        probes = {"404 (unknown resource)": resp_404, "400 (missing field)": resp_400, "401 (bad auth)": resp_401}
        error_shapes = {
            label: frozenset(resp.body.keys())
            for label, resp in probes.items()
            if isinstance(resp.body, dict) and resp.status_code is not None and resp.status_code >= 400
        }

        if len(error_shapes) < 2:
            status = ResultStatus.WARNING
            actual = f"Only {len(error_shapes)}/3 error conditions returned a JSON error body - not enough to compare consistency."
            recommendation = "Ensure every error path (validation, auth, not-found) returns a JSON body, not just a bare HTTP status."
        else:
            keysets = [set(keys) for keys in error_shapes.values()]
            common_keys = set.intersection(*keysets)
            if common_keys:
                status = ResultStatus.PASS
                actual = f"{len(error_shapes)} error conditions checked; all share common field(s) {sorted(common_keys)} - consistent error envelope."
                recommendation = None
            else:
                status = ResultStatus.WARNING
                shapes_desc = "; ".join(f"{label}: {sorted(keys)}" for label, keys in error_shapes.items())
                actual = f"{len(error_shapes)} error conditions checked; no field is common to all error bodies. Shapes - {shapes_desc}"
                recommendation = 'Standardize on one error envelope (e.g. {"error": {"code": ..., "message": ...}}) used by every error path, so clients can handle errors uniformly.'

        await self.emit(
            TestResult(
                test_case_id="ERR-002",
                category=self.category,
                name="Error response shape is consistent",
                description="Triggers three different error conditions (404 not-found, 400 validation, 401 auth) and checks whether their JSON bodies share a common envelope structure.",
                input_parameters={"probed": list(probes.keys())},
                expected="All error responses share at least one common top-level field (e.g. 'error' or 'code').",
                actual=actual,
                status=status,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- ERR-003 ------------------------------------------------------------

    async def _case_no_sensitive_info_leak(self, ep: EndpointMap, valid_payload: dict) -> None:
        started = datetime.now(timezone.utc)
        probes: list[tuple[str, ResponseEvidence]] = []

        _, resp = await self.context.http.request(ep.get_payment.method, ep.get_payment.path.format(payment_id="pay_qa_does_not_exist_000"))
        probes.append(("get unknown payment", resp))

        broken_json = b'{"amount": 5.00, "currency": "USD"'
        _, resp = await self.context.http.request(ep.create_payment.method, ep.create_payment.path, raw_body=broken_json)
        probes.append(("malformed JSON payment", resp))

        oversized_payload = {**valid_payload, "amount": 999999999999999.99}
        _, resp = await self.context.http.request(ep.create_payment.method, ep.create_payment.path, json_body=oversized_payload)
        probes.append(("oversized amount", resp))

        finished = datetime.now(timezone.utc)

        all_findings: list[tuple[str, str, str]] = []  # (probe_label, category, snippet)
        for label, resp in probes:
            if resp.body is None:
                continue
            text = resp.body if isinstance(resp.body, str) else json.dumps(resp.body, default=str)
            for finding in scan_for_leaks(text[:50000]):
                all_findings.append((label, finding.category, finding.snippet))

        if all_findings:
            status = ResultStatus.FAIL
            lines = [f"[{label}] {category}: ...{snippet}..." for label, category, snippet in all_findings]
            actual = f"{len(all_findings)} potential information-disclosure signal(s) found across {len(probes)} error response(s):\n" + "\n".join(lines)
            recommendation = "Return generic error messages to clients; log full stack traces and internal details server-side only, never in the HTTP response body."
        else:
            status = ResultStatus.PASS
            actual = f"No stack traces, file paths, database errors, or internal hostnames found across {len(probes)} error response(s) (pattern-based scan)."
            recommendation = None

        await self.emit(
            TestResult(
                test_case_id="ERR-003",
                category=self.category,
                name="Error messages don't leak sensitive info",
                description="Scans several triggered error responses for stack traces, file paths, database errors, framework debug pages, and internal hostnames/IPs.",
                input_parameters={"probed": [label for label, _ in probes]},
                expected="No information-disclosure patterns found in any error response body.",
                actual=actual,
                status=status,
                recommendation=recommendation,
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- ERR-004 ------------------------------------------------------------

    async def _case_request_correlation_id(self, ep: EndpointMap, valid_payload: dict) -> None:
        spec = ep.create_payment

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            header_id = next(
                (v for k, v in resp.headers.items() if k.lower() in ("x-request-id", "x-correlation-id", "x-trace-id", "request-id")),
                None,
            )
            body_id = None
            if isinstance(resp.body, dict):
                body_id = next((resp.body[k] for k in ("requestId", "request_id", "traceId", "trace_id", "correlationId") if k in resp.body), None)

            if header_id or body_id:
                source = "response header" if header_id else "response body"
                return ResultStatus.PASS, f"HTTP {resp.status_code} includes a request/correlation id in the {source} - server-side logs can be correlated with this exact response."
            return ResultStatus.WARNING, f"HTTP {resp.status_code} has no request/correlation id in headers or body - a support engineer cannot trace a client's reported error back to your logs without one."

        await self.execute_case(
            test_case_id="ERR-004",
            name="Requests carry a correlation id for log tracing",
            description=(
                "Checks whether responses include a request/correlation id (header or body field) that would let "
                "a support/QA engineer trace this exact request in server-side logs. This is a proxy for "
                "'logging works correctly' -- this suite has no access to your actual log storage, so it checks "
                "for the mechanism that makes log correlation possible in the first place."
            ),
            method=spec.method,
            path=spec.path,
            input_parameters=valid_payload,
            expected="Response includes an X-Request-Id (or equivalent) header, or a requestId/traceId field in the body.",
            evaluate=evaluate,
            recommendation="Emit a unique request/correlation id on every response (success or error) and include it in the corresponding server-side log line.",
        )

    # -- ERR-005 ------------------------------------------------------------

    async def _case_monitoring_alerts_note(self) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="ERR-005",
                category=self.category,
                name="Monitoring alerts fire correctly",
                description=(
                    "Whether a monitoring/alerting system (PagerDuty, Opsgenie, Datadog, ...) actually fires an "
                    "alert cannot be observed from black-box HTTP calls against your API alone -- this suite has "
                    "no access to your monitoring platform."
                ),
                input_parameters={},
                expected="N/A - see recommendation for how to make this verifiable.",
                actual="Not automatically verifiable from outside your infrastructure; reported as INFO rather than a false PASS.",
                status=ResultStatus.INFO,
                recommendation=(
                    "If your alerting platform supports a generic webhook/HTTP integration, point a test alert "
                    "rule at this backend (extend core/webhook_sink.py to accept alert payloads the same way it "
                    "already accepts payment webhooks), then poll it the way FunctionalTestModule verifies payment "
                    "webhooks. Alternatively, query your monitoring platform's own API for an alert matching this "
                    "run's timeframe after inducing a known fault condition (e.g. the EDGE-005 concurrency test)."
                ),
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )
