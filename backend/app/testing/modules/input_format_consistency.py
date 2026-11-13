"""Modul 12: Input-Format-Consistency (ISO/IEC 25010).

Auditor-Anforderung 2, verbatim: "ISO/IEC 25010 verlangt dass
Input-Validierung KONSISTENT ueber alle zulaessigen Formate hinweg
funktioniert. Wenn Ihr System einen JSON-Payload blockiert, muss derselbe
Payload als form-urlencoded ebenfalls blockiert werden."

Scope, deliberately bounded the same way ROLE-002 and path_prober.py bound
theirs:

  - Routes: ONLY routes ROLE-002 already tested this run AND found to
    block the standard JSON/lowercase payload on at least one attribute
    (read from context.shared_state["role_002_matrix"], stashed by
    role_based_access.py). This is a robustness re-check of an ALREADY
    CONFIRMED control, not new route discovery -- a route ROLE-002 never
    saw, or already found broken in plain JSON, is out of scope here (the
    latter is already a finding; re-confirming it via other encodings adds
    no new information, only more requests against the target).
  - Formats: a FIXED set of four variants (form-urlencoded, two casing
    variants, one Content-Type mismatch) -- not an open-ended encoding/
    bypass fuzzer. See _FORMAT_VARIANTS below; nothing else is tried.

Same evidence discipline as ROLE-002: a snapshot GET before, the mutation
itself, and -- whenever the mutation response alone is ambiguous (2xx
without reflection, or 5xx) -- an INDEPENDENT GET afterward to establish
the actual persisted state (SOC2 CC7.1: the response code proves nothing
by itself). Any confirmed change triggers the same immediate automatic
rollback pattern as ROLE-002-ROLLBACK-*, reported here as
FORMAT-ROLLBACK-*.

The actual cross-format CONSISTENCY verdict (comparing these results
against ROLE-002's JSON baseline) is deliberately NOT computed here --
this module only has this run's own results in hand while it's running,
not ROLE-002's already-finished verdict as a live, re-checkable fact. That
correlation happens retrospectively, with both modules' actual evidence
already on the table, in discovery/analyzers.py's analyze_format_consistency
(see discovery/engine.py) -- the same reason cross-module correlation in
general lives in the discovery layer rather than in any one module.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlencode

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.modules.role_based_access import (
    _MALICIOUS_PAYMENT_ATTRIBUTES,
    _SAFE_ROLLBACK_DEFAULTS,
    _evaluate_payment_attribute_injection,
    _slug,
)
from app.testing.models import TestResult


@dataclass(frozen=True)
class _FormatVariant:
    slug: str
    label: str
    # Returns (json_body, raw_body, extra_headers) for context.http.request.
    # Exactly one of json_body/raw_body is meaningful per variant.
    build: Callable[[dict[str, Any]], tuple[Any, bytes | None, dict[str, str]]]


def _form_urlencoded(payload: dict[str, Any]) -> tuple[None, bytes, dict[str, str]]:
    body = urlencode({key: str(value) for key, value in payload.items()}).encode("utf-8")
    return None, body, {"Content-Type": "application/x-www-form-urlencoded"}


def _recased_json(transform: Callable[[str], str]) -> Callable[[dict[str, Any]], tuple[Any, None, dict[str, str]]]:
    def _build(payload: dict[str, Any]) -> tuple[Any, None, dict[str, str]]:
        return {transform(key): value for key, value in payload.items()}, None, {}

    return _build


def _text_plain_content_type(payload: dict[str, Any]) -> tuple[None, bytes, dict[str, str]]:
    return None, json.dumps(payload).encode("utf-8"), {"Content-Type": "text/plain"}


_FORMAT_VARIANTS: tuple[_FormatVariant, ...] = (
    _FormatVariant(
        slug="FORMURLENCODED",
        label="form-urlencoded",
        build=_form_urlencoded,
    ),
    _FormatVariant(
        slug="CAPITALIZED",
        label="JSON, Capitalized-Keys",
        build=_recased_json(lambda k: k[0].upper() + k[1:]),
    ),
    _FormatVariant(
        slug="UPPERCASE",
        label="JSON, UPPERCASE-Keys",
        build=_recased_json(lambda k: k.upper()),
    ),
    _FormatVariant(
        slug="TEXTPLAIN",
        label="JSON body, Content-Type: text/plain",
        build=_text_plain_content_type,
    ),
)


class InputFormatConsistencyModule(BaseTestModule):
    module_id = "input_format_consistency"
    display_name = "Input Format Consistency (ISO/IEC 25010)"
    category = TestCategory.INPUT_FORMAT_CONSISTENCY

    async def run(self) -> None:
        matrix = self.context.shared_state.get("role_002_matrix")
        if not isinstance(matrix, list) or not matrix:
            await self._emit_skip()
            return

        eligible = [
            (position, row)
            for position, row in enumerate(matrix, start=1)
            if isinstance(row, dict) and "blocked" in row.get("attributes", {}).values()
        ]
        if not eligible:
            await self._emit_info(
                test_case_id="FORMAT-000",
                name="Input Format Consistency skipped",
                actual=(
                    f"ROLE-002 ran and checked {len(matrix)} route(s) this run, but none showed a 'blocked' "
                    "verdict for any payment attribute in the standard JSON case -- there is no working control "
                    "to format-stress-test yet (see ROLE-002-MATRIX; fix that first)."
                ),
            )
            return

        matrix_rows: list[dict[str, Any]] = []
        for position, row in eligible:
            route_result_rows = await self._run_route(position, row)
            matrix_rows.append(route_result_rows)

        await self._emit_matrix(matrix_rows, routes_checked=len(eligible), routes_total=len(matrix))

    # -- per-route / per-variant -------------------------------------------

    async def _run_route(self, position: int, row: dict[str, Any]) -> dict[str, Any]:
        method, path = row["method"], row["path"]
        role_002_ref = f"ROLE-002-{position:02d}-{_slug(path)}"
        original = await self._snapshot(path)

        variants: dict[str, dict[str, Any]] = {}
        for variant in _FORMAT_VARIANTS:
            result, verdicts = await self._case_format_variant(position, row, variant, original, role_002_ref)
            variants[variant.slug] = {"label": variant.label, "test_case_id": result.test_case_id, "verdicts": verdicts}

        return {
            "method": method, "path": path, "category": row.get("category", "unknown"),
            "role_002_reference": role_002_ref, "variants": variants,
        }

    async def _snapshot(self, path: str) -> dict[str, Any]:
        """Same best-effort pre-check as role_based_access.py's
        _snapshot_original_values -- captures the current value so a
        rollback restores the exact prior state instead of guessing."""
        _, resp = await self.context.http.request("GET", path)
        if resp.error is not None or not isinstance(resp.body, dict):
            return {}
        return {key: resp.body[key] for key in _MALICIOUS_PAYMENT_ATTRIBUTES if key in resp.body}

    async def _case_format_variant(
        self, position: int, row: dict[str, Any], variant: _FormatVariant, original: dict[str, Any], role_002_ref: str,
    ) -> tuple[TestResult, dict[str, str]]:
        method, path = row["method"], row["path"]
        json_body, raw_body, extra_headers = variant.build(_MALICIOUS_PAYMENT_ATTRIBUTES)

        started = datetime.now(timezone.utc)
        request_evidence, response_evidence = await self.context.http.request(
            method, path, json_body=json_body, raw_body=raw_body, extra_headers=extra_headers or None,
        )
        finished = datetime.now(timezone.utc)

        # Evaluated against the CANONICAL attribute names regardless of what
        # casing/encoding was actually sent on the wire -- what matters is
        # whether the malicious value reached the resource's real field,
        # not what key name carried it there. Using the recased keys here
        # instead would silently miss a server that case-folds/normalizes
        # incoming fields before persisting them.
        status, actual, verdicts, reflected = _evaluate_payment_attribute_injection(
            response_evidence, _MALICIOUS_PAYMENT_ATTRIBUTES
        )

        if not reflected and response_evidence.error is None and status in (ResultStatus.WARNING, ResultStatus.FAIL):
            resolution = await self._resolve_via_independent_get(path, original, ambiguous_from_error=status == ResultStatus.FAIL)
            if resolution is not None:
                status, note, reflected = resolution
                actual = f"{actual}{note}"
                if reflected:
                    verdicts = {k: ("accepted" if k in reflected else v) for k, v in verdicts.items()}

        recommendation: str | None = None
        if status in (ResultStatus.FAIL, ResultStatus.ERROR):
            recommendation = (
                f"The standard JSON/lowercase payload is already rejected on this route (see {role_002_ref}), but "
                f"the {variant.label} encoding of the exact same payload was not. Validate payment/subscription "
                "fields AFTER normalizing content-type/casing/encoding, not only for the one representation the "
                "client happens to send today."
            )
        elif status == ResultStatus.WARNING:
            recommendation = (
                "Re-fetch this resource through the customer-facing API as the same identity to confirm whether the field actually "
                "changed -- this response alone does not prove it was ignored (the internal state is UNKNOWN, not inspected)."
            )

        result = TestResult(
            test_case_id=f"FORMAT-{position:02d}-{variant.slug}-{_slug(path)}",
            category=self.category,
            name=f"Format consistency ({variant.label}): {method} {path}",
            description=(
                f"ISO/IEC 25010 input-validation consistency: resends the same malicious payload that "
                f"{role_002_ref} already confirmed this route blocks in standard JSON, this time as "
                f"{variant.label}, and checks whether the same attributes are rejected regardless of wire "
                "format. Scope is fixed to four format variants (form-urlencoded, two key-casing variants, one "
                "Content-Type mismatch) on routes ROLE-002 already covers -- no new routes, no open-ended "
                "encoding fuzzing."
            ),
            input_parameters={
                "variant": variant.label, "canonical_attributes": _MALICIOUS_PAYMENT_ATTRIBUTES, "role_002_reference": role_002_ref,
            },
            expected=f"Same outcome as {role_002_ref}: HTTP 4xx, or a 2xx that does not persist/reflect the attribute(s).",
            actual=actual,
            status=status,
            request=request_evidence,
            response=response_evidence,
            recommendation=recommendation,
            started_at=started,
            finished_at=finished,
            duration_ms=(finished - started).total_seconds() * 1000,
        )
        await self.emit(result)

        if reflected:
            await self._attempt_rollback(position, variant, method, path, original, reflected)

        return result, verdicts

    async def _resolve_via_independent_get(
        self, path: str, original: dict[str, Any], *, ambiguous_from_error: bool,
    ) -> tuple[ResultStatus, str, list[str]] | None:
        """SOC2 CC7.1: an ambiguous mutation response (2xx without
        reflection, or 5xx) proves nothing about the actual persisted
        state either way -- so check it directly instead of leaving the
        verdict as a guess. Returns None if the GET itself is inconclusive,
        leaving the original ambiguous verdict as final."""
        _, get_resp = await self.context.http.request("GET", path)
        if get_resp.error is not None or not isinstance(get_resp.body, dict):
            return None

        now_malicious = [
            key for key, malicious_value in _MALICIOUS_PAYMENT_ATTRIBUTES.items()
            if get_resp.body.get(key) == malicious_value and original.get(key) != malicious_value
        ]
        if now_malicious:
            return (
                ResultStatus.FAIL,
                f" Independent GET after the request confirms {sorted(now_malicious)} WAS persisted, despite not "
                "being reflected in the mutation response itself.",
                now_malicious,
            )
        if ambiguous_from_error:
            return (
                ResultStatus.WARNING,
                " Independent GET after the request confirms the payment/subscription field(s) were NOT changed "
                "-- but the server error itself should still be fixed to return a clean 4xx rejection instead.",
                [],
            )
        return (
            ResultStatus.PASS,
            " Independent GET after the request confirms the payment/subscription field(s) were NOT changed -- "
            "the response did not correspond to an actual state change.",
            [],
        )

    async def _attempt_rollback(
        self, position: int, variant: _FormatVariant, method: str, path: str, original: dict[str, Any], reflected_keys: list[str],
    ) -> None:
        """Identical pattern to role_based_access.py's _attempt_rollback --
        duplicated rather than imported across module classes to avoid
        touching that file beyond the one additive shared_state line
        elsewhere in this delivery."""
        restore_payload = {key: original.get(key, _SAFE_ROLLBACK_DEFAULTS[key]) for key in reflected_keys}

        started = datetime.now(timezone.utc)
        request_evidence, response_evidence = await self.context.http.request(method, path, json_body=restore_payload)
        finished = datetime.now(timezone.utc)

        if response_evidence.error is not None:
            status, actual = ResultStatus.FAIL, f"Rollback request failed at the transport level: {response_evidence.error}. Manual intervention needed."
        elif response_evidence.status_code is not None and 200 <= response_evidence.status_code < 300:
            body = response_evidence.body if isinstance(response_evidence.body, dict) else None
            confirmed = body is not None and all(body.get(k) == v for k, v in restore_payload.items())
            status = ResultStatus.PASS if confirmed else ResultStatus.WARNING
            actual = (
                f"HTTP {response_evidence.status_code} - rollback applied and confirmed: {restore_payload}."
                if confirmed
                else f"HTTP {response_evidence.status_code} - rollback accepted but not confirmed by the response body; verify manually."
            )
        else:
            status = ResultStatus.FAIL
            actual = f"HTTP {response_evidence.status_code} - rollback request itself was rejected. Manual intervention needed."

        await self.emit(
            TestResult(
                test_case_id=f"FORMAT-ROLLBACK-{position:02d}-{variant.slug}-{_slug(path)}",
                category=self.category,
                name=f"Automatic rollback attempt ({variant.label}): {method} {path}",
                description=(
                    f"The {variant.label} variant confirmed this route applied an injected payment attribute. "
                    "Per design, immediately attempted to restore the affected field(s) to the value captured "
                    "just before this test, or a conservative non-premium default."
                ),
                input_parameters=restore_payload,
                expected="The affected payment/subscription field(s) are restored on the test account.",
                actual=actual,
                status=status,
                request=request_evidence,
                response=response_evidence,
                recommendation=None if status == ResultStatus.PASS else "Manually verify and correct the test account's subscription/plan state.",
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- summary / skip -------------------------------------------------

    async def _emit_matrix(self, matrix_rows: list[dict[str, Any]], *, routes_checked: int, routes_total: int) -> None:
        any_accepted = any(
            verdict == "accepted"
            for row in matrix_rows
            for variant_info in row["variants"].values()
            for verdict in variant_info["verdicts"].values()
        )
        status = ResultStatus.FAIL if any_accepted else ResultStatus.PASS
        headline = (
            "One or more format variants accepted an attribute that the standard JSON case blocks -- a "
            "format-dependent Processing-Integrity inconsistency (ISO/IEC 25010). See the per-variant rows below "
            "and cross-reference each route's role_002_reference for the JSON baseline."
            if any_accepted
            else f"All {len(_FORMAT_VARIANTS)} format variants were rejected identically to the JSON baseline, "
            f"across {routes_checked} of {routes_total} route(s) checked (the rest had nothing to stress-test -- "
            "see FORMAT-000/ROLE-002-MATRIX)."
        )
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="FORMAT-MATRIX",
                category=self.category,
                name="Input format consistency across formats (matrix)",
                description=(
                    "ISO/IEC 25010 matrix: route x format-variant x payment-attribute x blocked/accepted, for "
                    "every route ROLE-002 confirmed blocking the standard JSON payload this run (see FORMAT-* "
                    "above for full per-variant request/response evidence, and FORMAT-ROLLBACK-* for any "
                    "automatic-restore attempts). The definitive cross-format consistency finding -- correlating "
                    "these rows against ROLE-002-MATRIX -- is produced retrospectively by the discovery layer's "
                    "analyze_format_consistency."
                ),
                input_parameters={"matrix": matrix_rows},
                expected="Every format variant produces the same blocked/accepted outcome as the JSON baseline.",
                actual=headline,
                status=status,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_skip(self) -> None:
        await self._emit_info(
            test_case_id="FORMAT-000",
            name="Input Format Consistency skipped",
            actual=(
                "No ROLE-002 results were available in this run (role_based_access must be enabled and run in "
                "the same pass, before this module -- see registry.py's MODULE_EXECUTION_ORDER) -- nothing to "
                "format-stress-test."
            ),
        )

    async def _emit_info(self, *, test_case_id: str, name: str, actual: str) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=name,
                description=(
                    "Resends payloads ROLE-002 already confirmed a route blocks in standard JSON, as "
                    "form-urlencoded / alternate key casing / a mismatched Content-Type, to verify input "
                    "validation is consistent across formats (ISO/IEC 25010), not only for the one wire format "
                    "the application's own client happens to send."
                ),
                input_parameters={},
                expected="N/A - informational.",
                actual=actual,
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )
