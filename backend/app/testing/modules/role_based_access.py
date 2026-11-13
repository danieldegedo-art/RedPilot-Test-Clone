"""Role-Based Access Verification Module (AICPA SOC2 CC6.1 / CC7.1 extension).

Consumes the FunctionMap Recon builds (context.shared_state["function_map"],
see recon/function_mapper.py and RECON-004) and runs three verifications
against it, all following the same design principle as every other module
in this suite: the tool verifies whether a request is CORRECTLY REJECTED.
Rejected -> PASS (the control works). Carried out -> FAIL (the control is
missing). This module never performs an action for its own sake -- every
request either reads the test session's own data back, or attempts a
change specifically so its rejection (or, on FAIL, its acceptance) can be
observed and reported.

  ROLE-001 (CC6.1, "restrict logical access... to authorized users"):
    account isolation. Calls every discovered account-management (GET)
    route with the test session's own credentials and checks whether the
    response contains data for more than one account. No foreign id is
    ever guessed, requested, or targeted -- this only checks that a route
    meant to return "my data" doesn't also return someone else's.

  ROLE-002 (CC7.1 Processing Integrity, extended to every mutating route):
    payment-attribute protection. Sends a payment/subscription-attribute
    injection payload to every PATCH/PUT/POST route Recon discovered
    (excluding the payment flow's own creation endpoints, where accepting
    these fields is the intended behavior) and checks whether any of them
    applied it. Builds the route x attribute x blocked/accepted matrix as
    ROLE-002-MATRIX. If a test ever DOES confirm an attribute was applied,
    an automatic rollback attempt is made immediately and reported as its
    own auditable result (ROLE-002-ROLLBACK-*) -- see _attempt_rollback.

  ROLE-003 (CC6.1, function-level authorization): system-route access
    check. Verifies every discovered system-administration route rejects
    the test session's own (non-admin) credentials, for GET and for every
    write method -- never attempting an actual system change (write-method
    probes use an empty body; the only thing observed is whether the
    request is rejected before any body-driven action would occur).

Every sub-check keeps its own full request/response evidence; the
-SUMMARY/-MATRIX results are aggregate rollups for the dashboard and never
replace the per-route evidence.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.core.control_port import NEGATIVE_ACCESS_CONTROL
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import ResponseEvidence, TestResult
from app.testing.recon.function_mapper import FunctionCategory, FunctionMap, MappedRoute

_IDENTITY_FIELDS: tuple[str, ...] = (
    "email", "user_email", "userEmail",
    "user_id", "userId",
    "account_id", "accountId",
    "customer_id", "customerId",
    "username",
)

_MALICIOUS_PAYMENT_ATTRIBUTES: dict[str, Any] = {
    "plan": "max",
    "subscription_status": "active",
    "tier": "premium",
    "is_premium": True,
}

_SAFE_ROLLBACK_DEFAULTS: dict[str, Any] = {
    "plan": "free",
    "subscription_status": "inactive",
    "tier": "free",
    "is_premium": False,
}

_LEGITIMATE_PAYMENT_OPERATIONS: tuple[str, ...] = (
    "create_payment", "create_subscription", "create_checkout_session", "create_refund", "cancel_subscription",
)

_SYSTEM_CHECK_METHODS: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH")

_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")


def _slug(path: str) -> str:
    slug = _SLUG_RE.sub("-", path).strip("-").upper()
    return (slug[:60] if len(slug) > 60 else slug) or "ROOT"


def _status_value(result: TestResult) -> str:
    return result.status if isinstance(result.status, str) else result.status.value


def _rollup_status(sub_results: list[TestResult]) -> ResultStatus:
    statuses = {_status_value(r) for r in sub_results}
    if ResultStatus.FAIL.value in statuses:
        return ResultStatus.FAIL
    if ResultStatus.ERROR.value in statuses:
        return ResultStatus.ERROR
    if ResultStatus.WARNING.value in statuses:
        return ResultStatus.WARNING
    if ResultStatus.PASS.value in statuses:
        return ResultStatus.PASS
    return ResultStatus.INFO


def _distinct_identity_values(items: list[Any]) -> dict[str, set[str]]:
    values: dict[str, set[str]] = defaultdict(set)
    for item in items:
        if not isinstance(item, dict):
            continue
        for field_name in _IDENTITY_FIELDS:
            if field_name in item and item[field_name] is not None:
                values[field_name].add(str(item[field_name]))
    return values


def _benign_placeholder_for(param_name: str) -> Any:
    """Best-effort filler for a route's OTHER observed parameters (see
    recon/js_endpoint_parser.py's param_names capture), so ROLE-002's
    payload looks like a plausible update rather than an obviously-bare
    probe -- the same best-effort spirit as the rest of Recon's heuristics."""
    lowered = param_name.lower()
    if "email" in lowered:
        return "qa-role-based-access@example.com"
    if any(k in lowered for k in ("name", "title", "label", "note", "bio")):
        return "QA Test Value"
    if any(k in lowered for k in ("amount", "price", "quantity", "count", "qty")):
        return 1
    if lowered == "id" or lowered.endswith("_id") or lowered.endswith("id"):
        return "qa-test-id"
    return "qa-test-value"


def _build_probe_payload(route: MappedRoute) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for param_name in sorted(route.param_names):
        if param_name in _MALICIOUS_PAYMENT_ATTRIBUTES:
            continue
        payload[param_name] = _benign_placeholder_for(param_name)
    payload.update(_MALICIOUS_PAYMENT_ATTRIBUTES)
    return payload


def _evaluate_payment_attribute_injection(
    resp: ResponseEvidence, sent_attributes: dict[str, Any],
) -> tuple[ResultStatus, str, dict[str, str], list[str]]:
    """Returns (status, actual_text, verdict_per_attribute, reflected_keys).
    `reflected_keys` lists attributes the response body echoed back with
    the exact injected value -- the trigger condition for an automatic
    rollback attempt."""
    if resp.error is not None:
        return ResultStatus.ERROR, f"Transport error: {resp.error}", {k: "unknown" for k in sent_attributes}, []

    if resp.status_code is not None and 400 <= resp.status_code < 500:
        return (
            ResultStatus.PASS,
            f"HTTP {resp.status_code} - request rejected; payment attributes were not applied.",
            {k: "blocked" for k in sent_attributes},
            [],
        )

    if resp.status_code is not None and resp.status_code >= 500:
        return (
            ResultStatus.FAIL,
            f"HTTP {resp.status_code} - server error instead of a clean rejection; validation behavior for "
            "these fields could not be confirmed and must be checked manually.",
            {k: "server_error" for k in sent_attributes},
            [],
        )

    if resp.status_code is not None and 200 <= resp.status_code < 300:
        body = resp.body if isinstance(resp.body, dict) else None
        reflected = [k for k, v in sent_attributes.items() if body is not None and k in body and body[k] == v]
        if reflected:
            return (
                ResultStatus.FAIL,
                f"HTTP {resp.status_code} - request accepted AND the response body reflects the injected "
                f"value(s) back for {sorted(reflected)}. This route lets a client set payment/subscription "
                "attributes directly, bypassing the payment flow.",
                {k: ("accepted" if k in reflected else "unconfirmed") for k in sent_attributes},
                reflected,
            )
        return (
            ResultStatus.WARNING,
            f"HTTP {resp.status_code} - the request was accepted at the transport level, but the response does "
            "not echo the injected attribute(s) back, so this black-box call alone cannot confirm whether they "
            "were silently persisted or silently ignored.",
            {k: "unconfirmed" for k in sent_attributes},
            [],
        )

    return (
        ResultStatus.WARNING,
        f"HTTP {resp.status_code} - unexpected response; could not classify.",
        {k: "unconfirmed" for k in sent_attributes},
        [],
    )


class RoleBasedAccessModule(BaseTestModule):
    module_id = "role_based_access"
    display_name = "Role-Based Access Verification (SOC2 CC6.1)"
    category = TestCategory.ROLE_BASED_ACCESS

    async def run(self) -> None:
        function_map = self.context.shared_state.get("function_map")
        if not isinstance(function_map, FunctionMap) or not function_map.routes:
            await self._emit_no_function_map()
            return

        await self._run_role_001(function_map)
        await self._run_role_002(function_map)
        await self._run_role_003(function_map)

    async def _emit_no_function_map(self) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="ROLE-000",
                category=self.category,
                name="Role-Based Access Verification skipped",
                description=(
                    "This module verifies access control against the FunctionMap Recon builds (see RECON-004). "
                    "No function map was available in this run."
                ),
                input_parameters={},
                expected="N/A - informational.",
                actual=(
                    "Skipped: no function map found in shared_state. Recon must run in the same pass, before "
                    "this module (see registry.py's MODULE_EXECUTION_ORDER), for ROLE-001/002/003 to have "
                    "discovered routes to verify."
                ),
                status=ResultStatus.INFO,
                recommendation="Enable the Recon module under Settings -> Test Modules if it's currently disabled.",
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_role_info(self, *, test_case_id: str, name: str, description: str, actual: str) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=name,
                description=description,
                input_parameters={},
                expected="N/A - informational.",
                actual=actual,
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_role_summary(
        self,
        *,
        test_case_id: str,
        name: str,
        description: str,
        sub_results: list[TestResult],
        fail_text: str,
        pass_text: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        status = _rollup_status(sub_results)
        counts: dict[str, int] = defaultdict(int)
        for result in sub_results:
            counts[_status_value(result)] += 1
        counts_desc = ", ".join(f"{count} {status_name}" for status_name, count in sorted(counts.items()))
        if status in (ResultStatus.FAIL, ResultStatus.ERROR):
            headline = fail_text
        elif status == ResultStatus.PASS:
            headline = pass_text
        else:
            headline = "Results were ambiguous or informational for one or more routes; see per-route results for detail."

        await self.emit(
            TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=name,
                description=description,
                input_parameters={"routes_checked": len(sub_results)},
                expected="N/A - aggregate rollup of the per-route results above.",
                actual=f"{headline} ({len(sub_results)} route(s)/method(s) checked: {counts_desc}).",
                status=status,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    # -- ROLE-001 -----------------------------------------------------------

    async def _run_role_001(self, function_map: FunctionMap) -> None:
        routes = [r for r in function_map.by_category(FunctionCategory.ACCOUNT_MANAGEMENT) if r.method == "GET"]
        if not routes:
            await self._emit_role_info(
                test_case_id="ROLE-001-SUMMARY",
                name="Account isolation on own data",
                description=(
                    "Calls every discovered account-management (GET) route and checks for cross-account data "
                    "exposure."
                ),
                actual="No GET account-management routes were found in this run's function map - nothing to verify.",
            )
            return

        sub_results = [
            await self._case_account_isolation(index, route)
            for index, route in enumerate(sorted(routes, key=lambda r: (r.method, r.path)), start=1)
        ]
        await self._emit_role_summary(
            test_case_id="ROLE-001-SUMMARY",
            name="Account isolation on own data (summary)",
            description=(
                "Aggregate verdict across every account-management route checked for cross-account data "
                "exposure (see ROLE-001-* above for full per-route request/response evidence)."
            ),
            sub_results=sub_results,
            fail_text="One or more account-management routes returned data for more than one account.",
            pass_text="Every account-management route returned data scoped to a single account only.",
        )

    async def _case_account_isolation(self, index: int, route: MappedRoute) -> TestResult:
        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code != 200:
                return (
                    ResultStatus.INFO,
                    f"HTTP {resp.status_code} - not a successful read; account isolation could not be evaluated "
                    "from this response.",
                )
            if isinstance(resp.body, list):
                leaking = {
                    field_name: sorted(values)
                    for field_name, values in _distinct_identity_values(resp.body).items()
                    if len(values) >= 2
                }
                if leaking:
                    fields_desc = ", ".join(f"{field_name} ({len(values)} distinct values)" for field_name, values in leaking.items())
                    return (
                        ResultStatus.FAIL,
                        f"HTTP 200 - response is a list of {len(resp.body)} item(s) containing multiple distinct "
                        f"values for identity field(s): {fields_desc}. This endpoint appears to return data "
                        "belonging to more than one account, not only the authenticated test session's own account.",
                    )
                return (
                    ResultStatus.PASS,
                    f"HTTP 200 - response is a list of {len(resp.body)} item(s); no identity field shows more "
                    "than one distinct value across the list - consistent with data scoped to a single account.",
                )
            if isinstance(resp.body, dict):
                present = [f for f in _IDENTITY_FIELDS if f in resp.body]
                return (
                    ResultStatus.INFO,
                    "HTTP 200 - response is a single object"
                    + (f" with identity field(s) {present}" if present else " with no identity field present")
                    + " - a single object carries no internal signal of a second account's data, so isolation "
                    "could not be actively falsified from this response alone (no foreign id was guessed or requested).",
                )
            return (
                ResultStatus.INFO,
                f"HTTP 200 - response body is {type(resp.body).__name__}, not a JSON object/list; account "
                "isolation could not be evaluated from this response shape.",
            )

        return await self.execute_case(
            test_case_id=f"ROLE-001-{index:02d}-{_slug(route.path)}",
            name=f"Account isolation: {route.method} {route.path}",
            description=(
                "Calls an account-management route discovered by Recon with the test session's own credentials "
                "and checks whether the response contains data for more than one account (AICPA SOC2 CC6.1: "
                "'restrict logical access to information assets to authorized users'). No foreign id is ever "
                "guessed or requested -- this only checks that a route meant to return the caller's own data "
                "doesn't also return someone else's."
            ),
            method=route.method,
            path=route.path,
            expected="Response contains data for the authenticated account only - no second, distinct account identity present.",
            evaluate=evaluate,
            recommendation=(
                "Scope this endpoint's query to the authenticated account (e.g. WHERE user_id = "
                "current_user.id) and add a regression test asserting no cross-account rows can ever be returned."
            ),
        )

    # -- ROLE-002 -----------------------------------------------------------

    def _is_legitimate_payment_flow_route(self, method: str, path: str) -> bool:
        """Excludes the payment/subscription-creation endpoints already
        covered by the Functional and Stripe Flow modules -- accepting a
        plan/tier field THERE is the intended behavior, not a finding."""
        for operation in _LEGITIMATE_PAYMENT_OPERATIONS:
            spec = self.context.endpoints.get(operation)
            if spec.method == method and spec.path == path:
                return True
        return False

    async def _run_role_002(self, function_map: FunctionMap) -> None:
        routes = [
            r
            for r in function_map.routes
            if r.method in ("PATCH", "PUT", "POST") and not self._is_legitimate_payment_flow_route(r.method, r.path)
        ]
        if not routes:
            await self._emit_role_info(
                test_case_id="ROLE-002-MATRIX",
                name="Payment attribute protection across all routes",
                description=(
                    "Sends a payment-attribute injection payload to every mutating (PATCH/PUT/POST) route "
                    "Recon discovered, excluding the payment flow's own creation endpoints."
                ),
                actual=(
                    "No mutating routes (outside the payment flow's own creation endpoints) were found in this "
                    "run's function map - nothing to verify."
                ),
            )
            return

        matrix_rows: list[dict[str, Any]] = []
        sub_results: list[TestResult] = []
        for index, route in enumerate(sorted(routes, key=lambda r: (r.method, r.path)), start=1):
            result, verdicts = await self._case_payment_attribute_injection(index, route)
            sub_results.append(result)
            matrix_rows.append(
                {"method": route.method, "path": route.path, "category": route.category.value, "attributes": verdicts}
            )

        # Erweiterung: lets input_format_consistency.py (Modul 12) know which
        # routes already have a confirmed-working JSON/lowercase control
        # worth format-stress-testing, and lets the discovery layer's
        # analyze_format_consistency correlate its FORMAT-* results against
        # this exact baseline -- same handoff pattern Recon already uses for
        # "stripe_detection". Purely additive: nothing existing reads this key.
        self.context.shared_state["role_002_matrix"] = matrix_rows

        status = _rollup_status(sub_results)
        if status in (ResultStatus.FAIL, ResultStatus.ERROR):
            headline = (
                "One or more routes accepted a payment/subscription attribute directly, or failed with a "
                "server error instead of a clean rejection - see the matrix and per-route evidence above."
            )
        elif status == ResultStatus.WARNING:
            headline = (
                "No route confirmed accepting a payment/subscription attribute, but one or more responses were "
                "ambiguous (accepted at the transport level without confirmation) - manual verification recommended."
            )
        else:
            headline = "No route accepted a payment/subscription attribute outside the verified payment flow."

        lines = [
            f"{row['method']} {row['path']} [{row['category']}]: "
            + ", ".join(f"{attribute}={verdict}" for attribute, verdict in row["attributes"].items())
            for row in matrix_rows
        ]

        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="ROLE-002-MATRIX",
                category=self.category,
                name="Payment attribute protection across all routes (matrix)",
                description=(
                    "CC7.1 Processing Integrity matrix: route x payment-attribute x blocked/accepted, "
                    "aggregated across every mutating route probed by ROLE-002 (see ROLE-002-* above for full "
                    "per-route request/response evidence, and ROLE-002-ROLLBACK-* for any automatic-restore "
                    "attempts)."
                ),
                input_parameters={"matrix": matrix_rows},
                expected="No route outside the verified payment flow accepts plan/subscription_status/tier/is_premium.",
                actual=f"{headline}\n" + "\n".join(lines),
                status=status,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _case_payment_attribute_injection(self, index: int, route: MappedRoute) -> tuple[TestResult, dict[str, str]]:
        payload = _build_probe_payload(route)
        original_values = await self._snapshot_original_values(route.path)

        started = datetime.now(timezone.utc)
        request_evidence, response_evidence = await self.context.http.request(route.method, route.path, json_body=payload)
        finished = datetime.now(timezone.utc)

        status, actual, verdicts, reflected_keys = _evaluate_payment_attribute_injection(
            response_evidence, _MALICIOUS_PAYMENT_ATTRIBUTES
        )

        recommendation: str | None = None
        if status in (ResultStatus.FAIL, ResultStatus.ERROR):
            recommendation = (
                "Never accept plan/tier/subscription_status/is_premium (or equivalent) fields on general-purpose "
                "update endpoints. Only the payment-flow endpoints -- verified server-side against your payment "
                "provider -- should ever change these fields; strip or explicitly reject them everywhere else."
            )
        elif status == ResultStatus.WARNING:
            recommendation = (
                "Re-fetch this resource through the customer-facing API as the same identity (and USE a plan-gated feature) to confirm whether "
                "plan/tier/subscription_status actually changed - a 2xx response that doesn't echo the field back is not proof it was ignored."
            )

        result = TestResult(
            test_case_id=f"ROLE-002-{index:02d}-{_slug(route.path)}",
            category=self.category,
            name=f"Payment attribute protection: {route.method} {route.path}",
            description=(
                "CC7.1 Processing Integrity, extended to every mutating route Recon discovered (not only "
                f"account-management routes): sends an update containing payment/subscription attributes "
                f"({sorted(_MALICIOUS_PAYMENT_ATTRIBUTES)}) that only the verified payment flow should ever be "
                "able to set, and checks whether this route applied them. Payment/subscription-creation "
                "endpoints already covered by the Functional and Stripe Flow modules are excluded, since "
                "accepting these fields there is the intended behavior."
            ),
            input_parameters=payload,
            expected="HTTP 4xx (payment attributes rejected), or a 2xx response that does not persist/reflect them.",
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

        if reflected_keys:
            await self._attempt_rollback(index, route, original_values, reflected_keys)

        return result, verdicts

    async def _snapshot_original_values(self, path: str) -> dict[str, Any]:
        """Best-effort pre-check: if this path also answers GET, capture its
        current value for the malicious attribute keys, so a rollback (if
        ever needed) restores the exact prior value instead of guessing."""
        _, resp = await self.context.http.request("GET", path)
        if resp.error is not None or not isinstance(resp.body, dict):
            return {}
        return {key: resp.body[key] for key in _MALICIOUS_PAYMENT_ATTRIBUTES if key in resp.body}

    async def _attempt_rollback(
        self, index: int, route: MappedRoute, original_values: dict[str, Any], reflected_keys: list[str]
    ) -> None:
        """Erweiterung 3: if a test confirms a payment attribute was
        actually applied, immediately try to restore it -- to the value
        snapshotted just before the test if one was captured, otherwise to
        a conservative non-premium default -- and report the outcome so
        it's auditable rather than silently assumed."""
        restore_payload = {key: original_values.get(key, _SAFE_ROLLBACK_DEFAULTS[key]) for key in reflected_keys}

        started = datetime.now(timezone.utc)
        request_evidence, response_evidence = await self.context.http.request(
            route.method, route.path, json_body=restore_payload
        )
        finished = datetime.now(timezone.utc)

        if response_evidence.error is not None:
            status = ResultStatus.FAIL
            actual = (
                f"Rollback request failed at the transport level: {response_evidence.error}. Manual "
                f"intervention is needed to restore the test account's {sorted(reflected_keys)}."
            )
        elif response_evidence.status_code is not None and 200 <= response_evidence.status_code < 300:
            body = response_evidence.body if isinstance(response_evidence.body, dict) else None
            confirmed = body is not None and all(body.get(k) == v for k, v in restore_payload.items())
            if confirmed:
                status = ResultStatus.PASS
                actual = f"HTTP {response_evidence.status_code} - rollback applied and confirmed in the response body: {restore_payload}."
            else:
                status = ResultStatus.WARNING
                actual = (
                    f"HTTP {response_evidence.status_code} - rollback request accepted but not confirmed by the "
                    f"response body; verify manually that {sorted(reflected_keys)} was actually restored on the "
                    "test account."
                )
        else:
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {response_evidence.status_code} - rollback request itself was rejected. Manual "
                f"intervention is needed to restore the test account's {sorted(reflected_keys)}."
            )

        await self.emit(
            TestResult(
                test_case_id=f"ROLE-002-ROLLBACK-{index:02d}-{_slug(route.path)}",
                category=self.category,
                name=f"Automatic rollback attempt: {route.method} {route.path}",
                description=(
                    "ROLE-002 confirmed this route actually applied an injected payment attribute on the test "
                    "account. Per design, the tool immediately attempted to restore the affected field(s) -- to "
                    "the value captured just before the test if one was available, otherwise a conservative "
                    "non-premium default -- and reports the outcome here rather than assuming success silently."
                ),
                input_parameters=restore_payload,
                expected="The affected payment/subscription field(s) are restored on the test account.",
                actual=actual,
                status=status,
                request=request_evidence,
                response=response_evidence,
                recommendation=None
                if status == ResultStatus.PASS
                else "Manually verify the test account's subscription/plan state and correct it if needed - the automatic rollback could not be confirmed.",
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- ROLE-003 -----------------------------------------------------------

    async def _run_role_003(self, function_map: FunctionMap) -> None:
        routes = function_map.by_category(FunctionCategory.SYSTEM_ADMINISTRATION)
        if not routes:
            await self._emit_role_info(
                test_case_id="ROLE-003-SUMMARY",
                name="System-administration route access check",
                description=(
                    "Verifies every discovered system-administration route rejects the test session's own "
                    "(non-admin) credentials, for GET and every write method."
                ),
                actual="No system-administration routes were found in this run's function map - nothing to verify.",
            )
            return

        sub_results: list[TestResult] = []
        for index, route in enumerate(sorted(routes, key=lambda r: (r.method, r.path)), start=1):
            for method in _SYSTEM_CHECK_METHODS:
                sub_results.append(await self._case_system_route_access(index, route, method))

        await self._emit_role_summary(
            test_case_id="ROLE-003-SUMMARY",
            name="System-administration route access check (summary)",
            description=(
                "Aggregate verdict across every discovered system-administration route and HTTP method checked "
                "(see ROLE-003-* above for full per-request evidence)."
            ),
            sub_results=sub_results,
            fail_text="One or more system-administration routes allowed access to the test session - see per-route findings above.",
            pass_text="Every system-administration route correctly denied the test session across all methods checked.",
        )

    async def _case_system_route_access(self, index: int, route: MappedRoute, method: str) -> TestResult:
        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code in (401, 403):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - access correctly denied to the test session."
            if resp.status_code == 404:
                return (
                    ResultStatus.WARNING,
                    f"HTTP {resp.status_code} - not found on re-verification (Recon's discovery may be stale, "
                    "or this path/method combination differs from what was probed); no access-control finding "
                    "can be drawn from a 404.",
                )
            if resp.status_code is not None and resp.status_code >= 500:
                return (
                    ResultStatus.FAIL,
                    f"HTTP {resp.status_code} - server error instead of a clean 401/403; confirm authentication "
                    "is checked before the request is processed at all.",
                )
            if resp.status_code == 200:
                return (
                    ResultStatus.FAIL,
                    f"HTTP {resp.status_code} - access was ALLOWED to the test session with method {method}. "
                    "Audit finding: this system-administration route does not enforce access control.",
                )
            return ResultStatus.WARNING, f"HTTP {resp.status_code} - ambiguous; not clearly a denial or an allowance."

        return await self.execute_case(
            test_case_id=f"ROLE-003-{index:02d}-{method}-{_slug(route.path)}",
            name=f"System route access control: {method} {route.path}",
            description=(
                "CC6.1 verification on a system-administration route Recon discovered: sends a single request "
                "with the test session's own (non-admin) credentials and checks that it is rejected. No system "
                "change is ever attempted -- write-method probes use an empty body, since the only thing "
                "verified is whether the request is rejected before any body-driven action would occur."
            ),
            method=method,
            path=route.path,
            input_parameters=None if method == "GET" else {},
            expected="HTTP 401 or 403 - access denied.",
            evaluate=evaluate,
            recommendation=(
                "Require and verify admin/elevated-role authorization on this route before it processes any "
                "request, for every HTTP method it accepts."
            ),
            probe_class=NEGATIVE_ACCESS_CONTROL,  # an admin-looking route probed with a CUSTOMER-level session, expecting a rejection
        )
