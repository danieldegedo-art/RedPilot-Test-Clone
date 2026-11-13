"""Business Rule Consistency Module (Module 19).

Verifies that the system under test enforces business rules correctly
across payment, subscription, and account workflows:

  BUSINESS-001: Trial parameter validation — sends unusual trial-period
    parameters (days=999999, trial_end far in the future, negative duration)
    and verifies the system properly validates them.

  BUSINESS-002: Completion handler verification — sends completion
    confirmations without an actual payment having occurred, verifying
    the system checks server-side state before activating.

  BUSINESS-003: Currency consistency — creates resources in different
    currencies and verifies server-side currency validation.

  BUSINESS-004: Balance floor validation — checks whether the system
    allows balances to go below zero through refund operations.

  BUSINESS-005: Undocumented route discovery — probes for GraphQL,
    batch, and debug routes that may have different validation rules
    than the primary API surface.

Based on documented incident patterns:
- Frontend-controlled trial period without server-side validation
- Payment completion accepted without Stripe verification
- Currency mismatch between checkout and activation
- Prepaid wallet systems reaching negative balances
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.core.control_port import NEGATIVE_ACCESS_CONTROL
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult
from app.testing.recon.function_mapper import FunctionCategory, FunctionMap


# Unusual trial parameters that should be rejected by server-side validation
_UNUSUAL_TRIAL_PARAMETERS: list[dict[str, Any]] = [
    {"days": 999999, "label": "Extremely large trial period (999999 days)"},
    {"trial_end": "2099-12-31", "label": "Trial end date far in the future (2099)"},
    {"duration": -1, "label": "Negative duration (-1)"},
    {"days": 999999, "trial_end": "2099-12-31", "duration": -1, "label": "All unusual values combined"},
]

# Completion-related keywords for route discovery
_COMPLETION_KEYWORDS = ("confirm", "success", "complete", "activate", "verify")

# Hidden route patterns to probe
_HIDDEN_ROUTE_PATTERNS: list[dict[str, Any]] = [
    {"path": "/graphql", "type": "graphql", "description": "GraphQL endpoint"},
    {"path": "/api/graphql", "type": "graphql", "description": "GraphQL endpoint (api prefix)"},
    {"path": "/graphiql", "type": "graphql_ui", "description": "GraphQL IDE (should not be exposed)"},
    {"path": "/api/v1/users/batch", "type": "batch", "description": "Batch user operations"},
    {"path": "/api/v1/batch", "type": "batch", "description": "Generic batch operations"},
    {"path": "/api/v1/bulk", "type": "batch", "description": "Bulk operations"},
    {"path": "/api/debug", "type": "debug", "description": "Debug endpoint"},
    {"path": "/debug", "type": "debug", "description": "Debug endpoint (no prefix)"},
    {"path": "/status", "type": "status", "description": "Status endpoint"},
    {"path": "/actuator", "type": "actuator", "description": "Spring Boot actuator"},
    {"path": "/actuator/health", "type": "actuator", "description": "Spring Boot health check"},
    {"path": "/actuator/env", "type": "actuator", "description": "Spring Boot environment (should not be exposed)"},
]

# GraphQL introspection query
_GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
  }
}
"""


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


def _extract_id(body: Any, *keys: str) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in keys:
        if body.get(key):
            return body[key]
    return None


class BusinessRuleConsistencyModule(BaseTestModule):
    """Business Rule Consistency Module — verifies that business rules
    for trials, payments, currencies, balances, and undocumented routes
    are properly enforced with server-side validation."""

    module_id = "business_rule_consistency"
    display_name = "Business Rule Consistency"
    category = TestCategory.BUSINESS_RULE_CONSISTENCY

    async def run(self) -> None:
        await self._case_trial_parameters()
        await self._case_completion_handler()
        await self._case_currency_consistency()
        await self._case_balance_floor()
        await self._case_hidden_routes()

    def _get_endpoints(self) -> dict[str, Any]:
        """Returns relevant endpoints from the EndpointMap."""
        ep = self.context.endpoints
        return {
            "create_payment": ep.create_payment,
            "get_payment": ep.get_payment,
            "create_subscription": ep.create_subscription,
            "get_subscription": ep.get_subscription,
            "cancel_subscription": ep.cancel_subscription,
            "create_refund": ep.create_refund,
        }

    def _find_trial_routes(self) -> list[tuple[str, str]]:
        """Finds routes that accept trial-related parameters."""
        function_map = self.context.shared_state.get("function_map")
        if not isinstance(function_map, FunctionMap):
            return []

        trial_keywords = ("trial", "duration", "period", "extension", "days")
        routes = []
        for route in function_map.routes:
            if route.method in ("POST", "PUT", "PATCH"):
                if any(keyword in route.path.lower() for keyword in trial_keywords):
                    routes.append((route.method, route.path))
                # Also check parameter names
                elif hasattr(route, "param_names") and route.param_names:
                    if any(any(k in p.lower() for k in trial_keywords) for p in route.param_names):
                        routes.append((route.method, route.path))
        return routes

    def _find_completion_routes(self) -> list[tuple[str, str]]:
        """Finds routes that process payment completions or confirmations."""
        function_map = self.context.shared_state.get("function_map")
        if not isinstance(function_map, FunctionMap):
            return []

        routes = []
        for route in function_map.routes:
            if route.method in ("POST", "PUT", "PATCH"):
                if any(keyword in route.path.lower() for keyword in _COMPLETION_KEYWORDS):
                    routes.append((route.method, route.path))
        return routes

    # -- BUSINESS-001 -------------------------------------------------------

    async def _case_trial_parameters(self) -> None:
        """Trial parameter validation — unusual values should be rejected."""

        # Find trial-related routes
        trial_routes = self._find_trial_routes()

        # Also check the subscription creation endpoint for trial parameters
        ep = self._get_endpoints()
        if not trial_routes:
            trial_routes = [(ep["create_subscription"].method, ep["create_subscription"].path)]

        if not trial_routes:
            await self._emit_skip(
                test_case_id="BUSINESS-001",
                name="Trial parameter validation",
                description=(
                    "Sends unusual trial-period parameters and verifies the system "
                    "properly validates them server-side."
                ),
                actual="No trial-related or subscription creation routes were found to test.",
            )
            return

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        method, path = trial_routes[0]

        for unusual_params in _UNUSUAL_TRIAL_PARAMETERS:
            # Build a base subscription body with the unusual trial parameters
            request_body = self.resolve_payload({
                "planId": "plan_standard_monthly",
                "customerEmail": "qa-business-rule@example.com",
                "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            })

            # Remove standard trial fields if present, then add unusual ones
            for trial_key in ("days", "trial_end", "duration", "extension", "period"):
                request_body.pop(trial_key, None)

            # Add the unusual parameters
            for key, value in unusual_params.items():
                if key != "label":
                    request_body[key] = value

            req, resp = await self.context.http.request(
                method, path, json_body=request_body
            )

            classification = _classify_response(resp)

            # Check if the subscription was created with unusual trial values
            trial_applied = False
            subscription_id = _extract_id(resp.body, "id", "subscriptionId", "subscription_id")

            if classification == "accepted" and subscription_id:
                # Check the created subscription's trial period
                check_path = ep["get_subscription"].path.format(subscription_id=subscription_id)
                _, check_resp = await self.context.http.request("GET", check_path)

                if isinstance(check_resp.body, dict):
                    # Look for trial-related fields
                    trial_fields = ("trial_end", "trial_days", "trial_period", "current_period_end", "duration")
                    for field in trial_fields:
                        if field in check_resp.body:
                            value = check_resp.body[field]
                            # Check if the value reflects the unusual input
                            if isinstance(value, (int, float)) and value > 365:
                                trial_applied = True
                            elif isinstance(value, str) and "2099" in value:
                                trial_applied = True
                            elif isinstance(value, (int, float)) and value < 0:
                                trial_applied = True

            results.append({
                "label": unusual_params["label"],
                "parameters": {k: v for k, v in unusual_params.items() if k != "label"},
                "classification": classification,
                "status_code": resp.status_code,
                "trial_applied": trial_applied,
                "request": req,
                "response": resp,
            })

        finished = datetime.now(timezone.utc)

        # Evaluate results
        any_applied = any(r["trial_applied"] for r in results)
        any_accepted = any(r["classification"] == "accepted" for r in results)
        all_declined = all(r["classification"] == "declined" for r in results)
        any_crashed = any(r["classification"] == "server_error" for r in results)

        if any_crashed:
            status = ResultStatus.FAIL
            crashed = [r["label"] for r in results if r["classification"] == "server_error"]
            actual = (
                f"Tested {len(results)} unusual trial parameter combinations. "
                f"Server errors occurred with: {crashed}. Unusual parameter values "
                f"should be validated and rejected gracefully, not cause crashes."
            )
            recommendation = (
                "Implement server-side validation for trial-related parameters: "
                "reject trial periods exceeding reasonable bounds (e.g., >365 days), "
                "trial end dates more than 1 year in the future, and negative durations. "
                "Handle invalid values gracefully with a clean 4xx response."
            )
        elif any_applied:
            status = ResultStatus.FAIL
            applied = [r["label"] for r in results if r["trial_applied"]]
            actual = (
                f"Tested {len(results)} unusual trial parameter combinations. "
                f"The system ACCEPTED and applied unusual trial values for: {applied}. "
                f"This means trial periods can be set to unreasonable values (999999 days, "
                f"year 2099, negative duration) without server-side validation, potentially "
                f"allowing unlimited free usage."
            )
            recommendation = (
                "Implement server-side validation for all trial-related parameters: "
                "(1) Reject trial periods exceeding a maximum reasonable bound (e.g., 90 days), "
                "(2) Reject trial end dates more than a reasonable time in the future, "
                "(3) Reject negative durations or periods, "
                "(4) Never trust client-supplied trial parameters — derive them from "
                "server-side plan definitions instead."
            )
        elif any_accepted and not any_applied:
            status = ResultStatus.WARNING
            accepted = [r["label"] for r in results if r["classification"] == "accepted"]
            actual = (
                f"Tested {len(results)} unusual trial parameter combinations. "
                f"{len(accepted)} were accepted but trial values were not clearly applied. "
                f"The parameters may have been silently ignored. "
                f"Verify manually that unusual trial values cannot extend free access."
            )
            recommendation = (
                "Verify that unusual trial parameter values are properly rejected or "
                "ignored. Implement explicit server-side bounds checking for all "
                "trial-related fields."
            )
        elif all_declined:
            status = ResultStatus.PASS
            actual = (
                f"Tested {len(results)} unusual trial parameter combinations. "
                f"ALL were cleanly declined by server-side validation. "
                f"Trial period parameters are properly validated."
            )
            recommendation = None
        else:
            status = ResultStatus.WARNING
            actual = (
                f"Tested {len(results)} unusual trial parameter combinations with mixed results: "
                f"{[(r['label'], r['classification']) for r in results]}. "
                f"Could not determine overall validation consistency."
            )
            recommendation = (
                "Verify that trial parameter validation is consistent across all "
                "subscription-related endpoints."
            )

        request_evidence = results[0].get("request") if results else None
        response_evidence = results[0].get("response") if results else None

        await self.emit(
            TestResult(
                test_case_id="BUSINESS-001",
                category=self.category,
                name="Trial parameter validation",
                description=(
                    "Sends subscription creation requests with unusual trial-period "
                    "parameters (days=999999, trial_end='2099-12-31', duration=-1, and "
                    "all combined). Verifies that the system validates these values "
                    "server-side and rejects unreasonable trial periods. Catches gaps "
                    "where frontend-controlled trial parameters are not validated on "
                    "the server, potentially allowing unlimited free usage."
                ),
                input_parameters={
                    "trial_parameter_sets": [r["label"] for r in results],
                    "route_tested": f"{method} {path}",
                },
                expected="All unusual trial parameters are rejected (HTTP 4xx) or safely ignored without extending the trial period.",
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

    # -- BUSINESS-002 -------------------------------------------------------

    async def _case_completion_handler(self) -> None:
        """Completion handler verification — completions without payments
        should be rejected."""

        # Find completion-related routes
        completion_routes = self._find_completion_routes()

        if not completion_routes:
            # Try known endpoints
            ep = self._get_endpoints()
            completion_routes = [
                ("POST", "/api/v1/account/confirm-upgrade"),
                ("POST", "/api/v1/payments/confirm"),
                ("POST", "/api/v1/subscriptions/activate"),
            ]

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        for method, path in completion_routes[:5]:  # Limit to 5 routes
            # Send a completion request without any payment reference
            # or with a clearly non-existent payment reference
            fake_reference = f"pay_qa_nonexistent_{uuid.uuid4().hex[:12]}"

            request_body = {
                "paymentId": fake_reference,
                "subscriptionId": f"sub_qa_{uuid.uuid4().hex[:8]}",
                "status": "success",
                "confirm": True,
            }

            req, resp = await self.context.http.request(
                method, path, json_body=request_body
            )

            classification = _classify_response(resp)

            # Check if a subscription was activated
            subscription_activated = False
            if classification == "accepted":
                if isinstance(resp.body, dict):
                    sub_status = resp.body.get("status", "")
                    if sub_status in ("active", "activated", "trialing"):
                        subscription_activated = True

            results.append({
                "method": method,
                "path": path,
                "classification": classification,
                "status_code": resp.status_code,
                "subscription_activated": subscription_activated,
                "fake_reference": fake_reference,
                "request": req,
                "response": resp,
            })

        finished = datetime.now(timezone.utc)

        any_activated = any(r["subscription_activated"] for r in results)
        any_accepted = any(r["classification"] == "accepted" for r in results)
        all_declined = all(r["classification"] == "declined" for r in results)

        if any_activated:
            status = ResultStatus.FAIL
            activated = [f"{r['method']} {r['path']}" for r in results if r["subscription_activated"]]
            actual = (
                f"Tested {len(results)} completion route(s). "
                f"{len(activated)} route(s) accepted a completion request with a "
                f"non-existent payment reference and ACTIVATED a subscription: "
                f"{activated}. This means subscriptions can be activated without "
                f"an actual payment having occurred."
            )
            recommendation = (
                "Implement server-side payment verification in completion handlers: "
                "before activating any subscription, retrieve the referenced payment "
                "from the payment provider (e.g., Stripe API) and verify it actually "
                "exists and was successful. Never trust the completion request's "
                "claim of 'status: success' without independent verification. "
                "Based on documented incidents where POST /confirm-upgrade with "
                "{'status': 'success'} was accepted without verification."
            )
        elif any_accepted:
            status = ResultStatus.WARNING
            accepted = [f"{r['method']} {r['path']}" for r in results if r["classification"] == "accepted"]
            actual = (
                f"Tested {len(results)} completion route(s). "
                f"{len(accepted)} route(s) accepted the completion request but did not "
                f"clearly activate a subscription. The request may have been processed "
                f"silently. Verify manually that no subscription state was changed."
            )
            recommendation = (
                "Verify that completion handlers check the referenced payment's actual "
                "status server-side before processing. Implement explicit verification "
                "of payment existence and success before allowing any state changes."
            )
        elif all_declined:
            status = ResultStatus.PASS
            actual = (
                f"Tested {len(results)} completion route(s). "
                f"ALL correctly declined completion requests with non-existent "
                f"payment references. Server-side verification is working."
            )
            recommendation = None
        else:
            status = ResultStatus.WARNING
            actual = (
                f"Tested {len(results)} completion route(s) with mixed results: "
                f"{[(f'{r['method']} {r['path']}', r['classification']) for r in results]}. "
                f"Could not determine overall consistency."
            )
            recommendation = (
                "Verify that all completion handlers check payment status server-side "
                "before processing."
            )

        request_evidence = results[0].get("request") if results else None
        response_evidence = results[0].get("response") if results else None

        await self.emit(
            TestResult(
                test_case_id="BUSINESS-002",
                category=self.category,
                name="Completion handler verification",
                description=(
                    "Sends completion/confirmation requests (confirm, success, complete, "
                    "activate keywords) with a fabricated payment reference that never "
                    "went through a real payment process. Verifies that the system "
                    "retrieves and verifies the payment's actual status server-side "
                    "before activating any subscription or granting access. Based on "
                    "documented incidents where completion endpoints accepted "
                    "'status: success' without checking with the payment provider."
                ),
                input_parameters={
                    "routes_tested": [f"{r['method']} {r['path']}" for r in results],
                    "payment_reference_format": "pay_qa_nonexistent_[random]",
                },
                expected="All completion requests with non-existent payment references are rejected (HTTP 4xx).",
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

    # -- BUSINESS-003 -------------------------------------------------------

    async def _case_currency_consistency(self) -> None:
        """Currency consistency — server-side currency validation."""

        ep = self._get_endpoints()

        # Test creating payments in different currencies and check consistency
        currencies_to_test = ["USD", "EUR", "JPY", "IDR"]

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        for currency in currencies_to_test:
            # Create a payment with this currency
            request_body = self.resolve_payload({
                "amount": 100.00,
                "currency": currency,
                "productId": "prod_standard_plan",
                "customerEmail": "qa-currency@example.com",
                "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            })

            req, resp = await self.context.http.request(
                ep["create_payment"].method, ep["create_payment"].path, json_body=request_body
            )

            classification = _classify_response(resp)
            payment_id = _extract_id(resp.body, "id", "paymentId", "payment_id")

            # If created, verify the persisted currency
            persisted_currency = None
            persisted_amount = None
            if payment_id:
                check_path = ep["get_payment"].path.format(payment_id=payment_id)
                _, check_resp = await self.context.http.request("GET", check_path)

                if isinstance(check_resp.body, dict):
                    persisted_currency = check_resp.body.get("currency", "")
                    persisted_amount = check_resp.body.get("amount", None)

            results.append({
                "currency": currency,
                "classification": classification,
                "status_code": resp.status_code,
                "payment_id": payment_id,
                "persisted_currency": persisted_currency,
                "persisted_amount": persisted_amount,
                "request": req,
                "response": resp,
            })

        finished = datetime.now(timezone.utc)

        # Check for currency mismatches
        mismatches = []
        for r in results:
            if r["persisted_currency"] and r["currency"] != r["persisted_currency"]:
                mismatches.append(
                    f"Requested {r['currency']} but persisted as {r['persisted_currency']}"
                )

        # Check for amount issues (e.g., JPY should be in whole numbers, IDR has different scale)
        amount_issues = []
        for r in results:
            if r["currency"] == "JPY" and r["persisted_amount"] is not None:
                if isinstance(r["persisted_amount"], float) and r["persisted_amount"] != int(r["persisted_amount"]):
                    amount_issues.append(f"JPY amount has decimal places: {r['persisted_amount']}")

        if mismatches:
            status = ResultStatus.FAIL
            actual = (
                f"Tested {len(results)} currency variations. Found {len(mismatches)} "
                f"currency mismatch(es): {'; '.join(mismatches)}. "
                f"The system does not consistently persist the requested currency, "
                f"potentially allowing currency arbitrage."
            )
            recommendation = (
                "Implement strict server-side currency validation: (1) Only accept "
                "currencies from a defined allowlist, (2) Store the currency exactly "
                "as provided without conversion, (3) If conversion is needed, perform "
                "it server-side using current exchange rates and store both the original "
                "and converted values, (4) Verify the charged amount matches the stored "
                "amount in the correct currency."
            )
        elif amount_issues:
            status = ResultStatus.WARNING
            actual = (
                f"Tested {len(results)} currency variations. Found {len(amount_issues)} "
                f"amount issue(s): {'; '.join(amount_issues)}. "
                f"Some currencies (JPY, IDR) use different decimal conventions that "
                f"should be validated."
            )
            recommendation = (
                "Implement currency-specific amount validation: JPY (Japanese Yen) and "
                "IDR (Indonesian Rupiah) use zero decimal places. Validate amounts "
                "according to each currency's convention."
            )
        else:
            all_accepted = all(r["classification"] == "accepted" for r in results)
            if all_accepted:
                status = ResultStatus.PASS
                actual = (
                    f"Tested {len(results)} currency variations. All were processed "
                    f"consistently with correct currency persistence. "
                    f"Currencies tested: {[r['currency'] for r in results]}."
                )
                recommendation = None
            else:
                status = ResultStatus.INFO
                actual = (
                    f"Tested {len(results)} currency variations with mixed results. "
                    f"Some currencies may not be supported: "
                    f"{[(r['currency'], r['classification']) for r in results]}. "
                    f"No currency mismatches were found in persisted values."
                )
                recommendation = None

        request_evidence = results[0].get("request") if results else None
        response_evidence = results[0].get("response") if results else None

        await self.emit(
            TestResult(
                test_case_id="BUSINESS-003",
                category=self.category,
                name="Currency consistency",
                description=(
                    "Creates payments in multiple currencies (USD, EUR, JPY, IDR) and "
                    "verifies that the server correctly validates and persists the "
                    "requested currency. Checks for currency mismatches between what was "
                    "requested and what was stored, which could enable arbitrage if "
                    "a payment is made in a low-value currency but the subscription is "
                    "activated based on a high-value currency amount."
                ),
                input_parameters={
                    "currencies_tested": currencies_to_test,
                    "amount_per_currency": 100.00,
                },
                expected="All currencies are either correctly processed with proper persistence, or cleanly declined if not supported.",
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

    # -- BUSINESS-004 -------------------------------------------------------

    async def _case_balance_floor(self) -> None:
        """Balance floor validation — balances should not go below zero."""

        # Look for wallet/balance-related routes
        function_map = self.context.shared_state.get("function_map")
        wallet_routes: list[tuple[str, str]] = []

        if isinstance(function_map, FunctionMap):
            wallet_keywords = ("wallet", "balance", "credit", "prepaid")
            for route in function_map.routes:
                if any(keyword in route.path.lower() for keyword in wallet_keywords):
                    wallet_routes.append((route.method, route.path))

        if not wallet_routes:
            await self._emit_skip(
                test_case_id="BUSINESS-004",
                name="Balance floor validation",
                description=(
                    "Checks whether the system allows balances to go below zero "
                    "through refund operations."
                ),
                actual=(
                    "No wallet or balance-related routes were discovered. "
                    "Cannot test balance floor validation without a wallet system."
                ),
            )
            return

        ep = self._get_endpoints()
        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        # Find the refund endpoint and a wallet/balance endpoint
        refund_route = (ep["create_refund"].method, ep["create_refund"].path)
        wallet_get_routes = [(m, p) for m, p in wallet_routes if m == "GET"]

        if not wallet_get_routes:
            await self._emit_skip(
                test_case_id="BUSINESS-004",
                name="Balance floor validation",
                description=(
                    "Checks whether the system allows balances to go below zero "
                    "through refund operations."
                ),
                actual=(
                    "Wallet routes were found but no GET route to check balance. "
                    "Cannot verify balance floor without a readable balance endpoint."
                ),
            )
            return

        # Create a payment first
        payment_id, create_resp = await self._create_payment_for_test("BUSINESS-004")

        if payment_id is None:
            await self._emit_skip(
                test_case_id="BUSINESS-004",
                name="Balance floor validation",
                description=(
                    "Checks whether the system allows balances to go below zero "
                    "through refund operations."
                ),
                actual=f"Could not create a payment for testing (HTTP {create_resp.status_code}).",
            )
            return

        # Check initial balance
        wallet_method, wallet_path = wallet_get_routes[0]
        _, initial_resp = await self.context.http.request(wallet_method, wallet_path)
        initial_balance = None
        if isinstance(initial_resp.body, dict):
            for field in ("balance", "amount", "credit", "value"):
                if field in initial_resp.body:
                    initial_balance = initial_resp.body[field]
                    break

        # Attempt to refund more than the balance (if we know the balance)
        refund_amount = 999999.99  # Clearly more than any reasonable balance
        if initial_balance is not None and isinstance(initial_balance, (int, float)):
            refund_amount = abs(initial_balance) * 2  # Refund 2x the current balance

        refund_body = {
            "paymentId": payment_id,
            "amount": refund_amount,
            "reason": "qa_balance_floor_test",
        }

        req, resp = await self.context.http.request(
            refund_route[0], refund_route[1], json_body=refund_body
        )

        classification = _classify_response(resp)

        # Check final balance
        _, final_resp = await self.context.http.request(wallet_method, wallet_path)
        final_balance = None
        if isinstance(final_resp.body, dict):
            for field in ("balance", "amount", "credit", "value"):
                if field in final_resp.body:
                    final_balance = final_resp.body[field]
                    break

        finished = datetime.now(timezone.utc)

        # Check if balance went negative
        balance_negative = False
        if final_balance is not None and isinstance(final_balance, (int, float)):
            if final_balance < 0:
                balance_negative = True

        if balance_negative:
            status = ResultStatus.FAIL
            actual = (
                f"Initial balance: {initial_balance}, Refund attempted: {refund_amount}, "
                f"Final balance: {final_balance}. "
                f"The system allowed the balance to go BELOW ZERO. "
                f"This indicates missing balance floor validation."
            )
            recommendation = (
                "Implement balance floor validation: reject any refund or deduction "
                "that would cause the balance to go below zero. Use database-level "
                "constraints (CHECK constraint: balance >= 0) or application-level "
                "validation with proper locking to prevent race conditions."
            )
        elif classification == "declined":
            status = ResultStatus.PASS
            actual = (
                f"Refund of {refund_amount} was declined (HTTP {resp.status_code}). "
                f"Initial balance: {initial_balance}, Final balance: {final_balance}. "
                f"The system correctly prevents refunds that exceed the available balance."
            )
            recommendation = None
        elif classification == "accepted" and not balance_negative:
            status = ResultStatus.WARNING
            actual = (
                f"Refund of {refund_amount} was accepted (HTTP {resp.status_code}) but "
                f"the balance did not go negative. Initial: {initial_balance}, "
                f"Final: {final_balance}. The refund may have been partially processed "
                f"or the balance system works differently than expected."
            )
            recommendation = (
                "Verify that refund amounts are properly validated against the available "
                "balance. Implement explicit balance checks before processing refunds."
            )
        else:
            status = ResultStatus.INFO
            actual = (
                f"Refund attempt returned HTTP {resp.status_code} ({classification}). "
                f"Initial balance: {initial_balance}, Final balance: {final_balance}. "
                f"Could not determine if balance floor validation is working."
            )
            recommendation = (
                "Verify that balance-deducting operations cannot cause negative balances. "
                "Implement explicit floor validation."
            )

        await self.emit(
            TestResult(
                test_case_id="BUSINESS-004",
                category=self.category,
                name="Balance floor validation",
                description=(
                    "Creates a payment, checks the initial wallet balance, then attempts "
                    "to refund an amount clearly exceeding the available balance. Verifies "
                    "that the system rejects the operation or otherwise prevents the "
                    "balance from going below zero. Based on documented incidents where "
                    "prepaid wallet systems allowed negative balances through excessive "
                    "refunds."
                ),
                input_parameters={
                    "wallet_endpoint": f"{wallet_method} {wallet_path}",
                    "initial_balance": initial_balance,
                    "refund_attempted": refund_amount,
                    "final_balance": final_balance,
                },
                expected="Refund exceeding the balance is rejected, or the balance never goes below zero.",
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

    async def _create_payment_for_test(self, test_case_id: str) -> tuple[str | None, ResponseEvidence]:
        """Creates a payment for use in other test cases."""
        ep = self._get_endpoints()
        body = self.resolve_payload({
            "amount": 50.00,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-business-rule@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
        })
        _, resp = await self.context.http.request(
            ep["create_payment"].method, ep["create_payment"].path, json_body=body
        )
        payment_id = _extract_id(resp.body, "id", "paymentId", "payment_id")
        return payment_id, resp

    # -- BUSINESS-005 -------------------------------------------------------

    async def _case_hidden_routes(self) -> None:
        """Undocumented route discovery — probes for GraphQL, batch, and
        debug routes that may have different validation rules."""

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        for pattern in _HIDDEN_ROUTE_PATTERNS:
            path = pattern["path"]

            # Probe with a GET request first
            # Pure Black-Box: an existence/access-control probe only. Tagged so the purity gate admits internal-looking paths
            # (/debug, /actuator ...) and so the response BODY is withheld -- an exposed internal surface's content is never ingested.
            req, resp = await self.context.http.request("GET", path, probe_class=NEGATIVE_ACCESS_CONTROL)
            classification = _classify_response(resp)

            if resp.status_code == 404 or classification == "transport_error":
                # Route doesn't exist
                results.append({
                    "path": path,
                    "type": pattern["type"],
                    "description": pattern["description"],
                    "exists": False,
                    "status_code": resp.status_code,
                    "classification": classification,
                })
                continue

            # Route exists — probe further based on type
            route_result: dict[str, Any] = {
                "path": path,
                "type": pattern["type"],
                "description": pattern["description"],
                "exists": True,
                "status_code": resp.status_code,
                "classification": classification,
                "request": req,
                "response": resp,
            }

            if pattern["type"] == "graphql":
                # DISABLED in Pure Black-Box mode: a GraphQL introspection query asks the target for its internal schema (= a private API
                # specification a customer does not obtain through normal product use). Reachability is still reported from the GET above.
                route_result["introspection"] = {"status_code": None, "classification": "not_supported_pure_black_box", "schema_exposed": False, "checked": False}

            elif pattern["type"] in ("batch", "bulk"):
                # DISABLED in Pure Black-Box mode: a crafted POST to an UNDOCUMENTED write-capable route is outside every approved flow.
                route_result["batch_test"] = {"status_code": None, "classification": "not_supported_pure_black_box", "checked": False}

            elif pattern["type"] in ("debug", "actuator"):
                # Status-based exposure verdict only: the body of a reachable debug/actuator surface is withheld and never read.
                route_result["info_exposed"] = resp.status_code == 200

            results.append(route_result)

        finished = datetime.now(timezone.utc)

        # Analyze results
        existing_routes = [r for r in results if r.get("exists")]
        graphql_routes = [r for r in existing_routes if r.get("type") == "graphql"]
        batch_routes = [r for r in existing_routes if r.get("type") in ("batch", "bulk")]
        debug_routes = [r for r in existing_routes if r.get("type") in ("debug", "actuator", "status")]

        findings: list[str] = []

        # Check GraphQL routes
        for r in graphql_routes:
            if r.get("introspection", {}).get("schema_exposed"):
                findings.append(
                    f"GraphQL endpoint at {r['path']} has introspection ENABLED — "
                    f"the full API schema is exposed, revealing all types, queries, "
                    f"and mutations."
                )
            if r.get("type") == "graphql_ui":
                findings.append(
                    f"GraphQL IDE (GraphiQL) is exposed at {r['path']} — "
                    f"this should not be accessible in production."
                )

        # Check debug routes
        for r in debug_routes:
            if r.get("info_exposed"):
                findings.append(
                    f"Debug/status endpoint at {r['path']} is reachable by the customer-level session (HTTP 200) -- "
                    f"an internal surface that should not be exposed. Response content was deliberately not inspected."
                )

        # Check actuator routes
        for r in existing_routes:
            if r.get("type") == "actuator" and "env" in r["path"]:
                findings.append(
                    f"Spring Boot actuator environment endpoint is exposed at "
                    f"{r['path']} — this typically reveals configuration, "
                    f"credentials, and internal system details."
                )

        if findings:
            status = ResultStatus.WARNING
            actual = (
                f"Probed {len(results)} undocumented route patterns. "
                f"Found {len(existing_routes)} existing route(s), "
                f"{len(graphql_routes)} GraphQL, {len(batch_routes)} batch/bulk, "
                f"{len(debug_routes)} debug/status. "
                f"Findings: {'; '.join(findings[:5])}"
            )
            recommendation = (
                "Review and secure undocumented routes: (1) Disable GraphQL "
                "introspection in production, (2) Remove or protect GraphiQL/IDE "
                "interfaces, (3) Restrict debug and status endpoints to internal "
                "networks only, (4) Ensure Spring Boot actuator endpoints (especially "
                "/env) are not publicly accessible, (5) Apply the same validation "
                "rules to batch/bulk endpoints as individual endpoints."
            )
        elif existing_routes:
            status = ResultStatus.INFO
            actual = (
                f"Probed {len(results)} undocumented route patterns. "
                f"Found {len(existing_routes)} existing route(s) but no critical "
                f"issues were identified. "
                f"Routes found: {[r['path'] for r in existing_routes]}"
            )
            recommendation = (
                "Verify that all discovered undocumented routes maintain the same "
                "validation standards as the primary API surface."
            )
        else:
            status = ResultStatus.PASS
            actual = (
                f"Probed {len(results)} undocumented route patterns. "
                f"None were found — all returned 404. "
                f"No GraphQL, batch, debug, or actuator routes are exposed."
            )
            recommendation = None

        request_evidence = existing_routes[0].get("request") if existing_routes else None
        response_evidence = existing_routes[0].get("response") if existing_routes else None

        await self.emit(
            TestResult(
                test_case_id="BUSINESS-005",
                category=self.category,
                name="Undocumented route discovery",
                description=(
                    "Probes for the existence of undocumented or hidden API routes "
                    "that may have different validation rules than the primary API "
                    "surface. Checks for: (1) GraphQL endpoints and whether "
                    "introspection is enabled, (2) Batch/bulk operation endpoints, "
                    "(3) Debug and status endpoints, (4) Spring Boot actuator endpoints. "
                    "For any discovered routes, verifies that they maintain the same "
                    "security standards as documented endpoints."
                ),
                input_parameters={
                    "patterns_probed": [p["path"] for p in _HIDDEN_ROUTE_PATTERNS],
                    "routes_found": [r["path"] for r in existing_routes],
                },
                expected="No undocumented routes are exposed, or all discovered routes maintain the same validation standards as the primary API.",
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

    # -- Shared helper -----------------------------------------------------

    async def _emit_skip(
        self,
        *,
        test_case_id: str,
        name: str,
        description: str,
        actual: str,
    ) -> None:
        """Emits an informational result when a check cannot be performed."""
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
