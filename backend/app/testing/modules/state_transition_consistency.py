"""State Transition Consistency Module (Module 15).

Verifies that the system under test maintains consistent state
transitions across all payment and subscription resources:

  STATE-001: Concurrent transition check — sends parallel requests that
    would both attempt to modify the same resource's state simultaneously,
    checking whether the system handles this safely (only one succeeds)
    or allows both to proceed (leading to inconsistent state).

  STATE-002: Unusual state transition check — attempts transitions that
    should not be allowed by business logic (e.g., from a terminal state
    back to an active state). Verifies the system rejects these.

  STATE-003: Cross-endpoint state consistency — reads the same resource's
    status from multiple endpoints (v1, v2, /me, /billing, etc.) and
    checks they all report the same state.

  STATE-004: Refund-to-subscription synchronization — after processing a
    refund, checks whether the associated subscription is correctly
    updated or deactivated, verifying cross-system state consistency.

Based on documented incident patterns:
- Parallel processing without proper locking (Industry Reports)
- Asynchronous systems not properly synchronized (BreachVex Industry Report)
"""
from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.lifecycle_model import (
    ACTIVE_LOOKING_STATES,
    CANCELLED_LOOKING_STATES,
    TERMINAL_PAYMENT_STATES,
    TERMINAL_SUBSCRIPTION_STATES,
    VALID_PAYMENT_TRANSITIONS,
    VALID_SUBSCRIPTION_TRANSITIONS,
)
from app.testing.lifecycle_model import is_terminal_state as _is_terminal_state
from app.testing.lifecycle_model import is_valid_transition as _is_valid_transition
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult
from app.testing.recon.function_mapper import FunctionCategory, FunctionMap

# The state tables and is_terminal_state()/is_valid_transition() used to be
# defined inline here. They now live in app.testing.lifecycle_model (a
# dependency-free leaf module state_exploration.py's exhaustive graph
# analysis also imports from, without needing httpx/pydantic to be
# installed) and are re-exported above under their original names, so
# every reference below -- and anything importing them FROM this module --
# keeps working unchanged. Same tables, same semantics, same
# case-insensitive lookups; only the location moved.


def _extract_id(body: Any, *keys: str) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in keys:
        if body.get(key):
            return body[key]
    return None


def _find_status_field(body: Any) -> tuple[str, str] | None:
    """Finds a status-like field in a response body."""
    if not isinstance(body, dict):
        return None
    status_keys = ("status", "subscription_status", "subscriptionStatus", "plan_status", "planStatus", "state")
    for key in status_keys:
        value = body.get(key)
        if isinstance(value, str) and value:
            return key, value.lower()
    return None


class StateTransitionConsistencyModule(BaseTestModule):
    """State Transition Consistency Module — verifies that state
    transitions are handled safely and consistently across all
    payment and subscription resources."""

    module_id = "state_transition_consistency"
    display_name = "State Transition Consistency"
    category = TestCategory.STATE_TRANSITION_CONSISTENCY

    async def run(self) -> None:
        await self._case_concurrent_transitions()
        await self._case_unusual_transitions()
        await self._case_cross_endpoint_consistency()
        await self._case_refund_subscription_sync()

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

    def _build_payment_request_body(self, test_case_id: str, amount: float = 25.00) -> dict[str, Any]:
        """Builds a valid payment creation request body."""
        return self.resolve_payload({
            "amount": amount,
            "currency": "USD",
            "productId": "prod_standard_plan",
            "customerEmail": "qa-state-transition@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "metadata": {"qa_test_case": test_case_id},
        })

    async def _create_payment(self, test_case_id: str, amount: float = 25.00) -> tuple[str | None, ResponseEvidence]:
        """Creates a payment and returns (payment_id, response)."""
        ep = self._get_endpoints()
        body = self._build_payment_request_body(test_case_id, amount)
        _, resp = await self.context.http.request(
            ep["create_payment"].method, ep["create_payment"].path, json_body=body
        )
        payment_id = _extract_id(resp.body, "id", "paymentId", "payment_id")
        return payment_id, resp

    # -- STATE-001 ---------------------------------------------------------

    async def _case_concurrent_transitions(self) -> None:
        """Concurrent modification of the same resource should be handled
        safely (only one succeeds, the other is properly rejected)."""
        ep = self._get_endpoints()

        # Create a payment first
        payment_id, create_resp = await self._create_payment("STATE-001")
        if payment_id is None:
            await self._emit_skip(
                test_case_id="STATE-001",
                name="Concurrent transition handling",
                description=(
                    "Sends parallel requests that both attempt to modify the same "
                    "resource's state, checking whether concurrent processing is handled safely."
                ),
                actual=(
                    f"Could not create a payment for testing (HTTP {create_resp.status_code}). "
                    "Concurrent transition checks require a valid payment resource."
                ),
            )
            return

        # Now send two concurrent requests to modify the same payment
        # (e.g., both attempting to cancel it)
        cancel_path = f"/api/v1/payments/{payment_id}/cancel"
        refund_path = ep["create_refund"].path

        cancel_body = {"reason": "qa_concurrent_test"}
        refund_body = {"paymentId": payment_id, "reason": "qa_concurrent_test", "amount": 25.00}

        started = datetime.now(timezone.utc)

        # Send both requests in parallel using asyncio.gather
        cancel_task = self.context.http.request("POST", cancel_path, json_body=cancel_body)
        refund_task = self.context.http.request(ep["create_refund"].method, refund_path, json_body=refund_body)

        responses = await asyncio.gather(cancel_task, refund_task, return_exceptions=True)
        finished = datetime.now(timezone.utc)

        # Process results
        results = []
        for i, result in enumerate(responses):
            if isinstance(result, Exception):
                results.append(("error", None, str(result)))
            else:
                req, resp = result
                status_code = resp.status_code
                if status_code is None:
                    results.append(("error", None, resp.error))
                elif 200 <= status_code < 300:
                    results.append(("accepted", status_code, None))
                elif 400 <= status_code < 500:
                    results.append(("declined", status_code, None))
                elif status_code >= 500:
                    results.append(("server_error", status_code, None))
                else:
                    results.append(("unclear", status_code, None))

        # Check the final state of the payment
        _, final_resp = await self.context.http.request(
            ep["get_payment"].method, ep["get_payment"].path.format(payment_id=payment_id)
        )
        final_status = None
        if isinstance(final_resp.body, dict):
            final_status = final_resp.body.get("status", "")

        # Evaluate
        accepted_count = sum(1 for r in results if r[0] == "accepted")
        error_count = sum(1 for r in results if r[0] in ("error", "server_error"))

        if error_count > 0:
            status = ResultStatus.ERROR
            actual = (
                f"One or both concurrent requests resulted in errors. "
                f"Cancel: {results[0][0]} ({results[0][2] or results[0][1]}), "
                f"Refund: {results[1][0]} ({results[1][2] or results[1][1]}). "
                f"Final payment status: '{final_status}'."
            )
        elif accepted_count == 0:
            status = ResultStatus.INFO
            actual = (
                f"Both concurrent requests were declined. "
                f"Cancel: HTTP {results[0][1]}, Refund: HTTP {results[1][1]}. "
                f"Final payment status: '{final_status}'. This may indicate "
                "the payment was not in a state that allows either operation."
            )
        elif accepted_count == 1:
            status = ResultStatus.PASS
            actual = (
                f"Only one of the two concurrent requests succeeded. "
                f"Cancel: {results[0][0]} (HTTP {results[0][1]}), "
                f"Refund: {results[1][0]} (HTTP {results[1][1]}). "
                f"Final payment status: '{final_status}'. "
                "Concurrent modification was handled safely — only one operation was processed."
            )
        elif accepted_count == 2:
            # Both succeeded — check if the final state is consistent
            if final_status and _is_terminal_state(final_status):
                status = ResultStatus.WARNING
                actual = (
                    f"Both concurrent requests were accepted. "
                    f"Cancel: HTTP {results[0][1]}, Refund: HTTP {results[1][1]}. "
                    f"Final payment status: '{final_status}' — this is a terminal state, so "
                    "the outcome may be safe, but concurrent processing without proper locking "
                    "should be reviewed."
                )
            else:
                status = ResultStatus.FAIL
                actual = (
                    f"Both concurrent requests were accepted. "
                    f"Cancel: HTTP {results[0][1]}, Refund: HTTP {results[1][1]}. "
                    f"Final payment status: '{final_status}' — the system allowed both a cancel "
                    "and a refund to process simultaneously on the same resource. This indicates "
                    "missing concurrent processing safeguards."
                )
        else:
            status = ResultStatus.WARNING
            actual = f"Unexpected concurrent result pattern: {results}. Final status: '{final_status}'."

        await self.emit(
            TestResult(
                test_case_id="STATE-001",
                category=self.category,
                name="Concurrent state transition handling",
                description=(
                    "Creates a payment, then sends two concurrent requests that both attempt to "
                    "modify the payment's state (one cancel, one refund). Verifies that the system "
                    "handles concurrent processing safely — at most one operation should succeed, "
                    "or the final state should be unambiguously consistent."
                ),
                input_parameters={
                    "payment_id": payment_id,
                    "concurrent_operations": ["cancel", "refund"],
                },
                expected="Only one concurrent operation succeeds, or the final state is unambiguously consistent.",
                actual=actual,
                status=status,
                recommendation=None if status == ResultStatus.PASS else (
                    "Implement proper locking or atomic operations for state-modifying endpoints. "
                    "Use database-level row locking (SELECT FOR UPDATE) or optimistic concurrency "
                    "control to prevent multiple concurrent modifications of the same resource."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- STATE-002 ---------------------------------------------------------

    async def _case_unusual_transitions(self) -> None:
        """Attempts transitions from terminal states that should be rejected."""
        ep = self._get_endpoints()

        # Define the unusual transitions to test
        # Each tuple: (description, setup_function, attempt_function)
        unusual_transitions = [
            {
                "name": "Cancelled subscription to active",
                "description": "Attempts to reactivate a cancelled subscription.",
                "setup": self._create_and_cancel_subscription,
                "attempt": self._attempt_reactivation,
                "from_state": "cancelled",
                "to_state": "active",
                "resource_type": "subscription",
            },
            {
                "name": "Refunded payment to captured",
                "description": "Attempts to re-capture an already refunded payment.",
                "setup": self._create_and_refund_payment,
                "attempt": self._attempt_recapture,
                "from_state": "refunded",
                "to_state": "captured",
                "resource_type": "payment",
            },
        ]

        for i, transition in enumerate(unusual_transitions, start=1):
            test_case_id = f"STATE-002-{i:02d}"
            await self._run_unusual_transition_check(test_case_id, transition)

    async def _run_unusual_transition_check(self, test_case_id: str, transition: dict) -> None:
        """Runs a single unusual transition check."""
        started = datetime.now(timezone.utc)

        # Setup: create the resource in the 'from' state
        resource_id, setup_resp = await transition["setup"]()

        if resource_id is None:
            await self._emit_skip(
                test_case_id=test_case_id,
                name=transition["name"],
                description=transition["description"],
                actual=(
                    f"Could not set up the test resource (HTTP {setup_resp.status_code}). "
                    f"Verification of unusual transitions requires a resource in the '{transition['from_state']}' state."
                ),
            )
            return

        # Attempt the transition
        req, resp = await transition["attempt"](resource_id)
        finished = datetime.now(timezone.utc)

        classification = "unclear"
        if resp.status_code is None:
            classification = "transport_error"
        elif 400 <= resp.status_code < 500:
            classification = "declined"
        elif resp.status_code >= 500:
            classification = "server_error"
        elif 200 <= resp.status_code < 300:
            classification = "accepted"

        # Check if the state actually changed
        state_changed = False
        new_state = None
        if transition["resource_type"] == "subscription":
            _, check_resp = await self.context.http.request(
                "GET", f"/api/v1/subscriptions/{resource_id}"
            )
            if isinstance(check_resp.body, dict):
                new_state = check_resp.body.get("status", "")
                state_changed = new_state.lower() not in CANCELLED_LOOKING_STATES
        else:
            _, check_resp = await self.context.http.request(
                "GET", f"/api/v1/payments/{resource_id}"
            )
            if isinstance(check_resp.body, dict):
                new_state = check_resp.body.get("status", "")
                state_changed = new_state.lower() not in ("refunded", "cancelled")

        if classification == "transport_error":
            status = ResultStatus.ERROR
            actual = f"Transport error during transition attempt: {resp.error}"
        elif classification == "server_error":
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — the system crashed while attempting an unusual "
                f"transition from '{transition['from_state']}' to '{transition['to_state']}'. "
                "This should be handled gracefully with a clean 4xx response."
            )
        elif classification == "declined":
            status = ResultStatus.PASS
            actual = (
                f"HTTP {resp.status_code} — the system correctly declined the transition "
                f"from '{transition['from_state']}' to '{transition['to_state']}'. "
                f"Final state remains: '{new_state or transition['from_state']}'."
            )
        elif classification == "accepted" and state_changed:
            status = ResultStatus.FAIL
            actual = (
                f"HTTP {resp.status_code} — the system accepted the unusual transition "
                f"from '{transition['from_state']}' to '{transition['to_state']}'. "
                f"The resource's state actually changed to '{new_state}'. "
                "This indicates missing state transition validation."
            )
        elif classification == "accepted" and not state_changed:
            status = ResultStatus.WARNING
            actual = (
                f"HTTP {resp.status_code} — the request was accepted but the state "
                f"did not actually change (remains '{new_state}'). "
                "The transition may have been silently ignored."
            )
        else:
            status = ResultStatus.WARNING
            actual = f"HTTP {resp.status_code} ({classification}) — could not determine outcome."

        await self.emit(
            TestResult(
                test_case_id=test_case_id,
                category=self.category,
                name=transition["name"],
                description=transition["description"],
                input_parameters={"resource_id": resource_id},
                expected=f"HTTP 4xx — transition from '{transition['from_state']}' to '{transition['to_state']}' is declined.",
                actual=actual,
                status=status,
                request=req,
                response=resp,
                recommendation=None if status == ResultStatus.PASS else (
                    f"Implement state transition validation: reject any attempt to change "
                    f"a resource from a terminal state ('{transition['from_state']}') to any "
                    f"other state. Use a state machine model to define valid transitions "
                    f"and enforce them at the API layer."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- STATE-002 Helper Functions -----------------------------------------

    async def _create_and_cancel_subscription(self) -> tuple[str | None, ResponseEvidence]:
        """Creates a subscription, cancels it, and returns the subscription ID."""
        ep = self._get_endpoints()
        body = self.resolve_payload({
            "planId": "plan_standard_monthly",
            "customerEmail": "qa-state-transition@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
        })

        _, create_resp = await self.context.http.request(
            ep["create_subscription"].method, ep["create_subscription"].path, json_body=body
        )
        subscription_id = _extract_id(create_resp.body, "id", "subscriptionId", "subscription_id")

        if subscription_id is None:
            return None, create_resp

        # Cancel the subscription
        cancel_path = ep["cancel_subscription"].path.format(subscription_id=subscription_id)
        _, cancel_resp = await self.context.http.request(
            ep["cancel_subscription"].method, cancel_path
        )

        return subscription_id, cancel_resp

    async def _attempt_reactivation(self, subscription_id: str) -> tuple[RequestEvidence, ResponseEvidence]:
        """Attempts to reactivate a cancelled subscription."""
        # Try to update the subscription status back to active
        update_path = f"/api/v1/subscriptions/{subscription_id}"
        update_body = {"status": "active"}
        return await self.context.http.request("PATCH", update_path, json_body=update_body)

    async def _create_and_refund_payment(self) -> tuple[str | None, ResponseEvidence]:
        """Creates a payment, refunds it, and returns the payment ID."""
        ep = self._get_endpoints()

        payment_id, create_resp = await self._create_payment("STATE-002-refund")
        if payment_id is None:
            return None, create_resp

        # Refund the payment
        refund_body = {"paymentId": payment_id, "reason": "qa_state_transition_test"}
        _, refund_resp = await self.context.http.request(
            ep["create_refund"].method, ep["create_refund"].path, json_body=refund_body
        )

        return payment_id, refund_resp

    async def _attempt_recapture(self, payment_id: str) -> tuple[RequestEvidence, ResponseEvidence]:
        """Attempts to re-capture an already refunded payment."""
        capture_path = f"/api/v1/payments/{payment_id}/capture"
        return await self.context.http.request("POST", capture_path, json_body={})

    # -- STATE-003 ---------------------------------------------------------

    async def _case_cross_endpoint_consistency(self) -> None:
        """Reads the same resource's status from multiple endpoints and
        checks they all report the same state."""
        ep = self._get_endpoints()

        # Create a subscription to test with
        body = self.resolve_payload({
            "planId": "plan_standard_monthly",
            "customerEmail": "qa-state-transition@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
        })

        _, create_resp = await self.context.http.request(
            ep["create_subscription"].method, ep["create_subscription"].path, json_body=body
        )
        subscription_id = _extract_id(create_resp.body, "id", "subscriptionId", "subscription_id")

        if subscription_id is None:
            await self._emit_skip(
                test_case_id="STATE-003",
                name="Cross-endpoint state consistency",
                description=(
                    "Reads the same resource's status from multiple endpoints and checks "
                    "they all report the same state."
                ),
                actual=f"Could not create a subscription for testing (HTTP {create_resp.status_code}).",
            )
            return

        # Cancel the subscription so we have a known state
        cancel_path = ep["cancel_subscription"].path.format(subscription_id=subscription_id)
        await self.context.http.request(ep["cancel_subscription"].method, cancel_path)

        # Now read from multiple endpoints
        started = datetime.now(timezone.utc)

        # Collect all endpoints that might report subscription status
        status_reports: dict[str, tuple[str | None, str]] = {}

        # 1. Primary get_subscription endpoint
        _, resp = await self.context.http.request(
            ep["get_subscription"].method,
            ep["get_subscription"].path.format(subscription_id=subscription_id),
        )
        if isinstance(resp.body, dict):
            field = _find_status_field(resp.body)
            if field:
                status_reports["get_subscription"] = (field[0], field[1])

        # 2. Account/profile endpoints (if discovered by Recon)
        function_map = self.context.shared_state.get("function_map")
        if isinstance(function_map, FunctionMap):
            account_routes = [
                r for r in function_map.by_category(FunctionCategory.ACCOUNT_MANAGEMENT)
                if r.method == "GET"
            ]
            for route in account_routes[:5]:  # Limit to 5 additional routes
                if "subscription" in route.path.lower() or "billing" in route.path.lower():
                    _, resp = await self.context.http.request(route.method, route.path)
                    if isinstance(resp.body, dict):
                        field = _find_status_field(resp.body)
                        if field:
                            status_reports[route.path] = (field[0], field[1])

        finished = datetime.now(timezone.utc)

        if len(status_reports) < 2:
            await self._emit_skip(
                test_case_id="STATE-003",
                name="Cross-endpoint state consistency",
                description=(
                    "Reads the same resource's status from multiple endpoints and checks "
                    "they all report the same state."
                ),
                actual=(
                    f"Only {len(status_reports)} endpoint(s) reported subscription status. "
                    "Need at least 2 to check for inconsistencies. "
                    f"Endpoints checked: {list(status_reports.keys())}"
                ),
            )
            return

        # Check consistency
        statuses = [s for _, s in status_reports.values()]
        all_consistent = len(set(statuses)) == 1

        if all_consistent:
            status = ResultStatus.PASS
            actual = (
                f"All {len(status_reports)} endpoint(s) report the same status: "
                f"'{statuses[0]}'. Cross-endpoint consistency is maintained."
            )
        else:
            # Check if any endpoint reports an active state when it should be cancelled
            has_active = any(s in ACTIVE_LOOKING_STATES for s in statuses)
            has_cancelled = any(s in CANCELLED_LOOKING_STATES for s in statuses)

            if has_active and has_cancelled:
                status = ResultStatus.FAIL
                actual = (
                    f"Endpoints report inconsistent states: {dict(status_reports)}. "
                    f"Some report active-looking states while others report cancelled-looking states. "
                    "This indicates a data synchronization issue across read paths."
                )
            else:
                status = ResultStatus.WARNING
                actual = (
                    f"Endpoints report different states: {dict(status_reports)}. "
                    "While none clearly contradict (active vs cancelled), the inconsistency "
                    "should be investigated."
                )

        await self.emit(
            TestResult(
                test_case_id="STATE-003",
                category=self.category,
                name="Cross-endpoint state consistency",
                description=(
                    "Creates and cancels a subscription, then reads its status from multiple "
                    "endpoints (primary subscription endpoint, account endpoints, billing endpoints) "
                    "to verify they all report the same state. Catches stale caches or "
                    "denormalized data that different read paths may not properly update."
                ),
                input_parameters={
                    "subscription_id": subscription_id,
                    "endpoints_checked": list(status_reports.keys()),
                },
                expected="All endpoints that report this subscription's status agree it is cancelled.",
                actual=actual,
                status=status,
                recommendation=None if status == ResultStatus.PASS else (
                    "Ensure all read paths for subscription status query the same source of truth. "
                    "If using caches or denormalized copies, implement proper invalidation when "
                    "the primary state changes. Consider using database transactions to ensure "
                    "atomic updates across all materialized views."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- STATE-004 ---------------------------------------------------------

    async def _case_refund_subscription_sync(self) -> None:
        """After processing a refund, checks whether the associated
        subscription is correctly updated or deactivated."""
        ep = self._get_endpoints()

        # Create a payment first
        payment_id, create_resp = await self._create_payment("STATE-004")
        if payment_id is None:
            await self._emit_skip(
                test_case_id="STATE-004",
                name="Refund-to-subscription synchronization",
                description=(
                    "After processing a refund, checks whether the associated subscription "
                    "is correctly updated or deactivated."
                ),
                actual=f"Could not create a payment for testing (HTTP {create_resp.status_code}).",
            )
            return

        # Create a subscription linked to this payment
        sub_body = self.resolve_payload({
            "planId": "plan_standard_monthly",
            "customerEmail": "qa-state-transition@example.com",
            "paymentMethod": {"type": "card", "token": "tok_test_visa_valid"},
            "paymentId": payment_id,
        })

        _, sub_resp = await self.context.http.request(
            ep["create_subscription"].method, ep["create_subscription"].path, json_body=sub_body
        )
        subscription_id = _extract_id(sub_resp.body, "id", "subscriptionId", "subscription_id")

        if subscription_id is None:
            await self._emit_skip(
                test_case_id="STATE-004",
                name="Refund-to-subscription synchronization",
                description=(
                    "After processing a refund, checks whether the associated subscription "
                    "is correctly updated or deactivated."
                ),
                actual=f"Could not create a subscription linked to the payment (HTTP {sub_resp.status_code}).",
            )
            return

        # Process a refund for the payment
        refund_body = {"paymentId": payment_id, "reason": "qa_state_sync_test"}
        started = datetime.now(timezone.utc)
        _, refund_resp = await self.context.http.request(
            ep["create_refund"].method, ep["create_refund"].path, json_body=refund_body
        )
        finished = datetime.now(timezone.utc)

        if refund_resp.error is not None:
            await self._emit_skip(
                test_case_id="STATE-004",
                name="Refund-to-subscription synchronization",
                description=(
                    "After processing a refund, checks whether the associated subscription "
                    "is correctly updated or deactivated."
                ),
                actual=f"Transport error processing refund: {refund_resp.error}",
            )
            return

        if refund_resp.status_code not in (200, 201):
            await self._emit_skip(
                test_case_id="STATE-004",
                name="Refund-to-subscription synchronization",
                description=(
                    "After processing a refund, checks whether the associated subscription "
                    "is correctly updated or deactivated."
                ),
                actual=f"Refund was not successfully processed (HTTP {refund_resp.status_code}).",
            )
            return

        # Now check the subscription status
        _, sub_check_resp = await self.context.http.request(
            ep["get_subscription"].method,
            ep["get_subscription"].path.format(subscription_id=subscription_id),
        )

        sub_status = None
        if isinstance(sub_check_resp.body, dict):
            field = _find_status_field(sub_check_resp.body)
            if field:
                sub_status = field[1]

        if sub_status is None:
            status = ResultStatus.INFO
            actual = (
                f"Refund processed successfully (HTTP {refund_resp.status_code}), but could not "
                f"determine subscription status from the response. Manual verification recommended."
            )
        elif sub_status in CANCELLED_LOOKING_STATES:
            status = ResultStatus.PASS
            actual = (
                f"Refund processed (HTTP {refund_resp.status_code}) and subscription correctly "
                f"shows status '{sub_status}'. Refund-to-subscription synchronization is working."
            )
        elif sub_status in ACTIVE_LOOKING_STATES:
            status = ResultStatus.FAIL
            actual = (
                f"Refund processed (HTTP {refund_resp.status_code}) but subscription still shows "
                f"status '{sub_status}'. The subscription was NOT deactivated or adjusted after "
                "the refund. This indicates missing cross-system synchronization."
            )
        else:
            status = ResultStatus.INFO
            actual = (
                f"Refund processed (HTTP {refund_resp.status_code}) and subscription shows "
                f"status '{sub_status}'. Could not determine if this represents correct synchronization."
            )

        await self.emit(
            TestResult(
                test_case_id="STATE-004",
                category=self.category,
                name="Refund-to-subscription synchronization",
                description=(
                    "Creates a payment and linked subscription, processes a full refund of "
                    "the payment, then checks whether the subscription is correctly updated "
                    "(deactivated or adjusted). Verifies that cross-system state synchronization "
                    "occurs when financial events (refunds) affect subscription state. "
                    "Based on documented incident patterns where refund handlers and subscription "
                    "managers were separate systems that didn't synchronize."
                ),
                input_parameters={
                    "payment_id": payment_id,
                    "subscription_id": subscription_id,
                },
                expected="After refund processing, the subscription shows a non-active status (cancelled, suspended, or adjusted).",
                actual=actual,
                status=status,
                recommendation=None if status == ResultStatus.PASS else (
                    "Implement cross-system synchronization: when a refund is processed, "
                    "trigger a corresponding update to the associated subscription. Use "
                    "event-driven architecture or database triggers to ensure the subscription "
                    "manager is notified of refund events and adjusts the subscription accordingly."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- Shared helper ---------------------------------------------------

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
