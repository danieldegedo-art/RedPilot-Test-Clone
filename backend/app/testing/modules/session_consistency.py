"""Session Consistency Module (Module 18).

Verifies that the system under test maintains consistent authentication
and session handling across all discovered routes and workflows:

  AUTH-001: Cross-endpoint authentication consistency — sends a clearly
    expired reference token to every discovered route and verifies that
    ALL routes consistently return 401 (or equivalent). Identifies routes
    that may not properly validate authentication.

  AUTH-002: Cross-site request validation — sends state-changing requests
    without the expected cross-site request validation token to every
    discovered mutating route. Verifies that protection is consistently
    enforced.

  AUTH-003: Middleware header consistency — sends requests with a special
    header (x-middleware-subrequest) that is known to affect middleware
    behavior in certain frameworks. Verifies that this header does not
    allow circumvention of access controls.

  AUTH-004: Session renewal privilege stability — checks the session's
    privilege level before and after a token refresh, verifying that
    refreshing does not silently elevate access permissions.

Based on documented incident patterns:
- Next.js Middleware Authorization issue (CVE-2025-29927)
- Token refresh privilege changes (Orbis AppSec Report)
- Inconsistent authentication across API versions
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult
from app.testing.recon.function_mapper import FunctionCategory, FunctionMap


# A clearly expired/invalid reference token for testing
_EXPIRED_REFERENCE = "Bearer QA-TEST-EXPIRED-REFERENCE-1970-01-01"

# The special header that affects middleware behavior in certain frameworks
_MIDDLEWARE_HEADER_NAME = "x-middleware-subrequest"
_MIDDLEWARE_HEADER_VALUES = ["middleware", "src/middleware", "src/proxy", "src/auth"]


def _classify_auth_response(resp: ResponseEvidence) -> str:
    """Classification specific to authentication checks."""
    if resp.status_code is None:
        return "transport_error"
    if resp.status_code in (401, 403):
        return "properly_rejected"
    if resp.status_code == 404:
        return "not_found"
    if resp.status_code >= 500:
        return "server_error"
    if 200 <= resp.status_code < 300:
        return "accepted"
    return "unclear"


class SessionConsistencyModule(BaseTestModule):
    """Session Consistency Module — verifies consistent authentication
    enforcement, cross-site request validation, middleware integrity,
    and session renewal privilege stability across all routes."""

    module_id = "session_consistency"
    display_name = "Session Consistency"
    category = TestCategory.SESSION_CONSISTENCY

    async def run(self) -> None:
        await self._case_cross_endpoint_auth()
        await self._case_csrf_validation()
        await self._case_middleware_header()
        await self._case_token_refresh_privileges()

    def _get_all_routes(self) -> list[tuple[str, str, str]]:
        """Returns all discovered routes as (method, path, category) tuples."""
        function_map = self.context.shared_state.get("function_map")
        if not isinstance(function_map, FunctionMap):
            return []

        routes = []
        for route in function_map.routes:
            routes.append((route.method, route.path, route.category.value))
        return routes

    def _get_mutating_routes(self) -> list[tuple[str, str, str]]:
        """Returns only mutating (POST/PUT/PATCH/DELETE) routes."""
        return [
            (m, p, c) for m, p, c in self._get_all_routes()
            if m in ("POST", "PUT", "PATCH", "DELETE")
        ]

    # -- AUTH-001 -----------------------------------------------------------

    async def _case_cross_endpoint_auth(self) -> None:
        """Sends an expired reference token to all discovered routes,
        verifying consistent 401 responses."""

        all_routes = self._get_all_routes()
        if not all_routes:
            await self._emit_skip(
                test_case_id="AUTH-001",
                name="Cross-endpoint authentication consistency",
                description=(
                    "Sends a clearly expired reference token to every discovered route "
                    "and verifies that ALL routes consistently return 401 (or equivalent)."
                ),
                actual="No routes were discovered by Recon. Cannot verify authentication consistency.",
            )
            return

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        for method, path, category in all_routes:
            headers = {"Authorization": _EXPIRED_REFERENCE}

            req, resp = await self.context.http.request(
                method, path, extra_headers=headers
            )

            classification = _classify_auth_response(resp)

            results.append({
                "method": method,
                "path": path,
                "category": category,
                "status_code": resp.status_code,
                "classification": classification,
                "request": req,
                "response": resp,
            })

        finished = datetime.now(timezone.utc)

        # Analyze consistency
        properly_rejected = [r for r in results if r["classification"] == "properly_rejected"]
        not_found = [r for r in results if r["classification"] == "not_found"]
        accepted = [r for r in results if r["classification"] == "accepted"]
        server_errors = [r for r in results if r["classification"] == "server_error"]
        transport_errors = [r for r in results if r["classification"] == "transport_error"]
        unclear = [r for r in results if r["classification"] == "unclear"]

        total = len(results)
        rejected_count = len(properly_rejected)
        accepted_count = len(accepted)
        error_count = len(server_errors) + len(transport_errors)

        if accepted_count > 0:
            # Some routes accepted the expired token — this is a FAIL
            accepted_details = [
                f"{r['method']} {r['path']} (HTTP {r['status_code']}, category: {r['category']})"
                for r in accepted[:10]
            ]
            status = ResultStatus.FAIL
            actual = (
                f"Tested {total} route(s) with an expired reference token. "
                f"{rejected_count} correctly returned 401/403, but {accepted_count} route(s) "
                f"ACCEPTED the expired token and returned a successful response: "
                f"{'; '.join(accepted_details)}. "
                f"These routes do not properly validate authentication."
            )
            recommendation = (
                "Ensure ALL routes validate the Authorization header and reject expired "
                "or invalid tokens with HTTP 401. Routes that accepted an expired token "
                "may be missing authentication middleware or may have incorrect token "
                "validation logic. Apply authentication checks uniformly across all "
                "endpoints using shared middleware rather than per-route checks."
            )
        elif error_count > 0:
            status = ResultStatus.ERROR
            error_details = [
                f"{r['method']} {r['path']} ({r['classification']})"
                for r in (server_errors + transport_errors)[:5]
            ]
            actual = (
                f"Tested {total} route(s). {rejected_count} correctly rejected the expired "
                f"token, but {error_count} route(s) resulted in server or transport errors: "
                f"{'; '.join(error_details)}. "
                f"Authentication validation should never cause server errors."
            )
            recommendation = (
                "Investigate routes that returned server errors when presented with an "
                "expired token. Authentication middleware should handle invalid tokens "
                "gracefully with a clean 401 response, not a 500-level error."
            )
        elif rejected_count == total:
            status = ResultStatus.PASS
            actual = (
                f"Tested {total} route(s) with an expired reference token. "
                f"ALL routes consistently returned 401/403. "
                f"Authentication is enforced uniformly across the entire API surface."
            )
            recommendation = None
        else:
            # Mixed results (some not found, some unclear) but no accepted
            status = ResultStatus.WARNING
            actual = (
                f"Tested {total} route(s). {rejected_count} correctly rejected, "
                f"{len(not_found)} returned 404 (may be stale discovery), "
                f"{len(unclear)} returned ambiguous responses. "
                f"While no route accepted the expired token, some responses were unclear."
            )
            recommendation = (
                "Verify that routes returning 404 or ambiguous responses still have "
                "authentication middleware applied. Consider adding explicit authentication "
                "checks to all routes regardless of whether they currently exist."
            )

        # Use the first accepted route's evidence if available, else first result
        request_evidence = None
        response_evidence = None
        if accepted:
            request_evidence = accepted[0]["request"]
            response_evidence = accepted[0]["response"]
        elif results:
            request_evidence = results[0]["request"]
            response_evidence = results[0]["response"]

        await self.emit(
            TestResult(
                test_case_id="AUTH-001",
                category=self.category,
                name="Cross-endpoint authentication consistency",
                description=(
                    "Sends a clearly expired reference token (Bearer QA-TEST-EXPIRED-REFERENCE-1970-01-01) "
                    "to every route discovered by Recon. Verifies that ALL routes consistently "
                    "return HTTP 401 (Unauthorized) or 403 (Forbidden) — identifying any routes "
                    "that may not properly validate authentication tokens. Inconsistent "
                    "authentication enforcement creates gaps where some endpoints can be "
                    "accessed without valid credentials."
                ),
                input_parameters={
                    "total_routes_tested": total,
                    "token_used": "QA-TEST-EXPIRED-REFERENCE-1970-01-01",
                },
                expected="All discovered routes return HTTP 401 or 403 when presented with an expired token.",
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

    # -- AUTH-002 -----------------------------------------------------------

    async def _case_csrf_validation(self) -> None:
        """Sends mutating requests without cross-site request validation
        tokens to all discovered mutating routes."""

        mutating_routes = self._get_mutating_routes()
        if not mutating_routes:
            await self._emit_skip(
                test_case_id="AUTH-002",
                name="Cross-site request validation consistency",
                description=(
                    "Sends state-changing requests without the expected cross-site "
                    "request validation token to every discovered mutating route."
                ),
                actual="No mutating routes (POST/PUT/PATCH/DELETE) were discovered. Cannot verify cross-site request validation.",
            )
            return

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        for method, path, category in mutating_routes:
            # Send a minimal empty body without any CSRF token
            # (No X-CSRF-Token, X-XSRF-Token, or similar headers)
            empty_body = {}

            req, resp = await self.context.http.request(
                method, path, json_body=empty_body
            )

            classification = _classify_auth_response(resp)

            results.append({
                "method": method,
                "path": path,
                "category": category,
                "status_code": resp.status_code,
                "classification": classification,
                "request": req,
                "response": resp,
            })

        finished = datetime.now(timezone.utc)

        # For CSRF, "accepted" means the request went through without CSRF validation
        # However, an empty body might be rejected for validation reasons (400) which
        # is different from being rejected for missing CSRF token (403)
        # We need to distinguish between:
        # - 403 = likely CSRF rejection (good)
        # - 400 = validation error on empty body (may or may not include CSRF check)
        # - 200 = accepted without CSRF (bad)
        # - 401 = authentication rejection (different concern)

        csrf_protected = [r for r in results if r["status_code"] in (403,)]
        validation_rejected = [r for r in results if r["status_code"] == 400]
        accepted_without_csrf = [r for r in results if r["classification"] == "accepted"]
        auth_rejected = [r for r in results if r["status_code"] == 401]

        total = len(results)

        if accepted_without_csrf:
            # Some mutating routes accepted requests without CSRF validation
            accepted_details = [
                f"{r['method']} {r['path']} (HTTP {r['status_code']})"
                for r in accepted_without_csrf[:10]
            ]
            status = ResultStatus.WARNING
            actual = (
                f"Tested {total} mutating route(s) without a cross-site request validation "
                f"token. {len(accepted_without_csrf)} route(s) ACCEPTED the request without "
                f"any CSRF validation: {'; '.join(accepted_details)}. "
                f"However, this may be intentional for API-only endpoints that use "
                f"token-based authentication (Bearer tokens) rather than cookie-based "
                f"sessions. CSRF validation is primarily needed for cookie-based "
                f"authentication where browsers automatically send cookies."
            )
            recommendation = (
                "Verify whether the accepted routes use cookie-based session authentication "
                "(where CSRF validation is critical) or token-based authentication via "
                "Authorization headers (where CSRF is less relevant since tokens are not "
                "automatically sent by browsers). If cookie-based authentication is used "
                "on any of these routes, implement CSRF token validation (e.g., double-submit "
                "cookie pattern or synchronizer token pattern)."
            )
        elif len(csrf_protected) == total:
            status = ResultStatus.PASS
            actual = (
                f"Tested {total} mutating route(s). ALL returned HTTP 403 when the "
                f"request was sent without a cross-site request validation token. "
                f"CSRF protection is consistently enforced."
            )
            recommendation = None
        elif len(validation_rejected) + len(csrf_protected) == total:
            status = ResultStatus.INFO
            actual = (
                f"Tested {total} mutating route(s). {len(csrf_protected)} returned 403 "
                f"(likely CSRF rejection), {len(validation_rejected)} returned 400 "
                f"(validation error on empty body — may include CSRF check). "
                f"No route accepted the request without validation."
            )
            recommendation = None
        elif auth_rejected and not accepted_without_csrf:
            status = ResultStatus.INFO
            actual = (
                f"Tested {total} mutating route(s). {len(auth_rejected)} returned 401 "
                f"(authentication required before CSRF check). "
                f"No route accepted the request without proper authentication and validation."
            )
            recommendation = None
        else:
            status = ResultStatus.WARNING
            actual = (
                f"Tested {total} mutating route(s) with mixed results: "
                f"{len(csrf_protected)} CSRF-rejected (403), "
                f"{len(validation_rejected)} validation-rejected (400), "
                f"{len(accepted_without_csrf)} accepted, "
                f"{len(auth_rejected)} auth-rejected (401). "
                f"Could not determine overall CSRF enforcement consistency."
            )
            recommendation = (
                "Verify that all mutating routes enforce cross-site request validation "
                "when cookie-based authentication is used. Consider implementing CSRF "
                "validation uniformly across all state-changing endpoints."
            )

        request_evidence = results[0]["request"] if results else None
        response_evidence = results[0]["response"] if results else None

        await self.emit(
            TestResult(
                test_case_id="AUTH-002",
                category=self.category,
                name="Cross-site request validation consistency",
                description=(
                    "Sends state-changing requests (POST/PUT/PATCH/DELETE) with an empty "
                    "body and NO cross-site request validation token (no X-CSRF-Token, "
                    "X-XSRF-Token, or similar headers) to every discovered mutating route. "
                    "Verifies that protection against cross-site requests is consistently "
                    "enforced. Note: for pure API endpoints using Bearer token authentication "
                    "(where tokens are sent via Authorization header), CSRF validation may "
                    "not be strictly necessary since browsers do not automatically send "
                    "these tokens."
                ),
                input_parameters={
                    "mutating_routes_tested": total,
                    "csrf_headers_omitted": ["X-CSRF-Token", "X-XSRF-Token", "X-CSRF-Header"],
                },
                expected="All mutating routes either enforce CSRF validation (403) or reject the request for other validation reasons (400/401).",
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

    # -- AUTH-003 -----------------------------------------------------------

    async def _case_middleware_header(self) -> None:
        """Sends requests with a special header that can affect middleware
        behavior, verifying it does not allow circumvention of access controls."""

        # Focus on routes that appear to require authentication or have
        # restricted access (admin, system, etc.)
        all_routes = self._get_all_routes()

        # Prioritize system_administration and account_management routes
        priority_routes = [
            (m, p, c) for m, p, c in all_routes
            if c in ("system_administration", "account_management")
        ]

        if not priority_routes:
            # Fall back to all routes if no priority routes found
            priority_routes = all_routes

        if not priority_routes:
            await self._emit_skip(
                test_case_id="AUTH-003",
                name="Middleware header consistency",
                description=(
                    "Sends requests with a special header (x-middleware-subrequest) that "
                    "is known to affect middleware behavior, verifying it does not allow "
                    "circumvention of access controls."
                ),
                actual="No routes were discovered to test middleware header handling.",
            )
            return

        results: list[dict[str, Any]] = []
        started = datetime.now(timezone.utc)

        # Test each middleware header value against each route
        for method, path, category in priority_routes[:10]:  # Limit to 10 routes
            for header_value in _MIDDLEWARE_HEADER_VALUES:
                headers = {_MIDDLEWARE_HEADER_NAME: header_value}

                req, resp = await self.context.http.request(
                    method, path, extra_headers=headers
                )

                classification = _classify_auth_response(resp)

                results.append({
                    "method": method,
                    "path": path,
                    "category": category,
                    "header_value": header_value,
                    "status_code": resp.status_code,
                    "classification": classification,
                    "request": req,
                    "response": resp,
                })

        finished = datetime.now(timezone.utc)

        # Check if any route returned a successful response with the middleware header
        # that would normally be restricted
        circumvented = [
            r for r in results
            if r["classification"] == "accepted"
            and r["category"] == "system_administration"
        ]

        total = len(results)
        accepted_count = sum(1 for r in results if r["classification"] == "accepted")
        rejected_count = sum(1 for r in results if r["classification"] == "properly_rejected")

        if circumvented:
            # System administration routes were accessible with the middleware header
            circumvented_details = [
                f"{r['method']} {r['path']} with '{_MIDDLEWARE_HEADER_NAME}: {r['header_value']}' "
                f"(HTTP {r['status_code']})"
                for r in circumvented[:5]
            ]
            status = ResultStatus.FAIL
            actual = (
                f"Tested {total} route/header combination(s). "
                f"{len(circumvented)} system administration route(s) became accessible "
                f"when the middleware header was present: "
                f"{'; '.join(circumvented_details)}. "
                f"This indicates that the middleware header can be used to circumvent "
                f"access controls, similar to the documented Next.js issue (CVE-2025-29927)."
            )
            recommendation = (
                "Immediately investigate and patch the middleware implementation. "
                "The 'x-middleware-subrequest' header should never be honored from "
                "external requests — it is an internal routing hint, not an authentication "
                "mechanism. Ensure that: (1) the header is stripped from all incoming "
                "requests at the load balancer or API gateway level, (2) middleware "
                "authorization checks are not bypassed by any request header, and "
                "(3) access control decisions are made independently of request routing hints."
            )
        elif accepted_count > 0:
            # Some routes accepted but they weren't system administration routes
            accepted_non_admin = [
                r for r in results
                if r["classification"] == "accepted"
                and r["category"] != "system_administration"
            ]
            status = ResultStatus.INFO
            actual = (
                f"Tested {total} route/header combination(s). "
                f"{rejected_count} were properly rejected, "
                f"{accepted_count} were accepted (but these were non-administration routes). "
                f"The middleware header did not appear to grant access to restricted "
                f"system administration routes."
            )
            recommendation = None
        elif rejected_count == total:
            status = ResultStatus.PASS
            actual = (
                f"Tested {total} route/header combination(s) with the middleware header "
                f"'{_MIDDLEWARE_HEADER_NAME}' set to various values. "
                f"ALL routes consistently returned 401/403 regardless of the header value. "
                f"The middleware header does not affect access control decisions."
            )
            recommendation = None
        else:
            status = ResultStatus.WARNING
            actual = (
                f"Tested {total} route/header combination(s) with mixed results. "
                f"{rejected_count} properly rejected, {accepted_count} accepted, "
                f"but none were clearly system administration routes. "
                f"Could not definitively determine if the header affects access control."
            )
            recommendation = (
                "Verify that the 'x-middleware-subrequest' header (or similar internal "
                "routing hints) cannot affect authorization decisions. Strip these "
                "headers from all incoming requests at the gateway level."
            )

        request_evidence = results[0]["request"] if results else None
        response_evidence = results[0]["response"] if results else None

        await self.emit(
            TestResult(
                test_case_id="AUTH-003",
                category=self.category,
                name="Middleware header consistency",
                description=(
                    "Sends requests with the 'x-middleware-subrequest' header set to "
                    "various values ('middleware', 'src/middleware', 'src/proxy', 'src/auth') "
                    "to discovered routes, particularly system administration and account "
                    "management routes. Verifies that this header — which is an internal "
                    "routing hint in certain frameworks — cannot be used to circumvent "
                    "access controls or gain unauthorized access to protected resources. "
                    "Based on the documented Next.js middleware authorization issue "
                    "(CVE-2025-29927) where this header could bypass middleware-based "
                    "access controls."
                ),
                input_parameters={
                    "routes_tested": len(priority_routes[:10]),
                    "header_values_tested": _MIDDLEWARE_HEADER_VALUES,
                    "header_name": _MIDDLEWARE_HEADER_NAME,
                },
                expected="The middleware header has no effect on access control — all routes maintain their normal authentication/authorization behavior.",
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

    # -- AUTH-004 -----------------------------------------------------------

    async def _case_token_refresh_privileges(self) -> None:
        """Checks privilege levels before and after session renewal,
        verifying no silent elevation occurs."""

        # This test requires knowing:
        # 1. A session renewal endpoint
        # 2. A way to check current privileges before renewal
        # 3. A way to check current privileges after renewal

        # Look for session/auth related endpoints
        function_map = self.context.shared_state.get("function_map")
        if not isinstance(function_map, FunctionMap):
            await self._emit_skip(
                test_case_id="AUTH-004",
                name="Session renewal privilege stability",
                description=(
                    "Checks the session's privilege level before and after a token "
                    "refresh, verifying that refreshing does not silently elevate "
                    "access permissions."
                ),
                actual="No function map available. Cannot identify session renewal endpoints.",
            )
            return

        # Find session-related endpoints
        renewal_candidates = []
        privilege_check_routes = []

        for route in function_map.routes:
            path_lower = route.path.lower()
            if any(keyword in path_lower for keyword in ("refresh", "renew", "token")):
                if route.method in ("POST", "PUT"):
                    renewal_candidates.append((route.method, route.path))
            if any(keyword in path_lower for keyword in ("me", "profile", "account", "session")):
                if route.method == "GET":
                    privilege_check_routes.append((route.method, route.path))

        if not renewal_candidates:
            await self._emit_skip(
                test_case_id="AUTH-004",
                name="Session renewal privilege stability",
                description=(
                    "Checks the session's privilege level before and after a token "
                    "refresh, verifying that refreshing does not silently elevate "
                    "access permissions."
                ),
                actual=(
                    "No session renewal endpoint was discovered (no routes matching "
                    "'refresh', 'renew', or 'token' with POST/PUT method). "
                    "Cannot verify privilege stability across token refresh."
                ),
            )
            return

        if not privilege_check_routes:
            await self._emit_skip(
                test_case_id="AUTH-004",
                name="Session renewal privilege stability",
                description=(
                    "Checks the session's privilege level before and after a token "
                    "refresh, verifying that refreshing does not silently elevate "
                    "access permissions."
                ),
                actual=(
                    "No privilege-checking endpoint was discovered (no GET routes matching "
                    "'me', 'profile', 'account', or 'session'). "
                    "Cannot verify privilege levels before and after refresh."
                ),
            )
            return

        started = datetime.now(timezone.utc)

        # Step 1: Check current privileges (before refresh)
        before_privileges: dict[str, Any] = {}
        before_requests = []

        for method, path in privilege_check_routes[:3]:  # Check up to 3 routes
            req, resp = await self.context.http.request(method, path)
            before_requests.append((req, resp))

            if isinstance(resp.body, dict):
                # Extract privilege-related fields
                privilege_fields = ["role", "roles", "permissions", "scopes", "level", "tier", "is_admin", "is_premium"]
                for field in privilege_fields:
                    if field in resp.body:
                        before_privileges[field] = resp.body[field]
                before_privileges[f"_status_{path}"] = resp.status_code

        # Step 2: Attempt token refresh
        refresh_method, refresh_path = renewal_candidates[0]
        refresh_body = {}  # Empty body — the refresh should use the existing session

        refresh_req, refresh_resp = await self.context.http.request(
            refresh_method, refresh_path, json_body=refresh_body
        )

        # Step 3: Check privileges after refresh (if refresh succeeded)
        after_privileges: dict[str, Any] = {}
        after_requests = []

        if refresh_resp.status_code is not None and 200 <= refresh_resp.status_code < 300:
            # Refresh succeeded — check privileges again
            for method, path in privilege_check_routes[:3]:
                req, resp = await self.context.http.request(method, path)
                after_requests.append((req, resp))

                if isinstance(resp.body, dict):
                    privilege_fields = ["role", "roles", "permissions", "scopes", "level", "tier", "is_admin", "is_premium"]
                    for field in privilege_fields:
                        if field in resp.body:
                            after_privileges[field] = resp.body[field]
                    after_privileges[f"_status_{path}"] = resp.status_code

        finished = datetime.now(timezone.utc)

        # Compare privileges
        if not after_privileges:
            # Refresh didn't succeed or no privilege data available after
            status = ResultStatus.INFO
            actual = (
                f"Session renewal endpoint found at {refresh_method} {refresh_path}. "
                f"Refresh attempt returned HTTP {refresh_resp.status_code}. "
                f"Before-refresh privileges: {before_privileges}. "
                f"Could not check after-refresh privileges (refresh may not have succeeded "
                f"or privilege data was not available). "
                f"Manual verification recommended: verify that refreshing a session token "
                f"does not change the user's role, permissions, or access level."
            )
            recommendation = (
                "Implement privilege stability checks in session renewal: when refreshing "
                "a token, the new token should carry exactly the same privileges as the "
                "original. If privilege changes are needed, they should go through a "
                "separate, authenticated authorization flow, not silently during token refresh."
            )
        else:
            # Compare before and after
            privilege_changed = False
            changed_fields = []

            for field, before_value in before_privileges.items():
                if field.startswith("_"):
                    continue  # Skip metadata fields
                after_value = after_privileges.get(field)
                if after_value != before_value:
                    privilege_changed = True
                    changed_fields.append(f"{field}: {before_value!r} → {after_value!r}")

            if privilege_changed:
                status = ResultStatus.FAIL
                actual = (
                    f"Session renewal at {refresh_method} {refresh_path} returned HTTP "
                    f"{refresh_resp.status_code}. "
                    f"Privilege CHANGED after refresh: {'; '.join(changed_fields[:5])}. "
                    f"This indicates that the token refresh process silently modifies "
                    f"the user's access level, which could lead to unauthorized privilege "
                    f"elevation."
                )
                recommendation = (
                    "Fix the session renewal process to preserve privilege stability: "
                    "when refreshing a token, the new token must carry exactly the same "
                    "privileges as the original token. If a user's privileges have been "
                    "legitimately changed (e.g., by an admin), this should be reflected "
                    "in the new token — but the refresh process should never add privileges "
                    "that weren't in the original. Implement a check that compares the "
                    "original token's claims with the refreshed token's claims and flags "
                    "any additions."
                )
            else:
                status = ResultStatus.PASS
                actual = (
                    f"Session renewal at {refresh_method} {refresh_path} returned HTTP "
                    f"{refresh_resp.status_code}. "
                    f"Privileges remained stable after refresh: "
                    f"{before_privileges} → {after_privileges}. "
                    f"No privilege elevation occurred during token refresh."
                )
                recommendation = None

        # Use the refresh request/response as evidence
        await self.emit(
            TestResult(
                test_case_id="AUTH-004",
                category=self.category,
                name="Session renewal privilege stability",
                description=(
                    "Discovers the session renewal endpoint (routes matching 'refresh', "
                    "'renew', or 'token'), checks the current session's privilege level "
                    "(role, permissions, scopes, tier) via account/profile endpoints, "
                    "then attempts a token refresh and checks privileges again. Verifies "
                    "that refreshing a session token does not silently elevate the user's "
                    "access level. Based on documented incident patterns where expired "
                    "tokens were renewed with expanded privileges."
                ),
                input_parameters={
                    "renewal_endpoint": f"{refresh_method} {refresh_path}",
                    "privilege_check_routes": [f"{m} {p}" for m, p in privilege_check_routes[:3]],
                    "privileges_before": before_privileges,
                    "privileges_after": after_privileges,
                },
                expected="Privilege level remains identical before and after session renewal — no fields are added or changed.",
                actual=actual,
                status=status,
                request=refresh_req,
                response=refresh_resp,
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
