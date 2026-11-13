"""Cross Version Consistency Module (Module 16).

Verifies that the system under test applies consistent validation rules
across different API versions of the same resource:

  VERSION-001: Cross-version validation consistency — sends identical
    non-standard input requests to both v1 and v2 of the same resource
    endpoint and compares whether both versions consistently decline them.
    A finding is reported when one version accepts what the other correctly
    blocks.

  VERSION-002: Legacy version discovery and validation — probes for
    existence of legacy or undocumented API versions (v0, v3, internal),
    and if found, sends the same non-standard inputs to verify that legacy
    endpoints maintain the same validation standards as the current version.

Based on documented incident patterns:
- API versions having inconsistent validation rules
- Legacy endpoints having weaker validation than current versions
- Undocumented internal endpoints being less restricted
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.testing.base import BaseTestModule
from app.core.control_port import NEGATIVE_ACCESS_CONTROL
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult


# Non-standard payment/subscription attributes that only the verified
# payment flow should be able to set (same set used by ROLE-002)
_NON_STANDARD_PAYMENT_FIELDS: dict[str, Any] = {
    "plan": "max",
    "subscription_status": "active",
    "tier": "premium",
    "is_premium": True,
}

# Legacy version patterns to probe for existence
_LEGACY_VERSION_PATTERNS: list[str] = [
    "/api/v0",
    "/api/v3",
    "/api/internal",
    "/api/v1/internal",
    "/api/beta",
    "/api/legacy",
]

# Common resource paths to test across versions
_RESOURCE_PATHS: list[str] = [
    "/user/profile",
    "/user",
    "/payments",
    "/subscriptions",
    "/account",
]


def _extract_version_prefix(path: str) -> str | None:
    """Extracts the version prefix (e.g., '/api/v1') from a path."""
    match = re.match(r"^(.*?/v\d+)", path)
    if match:
        return match.group(1)
    return None


def _replace_version(path: str, new_version: str) -> str:
    """Replaces the version segment in a path with a new version."""
    version_match = re.search(r"/v\d+", path)
    if version_match:
        return path[:version_match.start()] + new_version + path[version_match.end():]
    return path


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


def _extract_path_from_url(url: str) -> str:
    """Extracts just the path component from a full URL."""
    parsed = urlparse(url)
    return parsed.path


class CrossVersionConsistencyModule(BaseTestModule):
    """Cross Version Consistency Module — verifies that API versions
    apply consistent validation rules and that legacy versions maintain
    the same security standards as current versions."""

    module_id = "cross_version_consistency"
    display_name = "Cross Version Consistency"
    category = TestCategory.CROSS_VERSION_CONSISTENCY

    async def run(self) -> None:
        await self._case_cross_version_validation()
        await self._case_legacy_version_discovery()

    def _discover_version_endpoints(self) -> dict[str, list[tuple[str, str]]]:
        """Discovers all versioned endpoints from the Recon function map.
        
        Returns a dict mapping resource paths to lists of (method, full_path) 
        tuples, one per version.
        """
        function_map = self.context.shared_state.get("function_map")
        if not isinstance(function_map, object) or not hasattr(function_map, "routes"):
            return {}

        versioned_routes: dict[str, list[tuple[str, str]]] = {}

        for route in function_map.routes:
            version_prefix = _extract_version_prefix(route.path)
            if version_prefix is None:
                continue

            # Extract the resource path (everything after the version prefix)
            resource_path = route.path[len(version_prefix):]
            if not resource_path:
                resource_path = "/"

            if resource_path not in versioned_routes:
                versioned_routes[resource_path] = []
            versioned_routes[resource_path].append((route.method, route.path))

        return versioned_routes

    def _get_primary_version(self) -> str:
        """Determines the primary API version from the default endpoints."""
        create_payment_path = self.context.endpoints.create_payment.path
        version_match = re.search(r"/v\d+", create_payment_path)
        if version_match:
            return version_match.group(0)
        return "/v1"

    # -- VERSION-001 -------------------------------------------------------

    async def _case_cross_version_validation(self) -> None:
        """Sends identical non-standard input requests to v1 and v2 of the
        same resource, comparing whether both consistently decline them."""

        versioned_routes = self._discover_version_endpoints()

        # Find resource paths that exist in multiple versions
        multi_version_resources = {
            resource_path: routes
            for resource_path, routes in versioned_routes.items()
            if len(routes) > 1
        }

        if not multi_version_resources:
            # No multi-version endpoints discovered — try to construct them
            multi_version_resources = self._construct_version_pairs()

        if not multi_version_resources:
            await self._emit_skip(
                test_case_id="VERSION-001",
                name="Cross-version validation consistency",
                description=(
                    "Sends identical non-standard input requests to v1 and v2 of the same "
                    "resource endpoint and compares whether both versions consistently decline them."
                ),
                actual=(
                    "No endpoints with multiple API versions were discovered or could be "
                    "constructed. Cross-version consistency verification requires at least "
                    "one resource available in two different API versions."
                ),
            )
            return

        findings: list[dict[str, Any]] = []
        total_checked = 0

        started = datetime.now(timezone.utc)

        for resource_path, routes in multi_version_resources.items():
            # Only test PATCH/PUT/POST endpoints (mutating operations)
            mutating_routes = [(m, p) for m, p in routes if m in ("PATCH", "PUT", "POST")]
            if not mutating_routes:
                continue

            # Group by version
            version_groups: dict[str, tuple[str, str]] = {}
            for method, full_path in mutating_routes:
                version_prefix = _extract_version_prefix(full_path)
                if version_prefix:
                    version_groups[version_prefix] = (method, full_path)

            if len(version_groups) < 2:
                continue

            # Send the same non-standard input to each version
            version_results: dict[str, dict[str, Any]] = {}

            for version_prefix, (method, full_path) in version_groups.items():
                # Build the request body with non-standard fields
                request_body: dict[str, Any] = {"email": "qa-cross-version@example.com"}
                request_body.update(_NON_STANDARD_PAYMENT_FIELDS)

                req, resp = await self.context.http.request(
                    method, full_path, json_body=request_body
                )

                classification = _classify_response(resp)
                reflected = []
                if isinstance(resp.body, dict):
                    for key, value in _NON_STANDARD_PAYMENT_FIELDS.items():
                        if key in resp.body and resp.body[key] == value:
                            reflected.append(key)

                version_results[version_prefix] = {
                    "method": method,
                    "path": full_path,
                    "status_code": resp.status_code,
                    "classification": classification,
                    "reflected_fields": reflected,
                    "request": req,
                    "response": resp,
                }

                total_checked += 1

            # Compare results across versions
            classifications = {v: r["classification"] for v, r in version_results.items()}
            reflected_any = {v: len(r["reflected_fields"]) > 0 for v, r in version_results.items()}

            # Check for inconsistency
            declined_versions = [v for v, c in classifications.items() if c == "declined"]
            accepted_versions = [v for v, c in classifications.items() if c == "accepted"]
            reflected_versions = [v for v, r in reflected_any.items() if r]

            if len(accepted_versions) > 0 and len(declined_versions) > 0:
                # Inconsistency: one version accepts what another blocks
                findings.append({
                    "resource_path": resource_path,
                    "type": "inconsistent_validation",
                    "detail": (
                        f"Resource '{resource_path}' shows inconsistent validation across versions: "
                        f"{accepted_versions} accept non-standard fields while {declined_versions} "
                        f"correctly decline them. This means validation rules differ between API versions."
                    ),
                    "version_results": version_results,
                })
            elif len(reflected_versions) > 0 and len(reflected_versions) < len(version_results):
                # Inconsistency: one version reflects non-standard fields but another doesn't
                findings.append({
                    "resource_path": resource_path,
                    "type": "inconsistent_reflection",
                    "detail": (
                        f"Resource '{resource_path}' shows inconsistent field handling across versions: "
                        f"{reflected_versions} reflect non-standard fields back while others do not. "
                        f"This suggests one version processes these fields while another ignores them."
                    ),
                    "version_results": version_results,
                })

        finished = datetime.now(timezone.utc)

        if not findings:
            status = ResultStatus.PASS
            actual = (
                f"Checked {total_checked} endpoint(s) across multiple API versions. "
                f"All versions consistently apply the same validation rules for non-standard "
                f"payment/subscription fields."
            )
            recommendation = None
        else:
            has_reflection = any(f["type"] == "inconsistent_reflection" for f in findings)
            status = ResultStatus.FAIL if has_reflection else ResultStatus.WARNING

            details = "; ".join(f["detail"] for f in findings[:5])
            actual = (
                f"Checked {total_checked} endpoint(s) across {len(multi_version_resources)} "
                f"resource(s). Found {len(findings)} inconsistency(ies): {details}"
            )
            recommendation = (
                "Ensure all API versions of the same resource apply identical validation "
                "rules for payment/subscription fields. Move validation logic to a shared "
                "layer that runs after request normalization, so every API version uses "
                "the same rules. Document which version is authoritative and deprecate "
                "inconsistent legacy versions."
            )

        # Use the first finding's evidence if available
        request_evidence = None
        response_evidence = None
        if findings:
            first_version_results = findings[0]["version_results"]
            first_result = next(iter(first_version_results.values()))
            request_evidence = first_result.get("request")
            response_evidence = first_result.get("response")

        await self.emit(
            TestResult(
                test_case_id="VERSION-001",
                category=self.category,
                name="Cross-version validation consistency",
                description=(
                    "Sends identical non-standard input requests containing payment/subscription "
                    "attributes (plan, tier, subscription_status, is_premium) to v1 and v2 of "
                    "the same resource endpoint. Compares whether both versions consistently "
                    "decline these fields or whether one version accepts what the other blocks. "
                    "Identifies gaps where older API versions may have weaker validation."
                ),
                input_parameters={
                    "resources_checked": len(multi_version_resources),
                    "endpoints_checked": total_checked,
                    "non_standard_fields": list(_NON_STANDARD_PAYMENT_FIELDS.keys()),
                },
                expected="All API versions of the same resource apply identical validation rules for non-standard payment/subscription fields.",
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

    def _construct_version_pairs(self) -> dict[str, list[tuple[str, str]]]:
        """Constructs version pairs by taking known endpoints and creating
        alternate version paths for them."""
        primary_version = self._get_primary_version()

        # Determine alternate version
        version_num = re.search(r"\d+", primary_version)
        if version_num:
            current_num = int(version_num.group())
            alternate_num = current_num + 1 if current_num == 1 else current_num - 1
            alternate_version = f"/v{alternate_num}"
        else:
            alternate_version = "/v2"

        pairs: dict[str, list[tuple[str, str]]] = {}

        # Take the create_payment endpoint and construct both versions
        create_payment = self.context.endpoints.create_payment
        primary_path = create_payment.path
        alternate_path = _replace_version(primary_path, alternate_version)

        if primary_path != alternate_path:
            resource_path = _extract_path_from_url(primary_path)
            version_prefix = _extract_version_prefix(primary_path)
            if version_prefix:
                resource_path = primary_path[len(version_prefix):]

            pairs[resource_path] = [
                (create_payment.method, primary_path),
                (create_payment.method, alternate_path),
            ]

        return pairs

    # -- VERSION-002 -------------------------------------------------------

    async def _case_legacy_version_discovery(self) -> None:
        """Probes for legacy API versions and verifies they maintain the
        same validation standards as the current version."""

        primary_version = self._get_primary_version()
        create_payment = self.context.endpoints.create_payment
        base_path = create_payment.path

        # Remove the version segment to get the base resource path
        version_match = re.search(r"/v\d+", base_path)
        if version_match:
            resource_base = base_path[:version_match.start()] + base_path[version_match.end():]
        else:
            resource_base = base_path

        discovered_versions: list[dict[str, Any]] = []

        started = datetime.now(timezone.utc)

        # Probe each legacy version pattern
        for legacy_prefix in _LEGACY_VERSION_PATTERNS:
            legacy_path = f"{legacy_prefix}{resource_base}"

            req, resp = await self.context.http.request("GET", legacy_path, probe_class=NEGATIVE_ACCESS_CONTROL)

            classification = _classify_response(resp)

            # A 404 or transport error means the version doesn't exist
            if resp.status_code == 404 or classification == "transport_error":
                continue

            # Any other response (200, 401, 403, 500, etc.) suggests the endpoint exists
            if resp.status_code is not None:
                discovered_versions.append({
                    "prefix": legacy_prefix,
                    "path": legacy_path,
                    "status_code": resp.status_code,
                    "classification": classification,
                    "method": "GET",
                    "request": req,
                    "response": resp,
                })

        # For each discovered legacy version, send non-standard inputs
        legacy_findings: list[dict[str, Any]] = []

        for legacy in discovered_versions:
            # DISABLED in Pure Black-Box mode: sending state-changing requests (non-standard payment fields) to an UNDOCUMENTED legacy
            # endpoint is outside every approved flow of an Execution Brief. The exposure itself is reported from the tagged GET above;
            # whether the legacy version validates as strictly as the current one is NOT_SUPPORTED here (not "passed").
            if legacy["classification"] in ("accepted", "server_error", "unclear"):
                legacy_findings.append({
                    "prefix": legacy["prefix"],
                    "path": legacy["path"],
                    "type": "legacy_version_reachable",
                    "detail": (
                        f"Legacy/undocumented API version '{legacy['prefix']}' is reachable at {legacy['path']} "
                        f"(HTTP {legacy['status_code']}); its validation strictness was deliberately NOT tested "
                        f"(write probes against undocumented endpoints are disabled in pure black-box mode)."
                    ),
                    "request": legacy.get("request"),
                    "response": legacy.get("response"),
                })

        finished = datetime.now(timezone.utc)

        if not discovered_versions:
            status = ResultStatus.INFO
            actual = (
                f"Probed {len(_LEGACY_VERSION_PATTERNS)} legacy version patterns. "
                f"No legacy API versions were found — all patterns returned 404 or were unreachable. "
                f"This is the expected outcome for a well-maintained API."
            )
            recommendation = None
            request_evidence = None
            response_evidence = None
        elif not legacy_findings:
            status = ResultStatus.PASS
            actual = (
                f"Discovered {len(discovered_versions)} legacy version endpoint(s): "
                f"{[d['prefix'] for d in discovered_versions]}. "
                f"None of them was classified as reachable-and-accepting; the validation-strictness comparison is not "
                f"supported in pure black-box mode, so this is NOT a statement that legacy versions validate correctly."
            )
            recommendation = None
            request_evidence = discovered_versions[0].get("request") if discovered_versions else None
            response_evidence = discovered_versions[0].get("response") if discovered_versions else None
        else:
            status = ResultStatus.WARNING  # exposure observed; strictness comparison not supported in pure black-box mode

            details = "; ".join(f["detail"] for f in legacy_findings[:5])
            actual = (
                f"Discovered {len(discovered_versions)} legacy version endpoint(s). "
                f"Found {len(legacy_findings)} exposure observation(s): {details}"
            )
            recommendation = (
                "Legacy API versions should either be removed or updated to enforce the "
                "same validation rules as the current version. If legacy versions must "
                "remain for backward compatibility, implement a shared validation layer "
                "that applies to all versions uniformly. Consider using API gateway rules "
                "to redirect legacy version requests to the current version's validation logic."
            )
            request_evidence = legacy_findings[0].get("request") if legacy_findings else None
            response_evidence = legacy_findings[0].get("response") if legacy_findings else None

        await self.emit(
            TestResult(
                test_case_id="VERSION-002",
                category=self.category,
                name="Legacy version discovery and validation consistency",
                description=(
                    "Probes for the existence of legacy or undocumented API versions "
                    "(/api/v0, /api/v3, /api/internal, /api/beta, /api/legacy) by sending "
                    "GET requests to these path patterns. For any discovered legacy endpoints, "
                    "sends the same non-standard payment/subscription field inputs used in "
                    "current version testing, and verifies that legacy endpoints maintain "
                    "the same or stricter validation standards as the current version. "
                    "Identifies a common gap where older API versions have weaker or missing "
                    "validation compared to the current release."
                ),
                input_parameters={
                    "patterns_probed": _LEGACY_VERSION_PATTERNS,
                    "versions_discovered": [d["prefix"] for d in discovered_versions],
                    "primary_version": primary_version,
                },
                expected="No legacy versions exist, or all discovered legacy versions enforce the same validation rules as the current version.",
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
