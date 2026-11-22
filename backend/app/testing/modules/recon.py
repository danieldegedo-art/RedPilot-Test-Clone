"""Application-Layer Recon Module.

Crawls the Test Environment URL with a headless browser, observes real
XHR/fetch network calls, and additionally statically scans same-origin
JavaScript bundles for fetch()/axios() call patterns. Every discovery is
reported as an INFO test result (visible in the dashboard/exports like any
other finding), and -- where a discovered call unambiguously matches a
known logical operation -- merged into the shared EndpointMap so the
Functional/Negative/EdgeCase/Integration modules running afterwards in the
same pass automatically target the real, discovered routes instead of the
built-in defaults. A manual override already configured in Settings always
wins: recon fills gaps, it never overwrites a route you've set by hand.

When Electron pre-fetched recon data is available (passed via
context.shared_state["electron_recon"]), this module uses that data instead
of launching Playwright.  Electron's native BrowserWindow passes Cloudflare
and other WAFs that block Playwright's headless Chromium, so the pre-fetched
data contains the REAL network traffic and page HTML the target serves to a
normal browser.

Also detects third-party payment-provider integration (currently: Stripe
Checkout -- see recon/stripe_detector.py) from the same crawl signals, and
stashes the finding in `context.shared_state["stripe_detection"]` for the
Stripe flow module to consume. When a target has no payment API of its
own (Stripe handles it), this is *why* no create_payment-shaped endpoint
gets discovered/mapped above -- RECON-003 documents that explicitly rather
than leaving it looking like a gap.

Scope: this module only observes traffic a normal browser visit already
generates and only reads same-origin JavaScript the target already serves
to any visitor. It does not brute-force, fuzz, or attempt to reach
anything not already exposed to the page, and it does not scan for
secrets/credentials in the JS it reads (a Stripe *publishable* key is the
one exception -- it's designed by Stripe to be public, see
recon/stripe_detector.py).

Requires Playwright with Chromium installed: `playwright install chromium`
(already handled by backend/Dockerfile). Enabled by default (see
core/settings_store.py / SettingsSchema) and included in the Standard,
Comprehensive, and Full Regression scopes, so a first run with no manual
configuration already benefits from auto-discovered routes -- Smoke scope
excludes it to stay fast. Toggle it off in Settings if you'd rather not
launch a browser on every run.

CC6.1 "Completeness of Service Coverage" extension: after the passive
crawl above, this module additionally (1) actively probes a fixed set of
system-administration path patterns -- the one deliberate exception to
Recon's otherwise passive-only scope, kept narrow and documented in
recon/path_prober.py -- and (2) categorizes EVERY route found this pass
(organic + probed) into account_management / service_function /
system_administration via recon/function_mapper.py. The result is a
FunctionMap stashed in context.shared_state["function_map"] and reported
as RECON-004, the audit artifact CC6.1 requires: evidence that access
control was considered for every discovered function, not only the
obviously payment-shaped ones. RoleBasedAccessModule (ROLE-001/002/003)
consumes this map to run its access-control verification.

Any route under Settings -> Manual Routes is merged into the same
FunctionMap at "high" confidence (RECON-MANUAL-*, see
`_emit_manual_route`) -- the intended path for a route the discovery
channels above didn't find on their own, e.g. one a
DISCOVERY-CORRELATION-* finding (discovery/analyzers.py) recommended
adding.
"""
from __future__ import annotations

import asyncio
import re as _re
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.testing.base import BaseTestModule
from app.testing.dynamic_values import DiscoveredValues, build_discovered_values
from app.testing.endpoints import EndpointSpec
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import TestResult
from app.testing.recon.browser_crawler import CrawlResult, DiscoveredCall, crawl
from app.testing.recon.function_mapper import FunctionCategory, FunctionMap, MappedRoute, build_function_map, categorize_route
from app.testing.recon.js_endpoint_parser import extract_calls_from_js
from app.testing.recon.mapper import map_to_endpoint_overrides, register_discovered_features
from app.testing.recon.path_prober import ProbeHit, probe_system_paths
from app.testing.recon.stripe_detector import StripeDetection, detect_stripe

_MAX_SCRIPTS_SCANNED = 25  # keeps a single run bounded even on script-heavy SPAs
_SCRIPT_SRC_RE = _re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', _re.IGNORECASE)


class ReconModule(BaseTestModule):
    module_id = "recon"
    display_name = "Application-Layer Recon (Endpoint Discovery)"
    category = TestCategory.RECON

    def _build_crawl_result_from_electron(self, recon: dict) -> CrawlResult:
        """Convert Electron-captured recon data into a CrawlResult so the
        rest of this module's pipeline (endpoint mapping, Stripe detection,
        function map, dynamic values) works identically whether the data
        came from Playwright or Electron."""
        base_origin = self.context.base_url.rstrip("/")

        discovered: list[DiscoveredCall] = []
        network_hosts: set[str] = set()
        for call in recon.get("network_calls", []):
            url = call.get("url", "")
            parsed = urlparse(url)
            if parsed.hostname:
                network_hosts.add(parsed.hostname)
            discovered.append(DiscoveredCall(
                method=call.get("method", "GET"),
                path=parsed.path or "/",
                source="network",
            ))

        html = recon.get("html", "")
        script_urls: list[str] = []
        for match in _SCRIPT_SRC_RE.finditer(html):
            src = match.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base_origin + src
            if base_origin in src or src.startswith(base_origin):
                script_urls.append(src)

        cookie_names = set(recon.get("cookie_names", []))

        return CrawlResult(
            discovered=discovered,
            script_urls=script_urls[:_MAX_SCRIPTS_SCANNED],
            pages_visited=[self.context.entry_url],
            errors=[],
            cookie_names=cookie_names,
            network_hosts=network_hosts,
            html_content=html,
        )

    async def run(self) -> None:
        started = datetime.now(timezone.utc)

        electron_recon = self.context.shared_state.get("electron_recon")
        if electron_recon:
            result = self._build_crawl_result_from_electron(electron_recon)
        else:
            try:
                result = await crawl(
                    self.context.entry_url,
                    timeout_seconds=self.context.settings.timeout_seconds,
                    extra_headers=self.context.settings.custom_headers,
                )
            except Exception as exc:
                await self._emit_crawl_failed(started, exc)
                return

        # Fetch every same-origin script ONCE; both endpoint extraction and
        # Stripe detection run against the same fetched source text.
        script_sources = await self._fetch_scripts(result.script_urls)
        static_calls: list[DiscoveredCall] = []
        for source in script_sources:
            static_calls.extend(extract_calls_from_js(source))
        all_calls = result.discovered + static_calls

        await self._emit_discovery_summary(started, result, static_calls)

        stripe_detection = detect_stripe(
            cookie_names=result.cookie_names,
            script_urls=result.script_urls,
            network_hosts=result.network_hosts,
            js_sources=script_sources,
            html_content=result.html_content,
        )
        self.context.shared_state["stripe_detection"] = stripe_detection
        await self._emit_stripe_detection(started, stripe_detection)

        await self._build_and_emit_function_map(all_calls)
        await self._build_and_emit_discovered_values(all_calls)

        if not all_calls:
            return

        mapped = map_to_endpoint_overrides(all_calls)
        newly_mapped: dict[str, tuple[EndpointSpec, DiscoveredCall]] = {}
        for operation, (spec, source_call) in mapped.items():
            existing_override = self.context.endpoints.overrides.get(operation)
            if existing_override is not None:
                await self._emit_mapping_skipped(operation, source_call, existing_override)
                continue
            self.context.endpoints.overrides[operation] = spec
            newly_mapped[operation] = (spec, source_call)
            await self._emit_mapping(operation, spec, source_call)

        if newly_mapped and self.context.feature_registry is not None:
            await register_discovered_features(newly_mapped, self.context.feature_registry, discovered_at=started)

    async def _fetch_scripts(self, script_urls: list[str]) -> list[str]:
        # Each script is an independent, read-only GET -- nothing here
        # depends on another script's fetch, so they run concurrently
        # instead of one at a time. asyncio.gather preserves input order in
        # its results regardless of which finishes first, which matters
        # here: downstream code (Stripe detection, JS call extraction)
        # takes `script_sources` as a plain ordered list, not tagged by
        # origin URL, so silently reordering it on parallelization would be
        # an observable behavior change, not just a speedup.
        urls = script_urls[:_MAX_SCRIPTS_SCANNED]

        async def _fetch_one(url: str) -> str | None:
            _, resp = await self.context.http.request("GET", url)
            return resp.body if resp.error is None and isinstance(resp.body, str) else None

        fetched = await asyncio.gather(*(_fetch_one(url) for url in urls))
        return [source for source in fetched if source is not None]

    async def _emit_discovery_summary(self, started: datetime, result: CrawlResult, static_calls: list[DiscoveredCall]) -> None:
        finished = datetime.now(timezone.utc)
        all_calls = result.discovered + static_calls
        lines = sorted({f"{c.method} {c.path} (source={c.source})" for c in all_calls})

        actual = (
            f"Observed {len(result.discovered)} live network call(s) and {len(static_calls)} static-JS call(s) "
            f"across {len(result.script_urls)} same-origin script file(s); {len(lines)} distinct endpoint(s) found."
        )
        if result.errors:
            actual += " Warnings: " + "; ".join(result.errors)

        await self.emit(
            TestResult(
                test_case_id="RECON-001",
                category=self.category,
                name="API endpoint discovery",
                description=(
                    "Loads the Test Environment URL in headless Chromium, observes same-origin XHR/fetch network "
                    "calls, and statically scans same-origin JavaScript files for fetch()/axios() call patterns, "
                    "to build a coverage map of the API surface actually used by the frontend."
                ),
                input_parameters={"crawled_url": self.context.entry_url, "api_origin": self.context.base_url},
                expected="At least one API call is discovered from the page or its scripts.",
                actual=actual if all_calls else (
                    "No API calls observed. The page may be a static site, require login, use a "
                    "non-standard transport (GraphQL/WebSocket) this module doesn't parse, or route payments "
                    "through a third-party provider with no API calls of its own (see RECON-003 below)."
                ),
                status=ResultStatus.INFO if all_calls else ResultStatus.WARNING,
                recommendation=None if all_calls else (
                    "Confirm the URL is reachable and renders normally in a browser; if the app requires auth, "
                    "configure custom headers/cookies in Settings so the crawler sees an authenticated view."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

        if lines:
            await self.emit(
                TestResult(
                    test_case_id="RECON-002",
                    category=self.category,
                    name="Discovered endpoints (full list)",
                    description="Every distinct (method, path) pair discovered during recon, for manual review against your API documentation.",
                    input_parameters={},
                    expected="N/A - informational.",
                    actual="\n".join(lines),
                    status=ResultStatus.INFO,
                    started_at=started,
                    finished_at=finished,
                    duration_ms=0.0,
                )
            )

    async def _emit_stripe_detection(self, started: datetime, detection: StripeDetection) -> None:
        now = datetime.now(timezone.utc)
        if not detection.detected:
            return  # nothing Stripe-related found -- skip the noise of an empty result

        if detection.is_test_mode is True:
            mode = "TEST mode"
        elif detection.is_test_mode is False:
            mode = "LIVE mode"
        else:
            mode = "mode unknown (no publishable key found to check)"

        lines = [f"Stripe integration detected ({mode})."]
        lines.extend(f"- {e}" for e in detection.evidence)

        if detection.checkout_session_endpoint:
            lines.append(
                f"Likely flow: this page -> POST {detection.checkout_session_endpoint} (your backend, creates "
                "the Stripe session) -> redirect to checkout.stripe.com -> Stripe redirects back to your "
                "success_url/cancel_url -> Stripe sends your backend a webhook confirming payment."
            )
        else:
            lines.append(
                "Likely flow: this page -> your backend creates a Stripe Checkout Session server-side -> "
                "redirect to checkout.stripe.com -> Stripe redirects back to your success_url/cancel_url -> "
                "Stripe sends your backend a webhook confirming payment. The session-creation endpoint wasn't "
                "visible in client-side JS (common -- it's often a plain form POST, or a call this passive "
                "crawl's page load didn't trigger)."
            )
        if detection.success_url:
            lines.append(f"success_url observed: {detection.success_url}")
        if detection.cancel_url:
            lines.append(f"cancel_url observed: {detection.cancel_url}")
        if not detection.checkout_redirect_observed:
            lines.append(
                "Note: no redirect to checkout.stripe.com was observed -- this crawler only loads the page "
                "passively (no button clicks), so this is expected even on a fully working integration."
            )

        await self.emit(
            TestResult(
                test_case_id="RECON-003",
                category=self.category,
                name="Stripe Checkout integration detected",
                description=(
                    "Checks for signals of a Stripe Checkout integration: the __stripe_mid/__stripe_sid cookies "
                    "Stripe.js sets, a js.stripe.com script tag, a request to checkout.stripe.com, and a "
                    "publishable key in client-side JS (publishable keys are designed by Stripe to be public -- "
                    "see stripe.com/docs/keys). Used to route the Stripe-specific flow test and to explain why "
                    "your own API may have no create_payment-shaped endpoint for Recon to discover."
                ),
                input_parameters={},
                expected="N/A - informational.",
                actual="\n".join(lines),
                status=ResultStatus.INFO,
                recommendation=(
                    "The actual payment processing for this flow happens at Stripe, not on your own API -- the "
                    "Stripe Flow module's results test your webhook handler's signature verification instead. "
                    "Pure black-box mode: Recon cannot discover the webhook route (Stripe calls it server-to-server, never "
                    "from the browser) and an operator-declared route is a private endpoint list, so only the conventional "
                    "placeholder path is probed. A 404 there means 'not testable from outside' (UNKNOWN), never 'passed'."
                ),
                started_at=started,
                finished_at=now,
                duration_ms=(now - started).total_seconds() * 1000,
            )
        )

    async def _build_and_emit_function_map(self, all_calls: list[DiscoveredCall]) -> None:
        """CC6.1 extension: probes system-administration path patterns
        (path_prober.py), then categorizes every route found this pass --
        organic discoveries plus probe hits -- into the FunctionMap
        (function_mapper.py), stashed in context.shared_state["function_map"]
        for RoleBasedAccessModule. Runs even when `all_calls` is empty: a
        page that requires login or renders nothing client-side is exactly
        the case where active probing contributes the most coverage."""
        probe_hits = await probe_system_paths(self.context.http, [call.path for call in all_calls])
        for index, hit in enumerate(probe_hits, start=1):
            await self._emit_probe_hit(index, hit)

        function_map = build_function_map(
            network_and_js_calls=[(call.method, call.path, call.source, frozenset(call.param_names)) for call in all_calls],
            probed_hits=[(hit.method, hit.path, hit.status_code, hit.confidence) for hit in probe_hits],
        )
        for index, (method, path) in enumerate(self.context.settings.manual_routes, start=1):
            await self._emit_manual_route(index, method, path, function_map)
        self.context.shared_state["function_map"] = function_map
        await self._emit_function_map_summary(function_map)

    async def _emit_manual_route(self, index: int, method: str, path: str, function_map: FunctionMap) -> None:
        """Auditor-Anforderung 3 (Cross-Module Correlation) support: a route
        registered under Settings -> Manual Routes -- typically because a
        DISCOVERY-CORRELATION-* finding named it as a route no module ever
        exercised -- gets added at HIGH confidence (a human vouched for it
        directly, stronger than any organic or probed signal) so ROLE-002/
        ROLE-003/input_format_consistency treat it exactly like any other
        discovered route. Reported here, separately from RECON-PROBE-*,
        specifically so the evidence trail always shows which routes came
        from automatic discovery vs. an explicit human-entered override."""
        method = method.upper().strip()
        category, keyword = categorize_route(path)
        function_map.add(
            MappedRoute(
                method=method, path=path, category=category, source="manual-override", confidence="high",
                matched_keyword=keyword,
            )
        )
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id=f"RECON-MANUAL-{index:02d}",
                category=self.category,
                name=f"Manually registered route: {method} {path}",
                description=(
                    "Route added via Settings -> Manual Routes rather than discovered by the browser crawl, "
                    "static-JS parse, or system-path probe above. Added at 'high' confidence and merged into the "
                    "same FunctionMap those discovery channels populate, so every downstream module (ROLE-002, "
                    "ROLE-003, Input Format Consistency) treats it identically to an organically-discovered route."
                ),
                input_parameters={"method": method, "path": path},
                expected="N/A - informational registration only.",
                actual=f"Registered as {category.value}{f' (matched keyword: {keyword})' if keyword else ''}.",
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_probe_hit(self, index: int, hit: ProbeHit) -> None:
        now = datetime.now(timezone.utc)
        category, keyword = categorize_route(hit.path)
        await self.emit(
            TestResult(
                test_case_id=f"RECON-PROBE-{index:02d}",
                category=self.category,
                name=f"System-administration path found: {hit.path}",
                description=(
                    "Active probe for a system-administration path pattern (AICPA SOC2 CC6.1 'Completeness of "
                    "Service Coverage' / OWASP WSTG-INFO-07 'Map Application Architecture') -- unlike the rest "
                    "of Recon, this sends a request the page itself never makes. A single GET was sent with the "
                    "already-configured test session and compared against a baseline request to a "
                    "guaranteed-nonexistent path, to rule out a catch-all SPA fallback before being reported here."
                ),
                input_parameters={"probed_path": hit.path},
                expected=(
                    "N/A - informational discovery only. Whether access to this path is correctly restricted is "
                    "verified separately, with its own request/response evidence, by ROLE-003."
                ),
                actual=(
                    f"HTTP {hit.status_code} (confidence: {hit.confidence}) - did not match the baseline "
                    f"'nonexistent path' signature, so this path is likely real. Categorized as {category.value}"
                    f"{f' (matched keyword: {keyword})' if keyword else ''}."
                ),
                status=ResultStatus.INFO,
                request=hit.request,
                response=hit.response,
                recommendation=None,
                started_at=now,
                finished_at=now,
                duration_ms=hit.response.elapsed_ms or 0.0,
            )
        )

    async def _emit_function_map_summary(self, function_map: FunctionMap) -> None:
        now = datetime.now(timezone.utc)
        counts = function_map.counts_by_category()

        if not function_map.routes:
            await self.emit(
                TestResult(
                    test_case_id="RECON-004",
                    category=self.category,
                    name="Function map (Completeness of Service Coverage)",
                    description=(
                        "Categorizes every route discovered this pass (network-observed, static-JS, and actively "
                        "path-probed) into account_management / service_function / system_administration -- the "
                        "CC6.1 'Completeness of Service Coverage' audit artifact."
                    ),
                    input_parameters={"routes": [], "counts": counts},
                    expected="N/A - informational.",
                    actual=(
                        "No routes were discovered this pass (the organic crawl found nothing and no "
                        "system-administration probe pattern returned a non-baseline response) - nothing to "
                        "categorize, and ROLE-001/002/003 will have nothing to verify against."
                    ),
                    status=ResultStatus.WARNING,
                    recommendation=(
                        "Confirm the Test Environment URL is reachable and renders normally, and that Settings -> "
                        "Session Cookies holds a valid authenticated session if the app requires login -- recon "
                        "needs to see a real, logged-in view to build a meaningful coverage map."
                    ),
                    started_at=now,
                    finished_at=now,
                    duration_ms=0.0,
                )
            )
            return

        ordered_routes = sorted(function_map.routes, key=lambda r: (r.category.value, r.method, r.path))
        lines = [
            f"[{route.category.value}] {route.method} {route.path} (source={route.source}, confidence={route.confidence})"
            for route in ordered_routes
        ]
        routes_payload = [
            {
                "method": route.method,
                "path": route.path,
                "category": route.category.value,
                "source": route.source,
                "confidence": route.confidence,
                "matched_keyword": route.matched_keyword,
                "status_code_at_discovery": route.status_code_at_discovery,
            }
            for route in ordered_routes
        ]

        await self.emit(
            TestResult(
                test_case_id="RECON-004",
                category=self.category,
                name="Function map (Completeness of Service Coverage)",
                description=(
                    "Categorizes every route discovered this pass (network-observed, static-JS, and actively "
                    "path-probed for system-administration patterns) into account_management / service_function "
                    "/ system_administration. This is the CC6.1 'Completeness of Service Coverage' audit "
                    "artifact -- evidence that access control was considered for every discovered function, not "
                    "only the obviously payment-shaped routes -- and the shared map the Role-Based Access "
                    "Verification module consumes."
                ),
                input_parameters={"routes": routes_payload, "counts": counts},
                expected="N/A - informational; see ROLE-001/ROLE-002/ROLE-003 for the access-control verdicts drawn from this map.",
                actual=(
                    f"{len(ordered_routes)} route(s) categorized: {counts[FunctionCategory.ACCOUNT_MANAGEMENT.value]} "
                    f"account_management, {counts[FunctionCategory.SERVICE_FUNCTION.value]} service_function, "
                    f"{counts[FunctionCategory.SYSTEM_ADMINISTRATION.value]} system_administration.\n" + "\n".join(lines)
                ),
                status=ResultStatus.INFO,
                recommendation=None,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _build_and_emit_discovered_values(self, all_calls: list[DiscoveredCall]) -> None:
        """Flattens every network-observed call's real parameter values
        into context.shared_state["discovered_values"] (dynamic_values.py),
        so every module that runs after Recon in the same pass sends
        realistic values for fields Recon actually saw, instead of this
        suite's built-in defaults (see BaseTestModule.resolve_payload /
        execute_case)."""
        discovered_values = build_discovered_values(all_calls)
        self.context.shared_state["discovered_values"] = discovered_values
        await self._emit_discovered_values_summary(discovered_values)

    async def _emit_discovered_values_summary(self, discovered_values: DiscoveredValues) -> None:
        now = datetime.now(timezone.utc)
        if not discovered_values.by_field_name:
            await self.emit(
                TestResult(
                    test_case_id="RECON-005",
                    category=self.category,
                    name="Dynamic value resolution",
                    description=(
                        "Flattens real parameter values observed in the target's own network traffic into a "
                        "pool later modules draw from (dynamic_values.py), so their payloads use this "
                        "application's actual field values instead of this suite's generic built-in defaults."
                    ),
                    input_parameters={},
                    expected="N/A - informational.",
                    actual=(
                        "No usable real values were observed this pass (no scalar body/query fields captured "
                        "from network traffic) - later modules will use their built-in default values for "
                        "every field."
                    ),
                    status=ResultStatus.INFO,
                    started_at=now,
                    finished_at=now,
                    duration_ms=0.0,
                )
            )
            return

        lines = [
            f"{field_name}={value!r} (observed on {discovered_values.source_by_field_name[field_name][0]} "
            f"{discovered_values.source_by_field_name[field_name][1]})"
            for field_name, value in sorted(discovered_values.by_field_name.items())
        ]
        await self.emit(
            TestResult(
                test_case_id="RECON-005",
                category=self.category,
                name="Dynamic value resolution",
                description=(
                    "Flattens real parameter values observed in the target's own network traffic into a pool "
                    "later modules draw from (dynamic_values.py), so their payloads use this application's "
                    "actual field values instead of this suite's generic built-in defaults. Only replaces "
                    "values for fields a module already sends by that exact name -- this never changes what "
                    "shape of payload a module sends, and this suite's own defaults still apply to every field "
                    "not listed below."
                ),
                input_parameters={"resolved_fields": dict(discovered_values.by_field_name)},
                expected="N/A - informational.",
                actual=(
                    f"{len(discovered_values.by_field_name)} field(s) will use a real observed value for the "
                    "remainder of this run:\n" + "\n".join(lines)
                ),
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_mapping(self, operation: str, spec: EndpointSpec, source_call: DiscoveredCall) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id=f"RECON-MAP-{operation}",
                category=self.category,
                name=f"EndpointMap updated: {operation}",
                description=(
                    f"Discovered call {source_call.method} {source_call.path} (source={source_call.source}) matched "
                    f"the '{operation}' operation and was applied as an EndpointMap override for the rest of this "
                    "run (no manual override was configured in Settings for this operation)."
                ),
                input_parameters={"discovered_method": source_call.method, "discovered_path": source_call.path},
                expected="N/A - informational.",
                actual=f"EndpointMap['{operation}'] = {spec.method} {spec.path} (was built-in default).",
                status=ResultStatus.INFO,
                recommendation="Review this mapping before relying on it - it was applied automatically via keyword heuristics, not confirmed against your API documentation.",
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_mapping_skipped(self, operation: str, source_call: DiscoveredCall, existing: EndpointSpec) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id=f"RECON-MAP-{operation}",
                category=self.category,
                name=f"EndpointMap discovery skipped: {operation}",
                description=(
                    f"Discovered call {source_call.method} {source_call.path} (source={source_call.source}) matched "
                    f"the '{operation}' operation, but a manual override is already configured in Settings "
                    f"({existing.method} {existing.path}) - the manual override was kept, discovery not applied."
                ),
                input_parameters={"discovered_method": source_call.method, "discovered_path": source_call.path},
                expected="N/A - informational.",
                actual=f"EndpointMap['{operation}'] remains {existing.method} {existing.path} (manual override, not overwritten).",
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_crawl_failed(self, started: datetime, exc: Exception) -> None:
        finished = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="RECON-000",
                category=self.category,
                name="Recon crawl failed",
                description="Attempted to launch a headless browser and load the Test Environment URL.",
                input_parameters={"crawled_url": self.context.entry_url},
                expected="Headless browser loads the page and observes network traffic.",
                actual=f"{type(exc).__name__}: {exc}",
                status=ResultStatus.ERROR,
                recommendation=(
                    "Confirm Playwright's Chromium browser is installed in the backend container "
                    "(`playwright install chromium` - already run during the Docker image build) and that the "
                    "Test Environment URL is reachable from inside the backend container/network."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )
