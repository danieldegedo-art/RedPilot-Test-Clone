"""Nine retrospective analyzers over the TestResults the 10 test modules
already collected this run (plus Modul 12, input_format_consistency).
None of these send a single new request to the target -- every finding
here is derived purely from response bodies, status codes, timings, and
requests ALREADY captured as evidence, which is a deliberate design
boundary (see discovery/engine.py's module docstring for why): a
compliance tool's findings need to be reproducible from the evidence it
already recorded, not from an improvised extra probe nobody can review
after the fact.

The last three (analyze_route_pattern_consistency, analyze_format_consistency,
analyze_cross_module_correlation) implement Auditor-Anforderungen 1-3.
Each was deliberately kept inside this "no new requests" boundary even
though the auditor's own phrasing ("aktiv verifizieren") describes
something further -- see each function's docstring for the specific
reasoning, and input_format_consistency.py's module docstring for where
the one genuinely new, bounded set of active requests those anforderungen
needed (Modul 12's format variants) actually lives instead.
"""
from __future__ import annotations

import re
import statistics
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from app.testing.discovery.findings import Finding
from app.testing.enums import ResultStatus
from app.testing.models import TestResult
from app.testing.modules.role_based_access import _MALICIOUS_PAYMENT_ATTRIBUTES
from app.testing.pattern_library import (
    CARD_NUMBER_RE as _CARD_NUMBER_RE,
    KNOWN_TEST_VALUES as _KNOWN_TEST_VALUES,
    SECRET_PATTERNS as _SECRET_PATTERNS,
    SENSITIVE_FIELD_NAME_RE as _SENSITIVE_FIELD_NAME_RE,
    body_as_text as _body_as_text,
    luhn_valid as _luhn_valid,
    scan_field_names as _scan_field_names,
)
from app.testing.recon.function_mapper import FunctionMap

from app.testing.discovery.vuln_knowledge import (
    ADVERSARIAL_VALIDATION_RULES,
    ATTACK_SURFACE_MAP,
    CATEGORY_CVSS_DEFAULTS,
    CVE_CHAIN_TEMPLATES,
    HEADER_SIGNATURES,
    HUNTING_SKILLS,
    PAYLOAD_REFLECTION_PATTERNS,
    RESPONSE_BODY_SIGNATURES,
    TRUST_BOUNDARY_INDICATORS,
    TrustBoundary,
    VulnCategory,
    classify_finding_confidence,
    classify_trust_boundary,
    compute_cvss_for_category,
    get_hunting_skills_for_category,
    get_surface_categories_for_path,
    match_cve_chains,
)
from app.testing.pattern_library import (
    BUSINESS_LOGIC_ARTIFACTS,
    COMMAND_INJECTION_ARTIFACTS,
    CORS_ARTIFACTS,
    DESERIALIZATION_ARTIFACTS,
    FILE_UPLOAD_ARTIFACTS,
    GRAPHQL_ABUSE_ARTIFACTS,
    HEADER_SECURITY_PATTERNS,
    INFO_DISCLOSURE_PATTERNS,
    JWT_ABUSE_ARTIFACTS,
    OPEN_REDIRECT_ARTIFACTS,
    PATH_TRAVERSAL_ARTIFACTS,
    RACE_CONDITION_ARTIFACTS,
    SQL_INJECTION_ARTIFACTS,
    SSRF_ARTIFACTS,
    XSS_ARTIFACTS,
    headers_as_text as _headers_as_text,
    scan_header_security as _scan_header_security,
    scan_injection_artifacts as _scan_injection_artifacts,
)

# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _status_of(result: TestResult) -> str:
    return result.status if isinstance(result.status, str) else result.status.value


def _request_path(result: TestResult) -> str | None:
    if result.request is None:
        return None
    return urlparse(result.request.url).path


def _normalize_path(path: str) -> str:
    """Collapses dynamic id segments (numeric, or long alnum-with-a-digit)
    so different calls to the same endpoint group together, e.g.
    "/api/v1/payments/pay_8f21a9" and ".../pay_c02e17" both normalize to
    ".../{id}"."""
    segments = path.split("/")
    normalized = []
    for segment in segments:
        if not segment:
            normalized.append(segment)
            continue
        looks_like_id = segment.isdigit() or (
            len(segment) >= 6 and re.fullmatch(r"[a-zA-Z0-9_-]+", segment) and any(c.isdigit() for c in segment)
        )
        normalized.append("{id}" if looks_like_id else segment)
    return "/".join(normalized)


_VERSION_SEGMENT_RE = re.compile(r"^v\d+$", re.IGNORECASE)


def _strip_version_segments(path: str) -> str:
    """Collapses API-version path segments (v1, v2, v3, ...) to a
    wildcard, so the same logical endpoint exposed under multiple API
    versions groups together for Modul 11's structural-similarity
    comparison (Auditor-Anforderung 1's own worked example: a route
    verified under /v1/ but never re-checked under /v2/)."""
    return "/".join("{version}" if _VERSION_SEGMENT_RE.match(segment) else segment for segment in path.split("/"))


def _structural_pattern(method: str, path: str) -> tuple[str, str]:
    """(method, path-with-ids-and-versions-collapsed) -- the "same HTTP
    method, similar path, similar parameter structure" grouping key
    Auditor-Anforderung 1 asks for, kept to two cheap, deterministic
    normalizations rather than a fuzzier (and less reviewable) similarity
    score."""
    return method, _strip_version_segments(_normalize_path(path))


# ---------------------------------------------------------------------------
# 1. Sensitive-data / secret exposure scanner
#
# Pattern definitions (secrets, card numbers, sensitive field names) now
# live in app.testing.pattern_library, shared with
# benchmark.llm_replacement_layer's zero-shot pass -- see that module's
# import above and its docstring for why.
# ---------------------------------------------------------------------------


def analyze_sensitive_data(results: list[TestResult]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)

        for name, pattern, is_critical in _SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-SECRET-{name}-{result.test_case_id}",
                        title=f"Possible sensitive-data exposure: {name.replace('_', ' ')}",
                        description=(
                            "Scans every response body collected this run (not only the deliberately-triggered "
                            "error responses ERR-003 checks) for secret/credential-shaped patterns: live Stripe "
                            "keys, AWS access key ids, PEM private key blocks, JWT-shaped tokens, and "
                            "Luhn-valid card numbers."
                        ),
                        status=ResultStatus.FAIL if is_critical else ResultStatus.WARNING,
                        observation=f"A pattern matching '{name}' was found in the response body for {result.test_case_id} ({result.name}).",
                        standard_reference="PCI-DSS Req. 3.4; OWASP API3:2023 Excessive Data Exposure",
                        source_test_case_ids=[result.test_case_id],
                        recommendation="Confirm this is not a real secret; if it is, rotate it immediately and ensure it is never included in an API response body.",
                        evidence={"pattern": name},
                    )
                )

        for match in _CARD_NUMBER_RE.finditer(text):
            digits = re.sub(r"[ -]", "", match.group())
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-SECRET-card_number-{result.test_case_id}",
                        title="Possible sensitive-data exposure: card-number-shaped value",
                        description="Same cross-run response body scan as above, specifically for Luhn-valid digit sequences shaped like a real card number.",
                        status=ResultStatus.WARNING,
                        observation=f"A {len(digits)}-digit, Luhn-valid sequence was found in the response body for {result.test_case_id} ({result.name}).",
                        standard_reference="PCI-DSS Req. 3.3/3.4",
                        source_test_case_ids=[result.test_case_id],
                        recommendation="Confirm this isn't a real card number; card numbers should never appear un-truncated in an API response.",
                        evidence={},
                    )
                )
                break  # one hit per response is enough signal; avoid spamming one result with many near-identical findings

        for field_path, field_name, _value in _scan_field_names(result.response.body):
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-SENSITIVE-FIELD-{result.test_case_id}-{field_path}",
                    title=f"Sensitive-looking field returned: {field_path}",
                    description="Flags response fields whose NAME suggests secret/credential/PII content (password, secret, api_key, cvv, ssn, ...) and which had a non-empty, non-redacted value.",
                    status=ResultStatus.WARNING,
                    observation=f"Field '{field_path}' in the response for {result.test_case_id} had a non-empty value and a name suggesting sensitive content.",
                    standard_reference="OWASP API3:2023 Excessive Data Exposure; PCI-DSS Req. 3.3/3.4",
                    source_test_case_ids=[result.test_case_id],
                    recommendation=f"Confirm '{field_name}' should be present in this API response at all; if it must be, mask or omit its value.",
                    evidence={"field_path": field_path},
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 2. Cross-endpoint resource consistency
# ---------------------------------------------------------------------------

_ID_FIELD_NAMES = (
    "id", "paymentId", "payment_id", "subscriptionId", "subscription_id", "refundId", "refund_id",
    "customerId", "customer_id", "userId", "user_id", "accountId", "account_id", "orderId", "order_id",
)
_EXEMPT_FROM_CONSISTENCY_RE = re.compile(r"(status|_at$|time|date|updated|modified|version|etag|count|balance)", re.IGNORECASE)


def analyze_cross_endpoint_consistency(results: list[TestResult]) -> list[Finding]:
    id_index: dict[str, list[tuple[TestResult, dict]]] = defaultdict(list)
    for result in results:
        body = result.response.body if result.response else None
        if not isinstance(body, dict):
            continue
        for field_name in _ID_FIELD_NAMES:
            value = body.get(field_name)
            if value and isinstance(value, (str, int)):
                id_index[str(value)].append((result, body))
                break

    conflicts_by_field: dict[str, list[tuple[str, list[str], list[str]]]] = defaultdict(list)
    for id_value, occurrences in id_index.items():
        distinct_test_cases = {r.test_case_id for r, _ in occurrences}
        if len(distinct_test_cases) < 2:
            continue

        field_values: dict[str, set[str]] = defaultdict(set)
        field_sources: dict[str, set[str]] = defaultdict(set)
        for result, body in occurrences:
            for key, value in body.items():
                if value is None or isinstance(value, (dict, list)):
                    continue
                field_values[key].add(str(value))
                field_sources[key].add(result.test_case_id)

        for field_name, values in field_values.items():
            if len(values) < 2 or _EXEMPT_FROM_CONSISTENCY_RE.search(field_name):
                continue
            conflicts_by_field[field_name].append((id_value, sorted(values), sorted(field_sources[field_name])))

    findings = []
    for field_name, conflicts in conflicts_by_field.items():
        example_id, example_values, example_sources = conflicts[0]
        all_sources = sorted({tc for _, _, sources in conflicts for tc in sources})
        findings.append(
            Finding(
                finding_id=f"DISCOVERY-CONSISTENCY-{field_name}",
                title=f"Inconsistent '{field_name}' across endpoints for the same resource",
                description=(
                    "Cross-references every response body collected this run by shared resource identifier "
                    "(payment/subscription/customer/etc. id appearing in 2+ different test cases' responses) "
                    "and diffs the overlapping fields -- generalizing LIFECYCLE-004's subscription-status check "
                    "to every resource and field this run happened to observe more than once. Timestamp/status/"
                    "counter-shaped field names are excluded, since those are expected to legitimately change."
                ),
                status=ResultStatus.WARNING,
                observation=(
                    f"Resource {example_id!r}: field '{field_name}' had {len(example_values)} different values "
                    f"({example_values}) across results {example_sources}"
                    + (f"; {len(conflicts) - 1} other resource(s) showed this same field disagree." if len(conflicts) > 1 else ".")
                ),
                standard_reference="AICPA SOC2 CC7.1 (Processing Integrity - consistency); OWASP API3:2023",
                source_test_case_ids=all_sources,
                recommendation=f"Confirm every endpoint that reports '{field_name}' for this resource type reads from the same source of truth -- a stale cache or a denormalized copy a write path forgot to update is the most common cause.",
                evidence={"conflicts": [{"resource_id": i, "values": v, "sources": s} for i, v, s in conflicts[:10]]},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 3. Response shape anomalies (undocumented / inconsistent / debug fields)
# ---------------------------------------------------------------------------

_SUSPICIOUS_FIELD_NAME_RE = re.compile(r"(^_|debug|internal|raw_|admin_only|test_only|do_not_expose|backdoor)", re.IGNORECASE)


def analyze_response_shapes(results: list[TestResult]) -> list[Finding]:
    groups: dict[tuple[str, str], list[TestResult]] = defaultdict(list)
    for result in results:
        path = _request_path(result)
        if path is None or result.response is None or not isinstance(result.response.body, dict):
            continue
        groups[(result.request.method, _normalize_path(path))].append(result)

    findings: list[Finding] = []
    for (method, path), group_results in groups.items():
        field_sets = [set(r.response.body.keys()) for r in group_results]
        union_fields = set.union(*field_sets)
        common_fields = set.intersection(*field_sets)

        if len(group_results) >= 2 and union_fields - common_fields:
            inconsistent = union_fields - common_fields
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-SHAPE-{method}-{path}",
                    title=f"Inconsistent response shape: {method} {path}",
                    description=(
                        "Groups every response this run got from the same endpoint (dynamic id segments "
                        "normalized) and compares top-level field sets -- a field present in some calls but not "
                        "others to the identical endpoint is either an undocumented conditional field or a "
                        "serialization inconsistency worth explaining."
                    ),
                    status=ResultStatus.INFO,
                    observation=(
                        f"{len(group_results)} response(s) to {method} {path}: field(s) {sorted(inconsistent)} "
                        f"appeared in only some of them (fields common to all: {sorted(common_fields)})."
                    ),
                    standard_reference="OWASP API9:2023 Improper Inventory Management",
                    source_test_case_ids=sorted({r.test_case_id for r in group_results}),
                    recommendation=None,
                    evidence={"union_fields": sorted(union_fields), "common_fields": sorted(common_fields)},
                )
            )

        suspicious = {field for fields in field_sets for field in fields if _SUSPICIOUS_FIELD_NAME_RE.search(field)}
        if suspicious:
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-DEBUGFIELD-{method}-{path}",
                    title=f"Debug/internal-looking field(s) in a response: {method} {path}",
                    description="Flags response fields whose NAME suggests debug/internal-only content (leading underscore, 'debug', 'internal', 'raw_', ...) reaching a response this suite could observe.",
                    status=ResultStatus.WARNING,
                    observation=f"{method} {path} returned field(s) {sorted(suspicious)} across {len(group_results)} response(s) this run.",
                    standard_reference="OWASP API3:2023 Excessive Data Exposure",
                    source_test_case_ids=sorted({r.test_case_id for r in group_results}),
                    recommendation="Confirm these fields are intended for API consumers; strip debug/internal-only fields before serializing a production response.",
                    evidence={"fields": sorted(suspicious)},
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 4. Timing outliers within the same endpoint
# ---------------------------------------------------------------------------

_TIMING_MODIFIED_Z_THRESHOLD = 3.5  # Iglewicz & Hoaglin's recommended cutoff for the MAD-based modified z-score
_TIMING_Z_SCORE_THRESHOLD = 2.5  # fallback threshold, only used when MAD collapses to zero (see below)
_MAD_CONSTANT = 0.6745
_MIN_SAMPLES_FOR_TIMING = 4


def _median_absolute_deviation(values: list[float], median: float) -> float:
    deviations = sorted(abs(v - median) for v in values)
    n = len(deviations)
    if n % 2 == 1:
        return deviations[n // 2]
    return (deviations[n // 2 - 1] + deviations[n // 2]) / 2


def analyze_timing_outliers(results: list[TestResult]) -> list[Finding]:
    """Uses median + median-absolute-deviation (MAD), not mean/stdev: a
    single dominant outlier in a small sample inflates the mean and stdev
    used to judge it, which can hide the very outlier those look for (a
    500ms call among six ~50ms ones can fail a mean/stdev check simply
    because it dragged the mean up itself). Median/MAD is the standard
    robust alternative precisely because a single extreme value can't drag
    the median or MAD nearly as far."""
    groups: dict[tuple[str, str], list[tuple[TestResult, float]]] = defaultdict(list)
    for result in results:
        path = _request_path(result)
        if path is None or result.response is None or result.response.error is not None:
            continue
        if not result.duration_ms or result.duration_ms <= 0:
            continue
        groups[(result.request.method, _normalize_path(path))].append((result, result.duration_ms))

    findings: list[Finding] = []
    for (method, path), pairs in groups.items():
        if len(pairs) < _MIN_SAMPLES_FOR_TIMING:
            continue
        durations = [d for _, d in pairs]
        median = statistics.median(durations)
        mad = _median_absolute_deviation(durations, median)

        if mad >= 1e-6:
            outliers = [(r, d) for r, d in pairs if abs(_MAD_CONSTANT * (d - median) / mad) > _TIMING_MODIFIED_Z_THRESHOLD]
        else:
            # MAD collapses to zero when half or more of the samples are
            # identical -- fall back to mean/stdev so a genuine outlier
            # next to a block of identical "fast" responses still gets a
            # chance to be flagged, using the same threshold semantics.
            mean = statistics.mean(durations)
            stdev = statistics.pstdev(durations)
            if stdev < 1e-6:
                continue
            outliers = [(r, d) for r, d in pairs if abs((d - mean) / stdev) > _TIMING_Z_SCORE_THRESHOLD]

        if not outliers:
            continue

        lines = [f"{r.test_case_id}: {d:.0f}ms" for r, d in outliers]
        findings.append(
            Finding(
                finding_id=f"DISCOVERY-TIMING-{method}-{path}",
                title=f"Response-time outlier(s): {method} {path}",
                description=(
                    f"Compares every response time recorded this run for the same endpoint ({len(pairs)} "
                    "sample(s)) against the group's own median using the median-absolute-deviation modified "
                    "z-score (robust to a single dominant outlier skewing a plain mean/stdev check) -- a "
                    "same-endpoint timing outlier tied to a specific input (rather than general network "
                    "jitter) is the classic signature of a timing side-channel, e.g. whether an email already "
                    "exists being inferable from response time alone."
                ),
                status=ResultStatus.INFO,
                observation=f"{len(outliers)}/{len(pairs)} call(s) to {method} {path} (group median {median:.0f}ms) were outliers:\n" + "\n".join(lines),
                standard_reference="CWE-208 Observable Timing Discrepancy",
                source_test_case_ids=sorted({r.test_case_id for r, _ in outliers}),
                recommendation="If the outlier(s) correlate with a specific input value (e.g. an email/username that does vs. doesn't already exist), consider constant-time handling for that check.",
                evidence={
                    "group_median_ms": round(median, 1),
                    "group_mad_ms": round(mad, 1),
                    "outliers": [{"test_case_id": r.test_case_id, "duration_ms": round(d, 1)} for r, d in outliers],
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 5. Coverage gap: discovered but never exercised
# ---------------------------------------------------------------------------


def analyze_coverage_gaps(results: list[TestResult], function_map: FunctionMap | None) -> list[Finding]:
    if function_map is None or not function_map.routes:
        return []

    tested_paths: set[tuple[str, str]] = set()
    for result in results:
        path = _request_path(result)
        if path is not None:
            tested_paths.add((result.request.method, path))

    untested = [route for route in function_map.routes if (route.method, route.path) not in tested_paths]
    if not untested:
        return []

    by_category: dict[str, list[str]] = defaultdict(list)
    for route in untested:
        by_category[route.category.value].append(f"{route.method} {route.path}")
    lines = [f"{category}: {', '.join(paths)}" for category, paths in sorted(by_category.items())]

    return [
        Finding(
            finding_id="DISCOVERY-COVERAGE-GAP",
            title="Route(s) discovered but never exercised by any test this run",
            description=(
                "Cross-references Recon's full FunctionMap (RECON-004) against every (method, path) any of the "
                "10 modules actually called this run -- a route Recon found but nothing tested is a gap in CC6.1 "
                "'Completeness of Service Coverage', independent of what this run's other results say."
            ),
            status=ResultStatus.INFO,
            observation=f"{len(untested)}/{len(function_map.routes)} discovered route(s) were never called by any module this run:\n" + "\n".join(lines),
            standard_reference="AICPA SOC2 CC6.1 (Completeness of Service Coverage)",
            source_test_case_ids=["RECON-004"],
            recommendation="Add an EndpointMap override and a targeted case for these routes, or confirm excluding them is intentional (e.g. genuinely unreachable or deprecated).",
            evidence={"untested_routes": [{"method": r.method, "path": r.path, "category": r.category.value} for r in untested]},
        )
    ]


# ---------------------------------------------------------------------------
# 6. Systemic pattern synthesis (aggregates other modules' OWN results)
# ---------------------------------------------------------------------------

_SYSTEMIC_FAIL_RATE_THRESHOLD = 0.3
_MIN_SAMPLES_FOR_SYSTEMIC = 3


def analyze_systemic_patterns(results: list[TestResult]) -> list[Finding]:
    findings: list[Finding] = []

    role_002 = [
        r for r in results
        if r.test_case_id.startswith("ROLE-002-") and not r.test_case_id.startswith(("ROLE-002-MATRIX", "ROLE-002-ROLLBACK"))
    ]
    if len(role_002) >= _MIN_SAMPLES_FOR_SYSTEMIC:
        failing = [r for r in role_002 if _status_of(r) == ResultStatus.FAIL.value]
        rate = len(failing) / len(role_002)
        if rate >= _SYSTEMIC_FAIL_RATE_THRESHOLD:
            findings.append(
                Finding(
                    finding_id="DISCOVERY-SYSTEMIC-MASS-ASSIGNMENT",
                    title="Mass-assignment protection appears to be missing systemically, not on one route",
                    description=(
                        "Aggregates every ROLE-002 per-route result: when a large share of tested mutating "
                        "routes accept an unauthorized payment attribute, that points at a missing shared input "
                        "filter, not an isolated oversight on one route."
                    ),
                    status=ResultStatus.FAIL,
                    observation=f"{len(failing)}/{len(role_002)} ({rate:.0%}) tested mutating routes accepted a payment/subscription attribute they shouldn't. Affected: {sorted(r.test_case_id for r in failing)[:10]}",
                    standard_reference="OWASP API3:2023 Broken Object Property Level Authorization",
                    source_test_case_ids=[r.test_case_id for r in failing],
                    recommendation="Apply one shared, allow-list-based input filter (e.g. a DTO/serializer mapping only explicitly permitted fields) across every mutating route, rather than per-route ad hoc validation.",
                    evidence={"fail_rate": round(rate, 3), "failing_count": len(failing), "total_checked": len(role_002)},
                )
            )

    role_003 = [r for r in results if r.test_case_id.startswith("ROLE-003-") and not r.test_case_id.startswith("ROLE-003-SUMMARY")]
    if len(role_003) >= _MIN_SAMPLES_FOR_SYSTEMIC:
        failing = [r for r in role_003 if _status_of(r) == ResultStatus.FAIL.value]
        rate = len(failing) / len(role_003)
        if rate >= _SYSTEMIC_FAIL_RATE_THRESHOLD:
            findings.append(
                Finding(
                    finding_id="DISCOVERY-SYSTEMIC-ACCESS-CONTROL",
                    title="System-administration access control appears to be missing systemically, not on one route",
                    description=(
                        "Aggregates every ROLE-003 per-route/method result: a high failure rate across DIFFERENT "
                        "system-administration routes points at a missing shared authorization layer (e.g. no "
                        "middleware enforcing an admin-role check), not an isolated oversight."
                    ),
                    status=ResultStatus.FAIL,
                    observation=f"{len(failing)}/{len(role_003)} ({rate:.0%}) system-administration route/method checks allowed access to the test session. Affected: {sorted(r.test_case_id for r in failing)[:10]}",
                    standard_reference="OWASP API5:2023 Broken Function Level Authorization; AICPA SOC2 CC6.1",
                    source_test_case_ids=[r.test_case_id for r in failing],
                    recommendation="Enforce admin/elevated-role authorization in shared middleware applied to the entire system-administration path prefix, rather than per-route checks that are easy to forget on a new route.",
                    evidence={"fail_rate": round(rate, 3), "failing_count": len(failing), "total_checked": len(role_003)},
                )
            )

    error_bodies: dict[str, tuple[str, ...]] = {}
    for r in results:
        if r.response is None or not isinstance(r.response.body, dict):
            continue
        if r.response.status_code is None or r.response.status_code < 400:
            continue
        error_bodies[r.test_case_id] = tuple(sorted(r.response.body.keys()))

    if len(error_bodies) >= 4:
        shape_groups: dict[tuple[str, ...], list[str]] = defaultdict(list)
        for test_case_id, fields in error_bodies.items():
            shape_groups[fields].append(test_case_id)
        if len(shape_groups) >= 3:
            shapes_desc = "; ".join(f"{list(shape)}: {test_case_ids[:3]}" for shape, test_case_ids in list(shape_groups.items())[:5])
            findings.append(
                Finding(
                    finding_id="DISCOVERY-SYSTEMIC-ERROR-SHAPE",
                    title="Error response envelope varies widely across the run",
                    description=(
                        "ERR-002 checks 3 specific error conditions for a shared envelope; this reconciles that "
                        "against EVERY 4xx/5xx JSON body any of the 10 modules collected this run, since real "
                        "client code has to handle all of them, not only ERR-002's three."
                    ),
                    status=ResultStatus.WARNING,
                    observation=f"{len(error_bodies)} error response(s) across the run fell into {len(shape_groups)} distinct field-shape groups. Examples - {shapes_desc}",
                    standard_reference="AICPA SOC2 CC7.1 (Processing Integrity - consistency)",
                    source_test_case_ids=sorted(error_bodies.keys()),
                    recommendation="Standardize on one error envelope shape returned by every error path in the application, not only the specific ones ERR-002 probes.",
                    evidence={"distinct_shapes": len(shape_groups), "total_error_responses": len(error_bodies)},
                )
            )

    return findings


# ---------------------------------------------------------------------------
# 7. Auditor-Anforderung 1 (CC7.2): route-pattern consistency
# ---------------------------------------------------------------------------


def analyze_route_pattern_consistency(results: list[TestResult]) -> list[Finding]:
    """CC7.2 Pattern-Consistency, verbatim from the auditor: "Wenn Route A
    ein Zahlungsattribut blockiert, muss Route B mit derselben Struktur
    dasselbe Attribut ebenfalls blockieren."

    Groups ROLE-002-MATRIX's rows (ROLE-002 already tests every mutating
    route Recon found, exhaustively, not a sample -- see
    role_based_access.py) by structural pattern (_structural_pattern:
    same HTTP method, same path with API-version and id segments
    collapsed), then checks whether the SAME attribute gets the SAME
    verdict on every route sharing a pattern. Reuses ROLE-002's
    already-computed verdicts only; sends no request of its own (see this
    module's top docstring, and discovery/engine.py, for why).
    """
    matrix_result = next((r for r in results if r.test_case_id == "ROLE-002-MATRIX"), None)
    if matrix_result is None:
        return []
    matrix = matrix_result.input_parameters.get("matrix")
    if not isinstance(matrix, list) or len(matrix) < 2:
        return []

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in matrix:
        if not isinstance(row, dict) or not row.get("method") or not row.get("path"):
            continue
        groups[_structural_pattern(row["method"], row["path"])].append(row)

    findings: list[Finding] = []
    for (method, pattern), members in sorted(groups.items()):
        if len(members) < 2:
            continue  # nothing structurally similar to compare against
        attribute_names: set[str] = set()
        for member in members:
            attribute_names.update(member.get("attributes", {}).keys())

        for attribute in sorted(attribute_names):
            verdicts_by_route = {f"{m['method']} {m['path']}": m.get("attributes", {}).get(attribute, "unknown") for m in members}
            if len(set(verdicts_by_route.values())) <= 1:
                continue  # consistent across every route in the group -- not a finding

            blocked_routes = sorted(route for route, verdict in verdicts_by_route.items() if verdict == "blocked")
            inconsistent = {route: verdict for route, verdict in verdicts_by_route.items() if verdict != "blocked"}
            if not blocked_routes:
                continue  # no route in the group actually blocks it -- that's DISCOVERY-SYSTEMIC-MASS-ASSIGNMENT's finding, not a pattern INconsistency
            severity = ResultStatus.FAIL if "accepted" in inconsistent.values() else ResultStatus.WARNING

            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-PATTERN-{len(findings) + 1:02d}",
                    title=f"Inconsistent '{attribute}' enforcement across structurally similar {method} routes ({pattern})",
                    description=(
                        "Auditor-Anforderung 1 / CC7.2 Pattern-Consistency: groups ROLE-002-MATRIX's "
                        "already-exhaustive per-route verdicts by structural pattern (same HTTP method, path "
                        "with API-version/id segments collapsed) and checks whether the SAME attribute gets the "
                        "SAME verdict on every route in the group."
                    ),
                    status=severity,
                    observation=(
                        f"{len(blocked_routes)} of {len(members)} structurally similar {method} route(s) block "
                        f"'{attribute}' ({blocked_routes}), but the rest do not: {inconsistent}."
                    ),
                    standard_reference="SOC2 CC7.2 (Pattern-Consistency); OWASP API3:2023",
                    source_test_case_ids=["ROLE-002-MATRIX"],
                    recommendation=(
                        f"Apply the same '{attribute}' validation on {sorted(inconsistent)} that {blocked_routes} "
                        "already enforce(s) -- these routes share the same method and path shape and are exactly "
                        "the kind of pair a Type II auditor expects to see enforcing identical controls."
                    ),
                    evidence={"method": method, "pattern": pattern, "attribute": attribute, "verdicts_by_route": verdicts_by_route},
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 8. Auditor-Anforderung 2 (ISO/IEC 25010): format-dependent consistency
# ---------------------------------------------------------------------------


def analyze_format_consistency(results: list[TestResult]) -> list[Finding]:
    """ISO/IEC 25010 Input-Validation Consistency, verbatim from the
    auditor: "Wenn Ihr System einen JSON-Payload blockiert, muss derselbe
    Payload als form-urlencoded ebenfalls blockiert werden."

    Correlates FORMAT-MATRIX (Modul 12's own per-format-variant verdicts --
    see input_format_consistency.py) against ROLE-002-MATRIX (the JSON/
    lowercase baseline) for the identical route and attribute, and flags
    any route+attribute the JSON baseline blocks but some other format
    doesn't. Deliberately NOT computed inside input_format_consistency.py
    itself -- that module only has this run's own results in hand while
    it executes, not ROLE-002's verdict as an already-finished,
    re-checkable fact; correlating finished evidence across modules is
    exactly this layer's job. Sends no request of its own.
    """
    format_matrix_result = next((r for r in results if r.test_case_id == "FORMAT-MATRIX"), None)
    role_002_matrix_result = next((r for r in results if r.test_case_id == "ROLE-002-MATRIX"), None)
    if format_matrix_result is None or role_002_matrix_result is None:
        return []
    format_rows = format_matrix_result.input_parameters.get("matrix")
    role_002_rows = role_002_matrix_result.input_parameters.get("matrix")
    if not isinstance(format_rows, list) or not isinstance(role_002_rows, list):
        return []

    role_002_by_route = {(row.get("method"), row.get("path")): row for row in role_002_rows if isinstance(row, dict)}

    findings: list[Finding] = []
    for row in format_rows:
        if not isinstance(row, dict):
            continue
        method, path = row.get("method"), row.get("path")
        baseline = role_002_by_route.get((method, path))
        baseline_attrs = baseline.get("attributes", {}) if isinstance(baseline, dict) else {}
        variants = row.get("variants", {})
        if not isinstance(variants, dict):
            continue

        for variant_info in variants.values():
            if not isinstance(variant_info, dict):
                continue
            variant_label = variant_info.get("label", "unknown format")
            variant_test_case_id = variant_info.get("test_case_id", "")
            verdicts = variant_info.get("verdicts", {})
            if not isinstance(verdicts, dict):
                continue
            for attribute, verdict in verdicts.items():
                if baseline_attrs.get(attribute) != "blocked" or verdict == "blocked":
                    continue  # only the JSON-blocks-but-this-format-doesn't case is a finding
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-FORMAT-{len(findings) + 1:02d}",
                        title=f"Format-dependent bypass: {method} {path} blocks '{attribute}' as JSON but not as {variant_label}",
                        description=(
                            "Auditor-Anforderung 2 / ISO/IEC 25010 Input-Validation Consistency: correlates "
                            "Modul 12's per-format-variant verdicts against ROLE-002's JSON/lowercase baseline "
                            "for the identical route and attribute."
                        ),
                        status=ResultStatus.FAIL,
                        observation=(
                            f"{row.get('role_002_reference', 'ROLE-002-MATRIX')} confirms '{attribute}' is blocked as "
                            f"standard JSON on {method} {path}, but the identical payload sent as {variant_label} "
                            f"({variant_test_case_id}) was '{verdict}'. Processing-Integrity for this field is "
                            "format-dependent, not enforced at the resource/business-logic layer."
                        ),
                        standard_reference="ISO/IEC 25010 (Functional Suitability, Security sub-characteristic - Input Validation); OWASP API3:2023",
                        source_test_case_ids=[row.get("role_002_reference", "ROLE-002-MATRIX"), variant_test_case_id],
                        recommendation=(
                            f"Move '{attribute}' validation to a layer that runs AFTER content-type/encoding "
                            "normalization (e.g. the ORM/model layer) instead of a JSON-only request parser, so "
                            "every wire format this endpoint accepts is covered by the same check."
                        ),
                        evidence={
                            "method": method, "path": path, "attribute": attribute, "json_baseline_verdict": "blocked",
                            "variant": variant_label, "variant_verdict": verdict,
                        },
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# 9. Auditor-Anforderung 3: cross-module correlation (Integrated Control
#    Assessment)
# ---------------------------------------------------------------------------


def analyze_cross_module_correlation(results: list[TestResult]) -> list[Finding]:
    """Auditor-Anforderung 3, verbatim: "Wenn Modul A zeigt dass Route X
    ein Attribut blockiert, und Modul B zeigt dass Route Y eine
    schwaechere Authentifizierung hat -- dann muss Ihr System die
    Korrelations-Hypothese bilden und AKTIV verifizieren ob Route Y
    dasselbe Attribut akzeptiert."

    Forms the hypothesis; deliberately does NOT "aktiv verifizieren" by
    sending Route Y a request of its own (see this module's top docstring
    and discovery/engine.py for why an autonomous, hypothesis-driven new
    request crosses a line a reproducible compliance tool shouldn't).
    Exactly two outcomes instead:

      A) ROLE-003 flagged a route as weakly-authenticated, and that SAME
         route is ALSO already in ROLE-002-MATRIX this run -- both facts
         are already fully evidenced, so this just correlates and
         prioritizes them together (the actual "Integrated Control
         Assessment" a Big-4 auditor means by the term: combining two
         already-verified findings, not manufacturing a third request).
      B) ROLE-003 flagged a route ROLE-002 never touched this run (almost
         always: only ever observed/tested via a non-mutating method).
         States the hypothesis and the EXACT (method, path) to add under
         Settings -> Manual Routes -- ROLE-002 already iterates every
         FunctionMap route exhaustively (see its own docstring), so once
         registered, next run verifies it via that same, already-audited
         methodology instead of a one-off probe this layer invents.
    """
    role_003_fails = [
        r
        for r in results
        if r.test_case_id.startswith("ROLE-003-")
        and not r.test_case_id.startswith("ROLE-003-SUMMARY")
        and _status_of(r) == ResultStatus.FAIL.value
    ]
    role_002_matrix_result = next((r for r in results if r.test_case_id == "ROLE-002-MATRIX"), None)
    if not role_003_fails or role_002_matrix_result is None:
        return []
    role_002_rows = role_002_matrix_result.input_parameters.get("matrix")
    if not isinstance(role_002_rows, list):
        return []
    role_002_paths = {row.get("path"): row for row in role_002_rows if isinstance(row, dict)}

    findings: list[Finding] = []
    seen_paths: set[str] = set()
    for weak_result in role_003_fails:
        path = _request_path(weak_result)
        method = weak_result.request.method if weak_result.request else None
        if path is None or method is None or path in seen_paths:
            continue  # ROLE-003 checks GET+POST+PUT+PATCH per route -- one correlation finding per PATH is enough
        seen_paths.add(path)

        covering_row = role_002_paths.get(path)
        if isinstance(covering_row, dict):
            risky_attrs = {k: v for k, v in covering_row.get("attributes", {}).items() if v in ("accepted", "unconfirmed")}
            if not risky_attrs:
                continue  # ROLE-002 already confirms this exact route blocks everything -- nothing compounds
            role_002_test_case_id = next(
                (
                    r.test_case_id
                    for r in results
                    if r.test_case_id.startswith("ROLE-002-")
                    and not r.test_case_id.startswith(("ROLE-002-MATRIX", "ROLE-002-ROLLBACK"))
                    and _request_path(r) == path
                ),
                "ROLE-002-MATRIX",
            )
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-CORRELATION-{len(findings) + 1:02d}",
                    title=f"Compounded risk, already confirmed: weak access control AND attribute injection on {path}",
                    description=(
                        "Auditor-Anforderung 3 / Integrated Control Assessment: ROLE-003 found this route does "
                        "not enforce access control, and ROLE-002 independently found the SAME route accepts "
                        "payment-attribute injection -- both already evidenced this run, correlated here instead "
                        "of standing as two seemingly-unrelated findings."
                    ),
                    status=ResultStatus.FAIL,
                    observation=(
                        f"{weak_result.test_case_id} confirms {path} lets the test session's own (non-admin) "
                        f"credentials through via {method}. {role_002_test_case_id} confirms the SAME route's "
                        f"response for {sorted(risky_attrs)} was {risky_attrs} -- an under-authenticated caller "
                        "can reach an endpoint that also fails to reject payment/subscription-attribute injection."
                    ),
                    standard_reference="Big-4 practice: Integrated Control Assessment; OWASP API1:2023 + API3:2023 (chained)",
                    source_test_case_ids=[weak_result.test_case_id, role_002_test_case_id],
                    recommendation=(
                        f"Prioritize {path} above either finding taken alone: the combination -- not just either "
                        "issue individually -- is what makes this directly exploitable by any authenticated user, "
                        "not only an administrator."
                    ),
                    evidence={
                        "path": path, "weak_auth_test_case_id": weak_result.test_case_id,
                        "injection_test_case_id": role_002_test_case_id, "risky_attributes": risky_attrs,
                    },
                )
            )
            continue

        # Case B: hypothesis, not yet verified. ROLE-002 is scoped to
        # PATCH/PUT/POST (see its own docstring); propose PATCH as the
        # default probe method if the weak-auth method itself wasn't
        # already a mutating one -- the QA engineer should adjust it if
        # this API's own convention for partial updates differs.
        probe_method = method if method in ("PATCH", "PUT", "POST") else "PATCH"
        findings.append(
            Finding(
                finding_id=f"DISCOVERY-CORRELATION-{len(findings) + 1:02d}",
                title=f"Untested correlation hypothesis: {path} has weak access control, mutation never attempted",
                description=(
                    "Auditor-Anforderung 3 / Integrated Control Assessment: ROLE-003 found this route does not "
                    "enforce access control, but ROLE-002's payment-attribute-injection payload was never sent "
                    "here this run (no entry for this path in ROLE-002-MATRIX) -- most likely because it was "
                    "only ever observed/tested via a non-mutating method. This analyzer forms the hypothesis and "
                    "stops there rather than sending a request of its own to check it (see this module's top "
                    "docstring); verification happens via ROLE-002's own already-audited, exhaustive methodology "
                    "on a future run, once the route below is registered."
                ),
                status=ResultStatus.WARNING,
                observation=(
                    f"{weak_result.test_case_id} confirms {path} lets the test session's own (non-admin) "
                    f"credentials through via {method}. Combined with weak access control, this route is worth "
                    "checking for payment/subscription-attribute injection too -- that check has not run yet."
                ),
                standard_reference="Big-4 practice: Integrated Control Assessment; OWASP API1:2023",
                source_test_case_ids=[weak_result.test_case_id],
                recommendation=(
                    f"Route: {path} | Methode: {probe_method} | Erwartete Payload: {dict(_MALICIOUS_PAYMENT_ATTRIBUTES)} "
                    f"| Einzutragen in Settings -> Manual Routes als method=\"{probe_method}\", path=\"{path}\". "
                    "Next run, ROLE-002 tests it automatically (it already iterates every FunctionMap route -- no "
                    "code change needed) and ROLE-003 re-verifies access control on it under the added method too."
                ),
                evidence={
                    "path": path, "weak_auth_test_case_id": weak_result.test_case_id,
                    "suggested_settings_entry": {"method": probe_method, "path": path},
                },
            )
        )
    return findings


# ===========================================================================
# ANALYZERS 10-24: Enhanced detection from 10 security knowledge sources
#
# Every analyzer below follows the SAME retrospective-analysis-only
# boundary as analyzers 1-9: they examine already-collected TestResults,
# never send a new request to the target.
# ===========================================================================


# ---------------------------------------------------------------------------
# 10. Trust boundary violation detection (Cloudflare six-phase methodology)
# ---------------------------------------------------------------------------

_AUTH_PROTECTED_BOUNDARY = {TrustBoundary.AUTHENTICATED_TO_ADMIN, TrustBoundary.PAYMENT_TO_ENTITLEMENT}
_AUTH_REJECTION_CODES = {401, 403}


def analyze_trust_boundary_violations(results: list[TestResult]) -> list[Finding]:
    """Classifies every request path into trust boundaries and flags
    requests that crossed a sensitive boundary without being rejected."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for result in results:
        path = _request_path(result)
        if path is None or result.response is None:
            continue
        boundaries = classify_trust_boundary(path)
        if not boundaries:
            continue

        status_code = result.response.status_code
        if status_code is None:
            continue

        for boundary in boundaries:
            dedup_key = f"{boundary.value}-{_normalize_path(path)}"
            if dedup_key in seen:
                continue

            is_sensitive = boundary in _AUTH_PROTECTED_BOUNDARY
            crossed_without_rejection = status_code not in _AUTH_REJECTION_CODES and status_code < 500

            if not (is_sensitive and crossed_without_rejection):
                continue

            seen.add(dedup_key)
            cvss_vec = compute_cvss_for_category(VulnCategory.BROKEN_ACCESS_CONTROL)
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-BOUNDARY-{boundary.value}-{result.test_case_id}",
                    title=f"Trust boundary '{boundary.value}' crossed without rejection on {path}",
                    description=(
                        "Cloudflare six-phase trust-boundary analysis: classifies every request "
                        "path into trust boundaries and flags when a request that should cross "
                        "a sensitive boundary (e.g. authenticated_to_admin, payment_to_entitlement) "
                        "received a success response instead of 401/403."
                    ),
                    status=ResultStatus.WARNING,
                    observation=(
                        f"Request to {path} crosses the '{boundary.value}' trust boundary "
                        f"and received HTTP {status_code} instead of 401/403. "
                        f"Test case: {result.test_case_id}."
                    ),
                    standard_reference="Cloudflare Security Audit Skill Phase 1 (Trust-Boundary Mapping); OWASP API5:2023",
                    source_test_case_ids=[result.test_case_id],
                    recommendation=(
                        f"Verify that the '{boundary.value}' boundary is enforced with "
                        "proper authentication/authorization middleware on this path."
                    ),
                    evidence={
                        "path": path, "boundary": boundary.value,
                        "status_code": status_code,
                    },
                    cvss_vector=cvss_vec.vector_string(),
                    cvss_score=cvss_vec.base_score(),
                    severity_label=cvss_vec.severity_label(),
                    vuln_category=VulnCategory.BROKEN_ACCESS_CONTROL.value,
                    confidence="needs_validation",
                    trust_boundaries=[boundary.value],
                    boundary_violation=boundary.value,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 11. Vulnerability chain synthesis (sapper-v2 fact-intent graph + BugHunter)
# ---------------------------------------------------------------------------


def analyze_vulnerability_chains(results: list[TestResult], prior_findings: list[Finding] | None = None) -> list[Finding]:
    """Collects observed vulnerability categories from prior findings and
    matches them against known CVE chain templates."""
    if not prior_findings:
        return []

    observed_cats: set[VulnCategory] = set()
    cat_sources: dict[str, list[str]] = defaultdict(list)
    for f in prior_findings:
        if f.vuln_category:
            try:
                cat = VulnCategory(f.vuln_category)
                observed_cats.add(cat)
                cat_sources[cat.value].append(f.finding_id)
            except ValueError:
                pass

    matched_chains = match_cve_chains(observed_cats)
    if not matched_chains:
        return []

    findings: list[Finding] = []
    for chain in matched_chains:
        source_ids: list[str] = []
        for step in chain.steps:
            source_ids.extend(cat_sources.get(step.value, []))

        findings.append(
            Finding(
                finding_id=f"DISCOVERY-CHAIN-{chain.chain_id}",
                title=f"Vulnerability chain detected: {chain.name}",
                description=(
                    f"CVE chain correlation (sapper-v2 fact-intent graph + BugHunter "
                    f"enterprise focus): {chain.description}"
                ),
                status=ResultStatus.FAIL,
                observation=(
                    f"All {len(chain.steps)} steps of chain '{chain.name}' are present "
                    f"in this run's findings: {[s.value for s in chain.steps]}. "
                    f"Combined CVSS: {chain.combined_cvss}. "
                    f"{chain.enterprise_context}"
                ),
                standard_reference=f"{chain.reference}; Big-4 Integrated Control Assessment",
                source_test_case_ids=source_ids[:20],
                recommendation=(
                    "Prioritize this chain above its individual findings -- the combination "
                    "of these vulnerabilities creates a complete attack path that is greater "
                    "than the sum of its parts."
                ),
                evidence={
                    "chain_id": chain.chain_id,
                    "chain_steps": [s.value for s in chain.steps],
                    "combined_cvss": chain.combined_cvss,
                    "source_findings": source_ids[:20],
                },
                cvss_score=chain.combined_cvss,
                severity_label="critical" if chain.combined_cvss >= 9.0 else "high" if chain.combined_cvss >= 7.0 else "medium",
                vuln_category=chain.steps[0].value,
                confidence="confirmed" if len(source_ids) >= 3 else "needs_validation",
                chain_id=chain.chain_id,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 12. Auth bypass pattern detection (BugHunter + Shannon)
# ---------------------------------------------------------------------------

_AUTH_PATH_RE = re.compile(r"/(?:login|signin|auth|token|oauth|saml|sso|mfa|2fa|verify|session|api-key)", re.I)
_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "x-auth-token", "cookie"}


def analyze_auth_bypass_patterns(results: list[TestResult]) -> list[Finding]:
    """Scans for authentication bypass indicators: response bodies containing
    auth tokens, requests to auth-protected paths succeeding without auth
    headers, and JWT abuse artifacts."""
    findings: list[Finding] = []
    seen: set[str] = set()

    auth_sigs = [s for s in RESPONSE_BODY_SIGNATURES if s.category == VulnCategory.AUTH_BYPASS]

    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)
        path = _request_path(result)

        for sig in auth_sigs:
            if sig.pattern and sig.pattern.search(text):
                dedup = f"auth-sig-{sig.name}-{result.test_case_id}"
                if dedup in seen:
                    continue
                seen.add(dedup)
                cvss_vec = compute_cvss_for_category(VulnCategory.AUTH_BYPASS)
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-AUTHBYPASS-{sig.name}-{result.test_case_id}",
                        title=f"Auth bypass indicator: {sig.description}",
                        description=(
                            "BugHunter auth-bypass detection: scans every response body "
                            "for indicators of authentication tokens, default credentials, "
                            "or session data that should not be exposed."
                        ),
                        status=ResultStatus.WARNING if sig.confidence != "high" else ResultStatus.FAIL,
                        observation=f"Pattern '{sig.name}' matched in response for {result.test_case_id}.",
                        standard_reference="OWASP API2:2023 Broken Authentication; CWE-287",
                        source_test_case_ids=[result.test_case_id],
                        recommendation="Verify this response does not expose authentication material to unauthorized callers.",
                        evidence={"signature": sig.name, "path": path},
                        cvss_vector=cvss_vec.vector_string(),
                        cvss_score=cvss_vec.base_score(),
                        severity_label=cvss_vec.severity_label(),
                        vuln_category=VulnCategory.AUTH_BYPASS.value,
                        confidence=sig.confidence,
                        detection_signature=sig.name,
                    )
                )

        for jwt_name, jwt_pat in JWT_ABUSE_ARTIFACTS:
            if jwt_pat.search(text):
                dedup = f"jwt-{jwt_name}-{result.test_case_id}"
                if dedup in seen:
                    continue
                seen.add(dedup)
                cvss_vec = compute_cvss_for_category(VulnCategory.AUTH_BYPASS)
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-JWT-{jwt_name}-{result.test_case_id}",
                        title=f"JWT abuse indicator: {jwt_name}",
                        description=(
                            "BugHunter JWT crypto skill (hunt-jwt-crypto): detects alg:none "
                            "stripping, RS256-to-HS256 key confusion, expired token acceptance, "
                            "and weak kid/jku/x5u parameters."
                        ),
                        status=ResultStatus.FAIL,
                        observation=f"JWT abuse pattern '{jwt_name}' found in response for {result.test_case_id}.",
                        standard_reference="OWASP API2:2023; CWE-347 Improper Verification of Cryptographic Signature",
                        source_test_case_ids=[result.test_case_id],
                        recommendation="Review JWT validation: ensure alg is pinned, signatures are verified with the correct key type, and expiry is enforced.",
                        evidence={"jwt_pattern": jwt_name, "path": path},
                        cvss_vector=cvss_vec.vector_string(),
                        cvss_score=cvss_vec.base_score(),
                        severity_label=cvss_vec.severity_label(),
                        vuln_category=VulnCategory.AUTH_BYPASS.value,
                        confidence="high",
                        hunting_skill_id="HUNT-011",
                    )
                )

        if path and _AUTH_PATH_RE.search(path) and result.response.status_code == 200:
            req_headers = {k.lower() for k in (result.request.headers or {})} if result.request else set()
            has_auth = bool(req_headers & _AUTH_HEADER_NAMES)
            if not has_auth:
                dedup = f"noauth-{_normalize_path(path)}"
                if dedup not in seen:
                    seen.add(dedup)
                    cvss_vec = compute_cvss_for_category(VulnCategory.AUTH_BYPASS)
                    findings.append(
                        Finding(
                            finding_id=f"DISCOVERY-NOAUTH-{result.test_case_id}",
                            title=f"Auth-protected path accessible without auth headers: {path}",
                            description=(
                                "Shannon white-box analysis: an authentication endpoint returned "
                                "HTTP 200 without any recognizable auth header in the request."
                            ),
                            status=ResultStatus.WARNING,
                            observation=f"Request to {path} returned 200 with no Authorization/Cookie/API-key header.",
                            standard_reference="OWASP API2:2023; CWE-306 Missing Authentication",
                            source_test_case_ids=[result.test_case_id],
                            recommendation="Confirm this endpoint requires authentication.",
                            evidence={"path": path, "request_headers": sorted(req_headers)},
                            cvss_vector=cvss_vec.vector_string(),
                            cvss_score=cvss_vec.base_score(),
                            severity_label=cvss_vec.severity_label(),
                            vuln_category=VulnCategory.AUTH_BYPASS.value,
                            confidence="needs_validation",
                            trust_boundaries=[TrustBoundary.PUBLIC_TO_AUTHENTICATED.value],
                        )
                    )
    return findings


# ---------------------------------------------------------------------------
# 13. IDOR / BOLA indicator detection (BugHunter + PayloadsAllTheThings)
# ---------------------------------------------------------------------------

_SEQUENTIAL_ID_RE = re.compile(r'"(?:id|user_id|account_id|order_id|customer_id|invoice_id)":\s*(\d{1,8})\b')
_UUID_IN_PATH_RE = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)
_NUMERIC_ID_IN_PATH_RE = re.compile(r"/(\d{1,8})(?:/|$)")


def analyze_idor_indicators(results: list[TestResult]) -> list[Finding]:
    """Scans for IDOR/BOLA indicators: sequential IDs, predictable resource
    references, and the same resource accessible from different auth contexts."""
    findings: list[Finding] = []

    id_observations: dict[str, list[tuple[TestResult, int]]] = defaultdict(list)
    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)
        for match in _SEQUENTIAL_ID_RE.finditer(text):
            id_val = int(match.group(1))
            field = match.group(0).split(":")[0].strip().strip('"')
            id_observations[field].append((result, id_val))

    for field_name, obs in id_observations.items():
        if len(obs) < 2:
            continue
        ids = sorted(set(v for _, v in obs))
        if len(ids) < 2:
            continue

        gaps = [ids[i + 1] - ids[i] for i in range(len(ids) - 1)]
        avg_gap = sum(gaps) / len(gaps) if gaps else 0
        is_sequential = avg_gap <= 5 and all(g > 0 for g in gaps)

        if is_sequential:
            source_ids = sorted({r.test_case_id for r, _ in obs})
            cvss_vec = compute_cvss_for_category(VulnCategory.IDOR)
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-IDOR-SEQ-{field_name}",
                    title=f"Sequential ID pattern in '{field_name}' enables enumeration",
                    description=(
                        "BugHunter hunt-idor skill: sequential numeric IDs in responses "
                        "indicate resource identifiers are predictable, enabling IDOR "
                        "attacks by incrementing/decrementing the ID."
                    ),
                    status=ResultStatus.WARNING,
                    observation=(
                        f"Field '{field_name}' contained {len(ids)} distinct sequential IDs "
                        f"(range {ids[0]}-{ids[-1]}, avg gap {avg_gap:.1f})."
                    ),
                    standard_reference="OWASP API1:2023 Broken Object Level Authorization; CWE-639",
                    source_test_case_ids=source_ids[:10],
                    recommendation="Replace sequential IDs with UUIDs or non-enumerable identifiers, and enforce object-level authorization checks.",
                    evidence={
                        "field": field_name, "id_count": len(ids),
                        "id_range": [ids[0], ids[-1]], "avg_gap": round(avg_gap, 1),
                    },
                    cvss_vector=cvss_vec.vector_string(),
                    cvss_score=cvss_vec.base_score(),
                    severity_label=cvss_vec.severity_label(),
                    vuln_category=VulnCategory.IDOR.value,
                    confidence="needs_validation",
                    hunting_skill_id="HUNT-010",
                )
            )

    resource_access: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for result in results:
        path = _request_path(result)
        if path is None or result.response is None or result.response.status_code != 200:
            continue
        uuid_match = _UUID_IN_PATH_RE.search(path)
        num_match = _NUMERIC_ID_IN_PATH_RE.search(path)
        resource_ref = uuid_match.group(1) if uuid_match else (num_match.group(1) if num_match else None)
        if resource_ref:
            category = result.category if isinstance(result.category, str) else result.category.value
            resource_access[resource_ref].append((result.test_case_id, category))

    for resource_id, accesses in resource_access.items():
        categories = {cat for _, cat in accesses}
        if len(categories) >= 2:
            source_ids = sorted({tc for tc, _ in accesses})
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-IDOR-XCAT-{resource_id[:16]}",
                    title=f"Resource '{resource_id[:16]}...' accessed from {len(categories)} test categories",
                    description=(
                        "Cross-category IDOR analysis: the same resource identifier appeared "
                        "in successful responses from multiple test module categories."
                    ),
                    status=ResultStatus.INFO,
                    observation=f"Resource '{resource_id}' accessed from categories: {sorted(categories)}.",
                    standard_reference="OWASP API1:2023 BOLA; CWE-639",
                    source_test_case_ids=source_ids[:10],
                    evidence={"resource_id": resource_id, "categories": sorted(categories)},
                    vuln_category=VulnCategory.IDOR.value,
                    confidence="needs_validation",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 14. Business logic flaw detection (BugHunter + PayloadsAllTheThings)
# ---------------------------------------------------------------------------


def analyze_business_logic_flaws(results: list[TestResult]) -> list[Finding]:
    """Scans response bodies for business-logic violations: negative amounts,
    zero prices, state machine violations, discount overflows."""
    findings: list[Finding] = []
    seen: set[str] = set()
    payment_skills = [s for s in HUNTING_SKILLS if s.category in (VulnCategory.PAYMENT_MANIPULATION, VulnCategory.BUSINESS_LOGIC)]

    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)
        path = _request_path(result)

        for pattern_name, pattern_re in BUSINESS_LOGIC_ARTIFACTS:
            if not pattern_re.search(text):
                continue
            dedup = f"bizlogic-{pattern_name}-{result.test_case_id}"
            if dedup in seen:
                continue
            seen.add(dedup)
            cat = VulnCategory.PAYMENT_MANIPULATION if "price" in pattern_name or "value" in pattern_name else VulnCategory.BUSINESS_LOGIC
            cvss_vec = compute_cvss_for_category(cat)
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-BIZLOGIC-{pattern_name}-{result.test_case_id}",
                    title=f"Business logic indicator: {pattern_name.replace('_', ' ')}",
                    description=(
                        "PayloadsAllTheThings business-logic + BugHunter hunt-business-logic: "
                        "detects responses showing negative amounts, zero prices, state machine "
                        "violations, discount overflows, and free premium feature access."
                    ),
                    status=ResultStatus.FAIL if "zero_price" in pattern_name or "negative" in pattern_name or "free_premium" in pattern_name else ResultStatus.WARNING,
                    observation=f"Pattern '{pattern_name}' matched in response for {result.test_case_id} (path: {path}).",
                    standard_reference="CWE-840 Business Logic Errors; OWASP Business Logic Testing",
                    source_test_case_ids=[result.test_case_id],
                    recommendation="Enforce server-side validation for all business-critical values.",
                    evidence={"pattern": pattern_name, "path": path},
                    cvss_vector=cvss_vec.vector_string(),
                    cvss_score=cvss_vec.base_score(),
                    severity_label=cvss_vec.severity_label(),
                    vuln_category=cat.value,
                    confidence="needs_validation",
                )
            )

        if isinstance(result.response.body, dict):
            body = result.response.body
            for skill in payment_skills:
                matched_indicators = [ind for ind in skill.indicators if ind in body]
                if not matched_indicators:
                    continue
                dedup = f"hunt-{skill.skill_id}-{result.test_case_id}"
                if dedup in seen:
                    continue
                seen.add(dedup)
                flagged = False
                for ind in matched_indicators:
                    val = body.get(ind)
                    if isinstance(val, (int, float)) and val <= 0:
                        flagged = True
                    elif isinstance(val, str) and val.lower() in ("null", "none", "", "0"):
                        flagged = True
                if not flagged:
                    continue

                cvss_vec = compute_cvss_for_category(skill.category)
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-HUNT-{skill.skill_id}-{result.test_case_id}",
                        title=f"Hunting skill match: {skill.name}",
                        description=skill.description,
                        status=ResultStatus.WARNING,
                        observation=f"Skill '{skill.name}' indicators {matched_indicators} found with anomalous values.",
                        standard_reference="BugHunter HackerOne Taxonomy; CWE-840",
                        source_test_case_ids=[result.test_case_id],
                        recommendation=f"Investigate {matched_indicators} values for business logic bypass.",
                        evidence={"skill_id": skill.skill_id, "matched_indicators": matched_indicators, "path": path},
                        vuln_category=skill.category.value,
                        confidence="needs_validation",
                        hunting_skill_id=skill.skill_id,
                        cvss_vector=cvss_vec.vector_string(),
                        cvss_score=cvss_vec.base_score(),
                        severity_label=cvss_vec.severity_label(),
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# 15. Privilege escalation detection (BugHunter + Shannon)
# ---------------------------------------------------------------------------

_ADMIN_INDICATOR_RE = re.compile(
    r'"(?:role|is_admin|admin|permission|privilege|access_level|user_type|account_type)"'
    r'\s*:\s*"?(?:admin|superadmin|super_admin|root|owner|manager|system|elevated|full)',
    re.I,
)
_ROLE_FIELD_RE = re.compile(r'"(?:role|roles|permissions?|scopes?|groups?|access_level)":\s*[\["{]', re.I)


def analyze_privilege_escalation(results: list[TestResult]) -> list[Finding]:
    """Scans for privilege escalation indicators: admin-level data returned
    to non-admin requests, role fields in responses."""
    findings: list[Finding] = []
    seen: set[str] = set()

    non_admin_results = [
        r for r in results
        if r.test_case_id.startswith(("ROLE-", "LIFECYCLE-", "PAY-", "AUTH-", "WEBHOOK-"))
        and r.response is not None
        and r.response.body is not None
    ]

    for result in non_admin_results:
        text = _body_as_text(result.response.body)
        path = _request_path(result)

        if _ADMIN_INDICATOR_RE.search(text):
            dedup = f"privesc-admin-{result.test_case_id}"
            if dedup in seen:
                continue
            seen.add(dedup)
            cvss_vec = compute_cvss_for_category(VulnCategory.PRIVILEGE_ESCALATION)
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-PRIVESC-{result.test_case_id}",
                    title=f"Admin-level data returned to non-admin context: {path or 'unknown'}",
                    description=(
                        "Shannon + BugHunter privilege escalation: a response from a test "
                        "module operating in a non-admin context contained admin-level "
                        "role/permission indicators."
                    ),
                    status=ResultStatus.WARNING,
                    observation=f"Admin role/permission indicator found in response for non-admin test case {result.test_case_id}.",
                    standard_reference="OWASP API5:2023 Broken Function Level Authorization; CWE-269",
                    source_test_case_ids=[result.test_case_id],
                    recommendation="Verify this response should expose admin-level role information to the requesting context.",
                    evidence={"path": path, "test_case_id": result.test_case_id},
                    cvss_vector=cvss_vec.vector_string(),
                    cvss_score=cvss_vec.base_score(),
                    severity_label=cvss_vec.severity_label(),
                    vuln_category=VulnCategory.PRIVILEGE_ESCALATION.value,
                    confidence="needs_validation",
                )
            )

        if isinstance(result.response.body, dict) and _status_of(result) == ResultStatus.FAIL.value:
            role_in_response = _ROLE_FIELD_RE.search(text)
            if role_in_response:
                dedup = f"privesc-role-{result.test_case_id}"
                if dedup not in seen:
                    seen.add(dedup)
                    findings.append(
                        Finding(
                            finding_id=f"DISCOVERY-PRIVESC-ROLE-{result.test_case_id}",
                            title=f"Role/permission field in failed-test response: {path or 'unknown'}",
                            description=(
                                "A failing test case's response contained role/permission fields, "
                                "suggesting authorization-relevant data could be manipulated."
                            ),
                            status=ResultStatus.INFO,
                            observation=f"Role/permission field detected in response body for failing test {result.test_case_id}.",
                            standard_reference="CWE-269 Improper Privilege Management",
                            source_test_case_ids=[result.test_case_id],
                            recommendation="Ensure role/permission fields are not writable via mass assignment.",
                            evidence={"path": path},
                            vuln_category=VulnCategory.PRIVILEGE_ESCALATION.value,
                            confidence="low_confidence",
                        )
                    )
    return findings


# ---------------------------------------------------------------------------
# 16. Master injection artifact scanner (PayloadsAllTheThings)
# ---------------------------------------------------------------------------


def analyze_injection_artifacts(results: list[TestResult]) -> list[Finding]:
    """Scans every response body for reflected/echoed payload indicators
    across all injection categories."""
    findings: list[Finding] = []
    seen: set[str] = set()

    all_pattern_groups: list[tuple[str, VulnCategory, list[tuple[str, re.Pattern[str]]]]] = [
        ("SQL Injection", VulnCategory.SQLI, SQL_INJECTION_ARTIFACTS),
        ("XSS", VulnCategory.XSS, XSS_ARTIFACTS),
        ("Command Injection", VulnCategory.COMMAND_INJECTION, COMMAND_INJECTION_ARTIFACTS),
        ("Path Traversal", VulnCategory.PATH_TRAVERSAL, PATH_TRAVERSAL_ARTIFACTS),
        ("Deserialization", VulnCategory.DESERIALIZATION, DESERIALIZATION_ARTIFACTS),
        ("File Upload", VulnCategory.FILE_UPLOAD, FILE_UPLOAD_ARTIFACTS),
        ("Open Redirect", VulnCategory.OPEN_REDIRECT, OPEN_REDIRECT_ARTIFACTS),
        ("GraphQL Abuse", VulnCategory.GRAPHQL_ABUSE, GRAPHQL_ABUSE_ARTIFACTS),
    ]

    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)
        if len(text) < 5:
            continue
        path = _request_path(result)

        for group_name, vuln_cat, patterns in all_pattern_groups:
            for pattern_name, pattern_re in patterns:
                match = pattern_re.search(text)
                if not match:
                    continue
                dedup = f"inject-{pattern_name}-{result.test_case_id}"
                if dedup in seen:
                    continue
                seen.add(dedup)

                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 50)
                snippet = text[start:end].strip()

                cvss_vec = compute_cvss_for_category(vuln_cat)
                severity = ResultStatus.FAIL if cvss_vec.base_score() >= 7.0 else ResultStatus.WARNING
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-INJECT-{pattern_name}-{result.test_case_id}",
                        title=f"{group_name} artifact: {pattern_name.replace('_', ' ')}",
                        description=(
                            f"PayloadsAllTheThings {group_name} detection: a pattern indicating "
                            f"reflected or processed {group_name.lower()} artifacts was found in "
                            "an already-collected response body."
                        ),
                        status=severity,
                        observation=f"Pattern '{pattern_name}' matched in response for {result.test_case_id}: ...{snippet}...",
                        standard_reference=f"OWASP Top 10; CWE mapping for {group_name}",
                        source_test_case_ids=[result.test_case_id],
                        recommendation=f"Confirm whether {group_name.lower()} input was reflected/processed unsafely.",
                        evidence={
                            "injection_type": group_name, "pattern": pattern_name,
                            "snippet": snippet[:200], "path": path,
                        },
                        cvss_vector=cvss_vec.vector_string(),
                        cvss_score=cvss_vec.base_score(),
                        severity_label=cvss_vec.severity_label(),
                        vuln_category=vuln_cat.value,
                        confidence="needs_validation",
                        detection_signature=pattern_name,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# 17. Header security analysis (Cloudflare + Shannon)
# ---------------------------------------------------------------------------


def analyze_header_security(results: list[TestResult]) -> list[Finding]:
    """Checks response headers for missing security headers and CORS
    misconfigurations."""
    findings: list[Finding] = []
    missing_header_counts: dict[str, list[str]] = defaultdict(list)
    cors_issues: list[tuple[str, str, TestResult]] = []

    for result in results:
        if result.response is None:
            continue
        headers = result.response.headers or {}
        path = _request_path(result) or "unknown"

        for _issue_name, header_name in HEADER_SECURITY_PATTERNS:
            lower_headers = {k.lower(): v for k, v in headers.items()}
            if header_name not in lower_headers:
                missing_header_counts[header_name].append(result.test_case_id)

        header_text = _headers_as_text(headers)
        for cors_name, cors_re in CORS_ARTIFACTS:
            if cors_re.search(header_text):
                cors_issues.append((cors_name, path, result))

    total_responses = sum(1 for r in results if r.response is not None)
    if total_responses > 0:
        for header_name, affected_test_cases in missing_header_counts.items():
            rate = len(affected_test_cases) / total_responses
            if rate < 0.5:
                continue
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-HEADER-MISSING-{header_name}",
                    title=f"Missing security header: {header_name}",
                    description=(
                        "Cloudflare/Shannon header security: checks every response for "
                        "critical security headers. Missing headers aggregated to identify "
                        "systemic issues."
                    ),
                    status=ResultStatus.WARNING,
                    observation=f"Header '{header_name}' missing from {len(affected_test_cases)}/{total_responses} ({rate:.0%}) responses.",
                    standard_reference="OWASP Secure Headers Project; CWE-693 Protection Mechanism Failure",
                    source_test_case_ids=sorted(set(affected_test_cases))[:10],
                    recommendation=f"Add '{header_name}' header to all responses via shared middleware.",
                    evidence={
                        "header": header_name, "missing_count": len(affected_test_cases),
                        "total_responses": total_responses, "rate": round(rate, 3),
                    },
                    vuln_category=VulnCategory.INFO_DISCLOSURE.value,
                    confidence="confirmed" if rate > 0.8 else "needs_validation",
                )
            )

    seen_cors: set[str] = set()
    for cors_name, path, result in cors_issues:
        dedup = f"cors-{cors_name}-{_normalize_path(path)}"
        if dedup in seen_cors:
            continue
        seen_cors.add(dedup)
        cvss_vec = compute_cvss_for_category(VulnCategory.CORS_MISCONFIGURATION)
        findings.append(
            Finding(
                finding_id=f"DISCOVERY-CORS-{cors_name}-{result.test_case_id}",
                title=f"CORS misconfiguration: {cors_name.replace('_', ' ')}",
                description="PayloadsAllTheThings CORS detection: wildcard origins, null origin trust, reflected origins, credentials-with-CORS.",
                status=ResultStatus.WARNING,
                observation=f"CORS issue '{cors_name}' on {path} ({result.test_case_id}).",
                standard_reference="OWASP API7:2023; CWE-942 Overly Permissive CORS Policy",
                source_test_case_ids=[result.test_case_id],
                recommendation="Restrict Access-Control-Allow-Origin to specific trusted origins.",
                evidence={"cors_issue": cors_name, "path": path},
                cvss_vector=cvss_vec.vector_string(),
                cvss_score=cvss_vec.base_score(),
                severity_label=cvss_vec.severity_label(),
                vuln_category=VulnCategory.CORS_MISCONFIGURATION.value,
                confidence="high",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 18. SSRF indicator detection (PayloadsAllTheThings + BugHunter)
# ---------------------------------------------------------------------------


def analyze_ssrf_indicators(results: list[TestResult]) -> list[Finding]:
    """Deep SSRF analysis: internal IPs, cloud metadata endpoints, DNS
    rebinding indicators, and URL-scheme echoes in response bodies."""
    findings: list[Finding] = []
    seen: set[str] = set()

    ssrf_sigs = [s for s in RESPONSE_BODY_SIGNATURES if s.category == VulnCategory.SSRF]

    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)
        path = _request_path(result)

        for sig in ssrf_sigs:
            if sig.pattern and sig.pattern.search(text):
                dedup = f"ssrf-sig-{sig.name}-{result.test_case_id}"
                if dedup in seen:
                    continue
                seen.add(dedup)
                cvss_vec = compute_cvss_for_category(VulnCategory.SSRF)
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-SSRF-{sig.name}-{result.test_case_id}",
                        title=f"SSRF indicator: {sig.description}",
                        description=(
                            "BugHunter hunt-ssrf + PayloadsAllTheThings SSRF bypass library: "
                            "detects internal IP addresses, cloud metadata responses, and "
                            "SSRF-indicative content in collected response bodies."
                        ),
                        status=ResultStatus.FAIL if sig.severity_base >= 8.0 else ResultStatus.WARNING,
                        observation=f"SSRF signature '{sig.name}' found in response for {result.test_case_id} ({path}).",
                        standard_reference="OWASP API7:2023 SSRF; CWE-918",
                        source_test_case_ids=[result.test_case_id],
                        recommendation="Block requests to internal IP ranges and cloud metadata endpoints.",
                        evidence={"signature": sig.name, "path": path},
                        cvss_vector=cvss_vec.vector_string(),
                        cvss_score=cvss_vec.base_score(),
                        severity_label=cvss_vec.severity_label(),
                        vuln_category=VulnCategory.SSRF.value,
                        confidence=sig.confidence,
                        detection_signature=sig.name,
                    )
                )

        for artifact_name, artifact_re in SSRF_ARTIFACTS:
            match = artifact_re.search(text)
            if not match:
                continue
            dedup = f"ssrf-art-{artifact_name}-{result.test_case_id}"
            if dedup in seen:
                continue
            seen.add(dedup)

            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 40)
            snippet = text[start:end].strip()
            cvss_vec = compute_cvss_for_category(VulnCategory.SSRF)
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-SSRF-ART-{artifact_name}-{result.test_case_id}",
                    title=f"SSRF artifact: {artifact_name.replace('_', ' ')}",
                    description="PayloadsAllTheThings SSRF bypass pattern detection in collected responses.",
                    status=ResultStatus.WARNING,
                    observation=f"SSRF artifact '{artifact_name}' in response: ...{snippet}...",
                    standard_reference="CWE-918; PayloadsAllTheThings SSRF Bypass Methodology",
                    source_test_case_ids=[result.test_case_id],
                    recommendation="Validate and restrict all server-side URL fetches.",
                    evidence={"artifact": artifact_name, "snippet": snippet[:200], "path": path},
                    cvss_vector=cvss_vec.vector_string(),
                    cvss_score=cvss_vec.base_score(),
                    severity_label=cvss_vec.severity_label(),
                    vuln_category=VulnCategory.SSRF.value,
                    confidence="needs_validation",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 19. CVE chain correlation at indicator level (sapper-v2 fact graph)
# ---------------------------------------------------------------------------


def analyze_cve_chain_correlation(results: list[TestResult]) -> list[Finding]:
    """Builds a fact graph of observed vulnerability indicators at the
    individual response-pattern level and matches against CVE chain templates."""
    indicator_cats: dict[VulnCategory, list[str]] = defaultdict(list)

    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)

        for sig in RESPONSE_BODY_SIGNATURES:
            if sig.pattern and sig.pattern.search(text):
                indicator_cats[sig.category].append(result.test_case_id)

        for cat, _name, pat in PAYLOAD_REFLECTION_PATTERNS:
            if pat.search(text):
                indicator_cats[cat].append(result.test_case_id)

    for result in results:
        if _status_of(result) != ResultStatus.FAIL.value:
            continue
        tc = result.test_case_id
        if tc.startswith("ROLE-002"):
            indicator_cats[VulnCategory.MASS_ASSIGNMENT].append(tc)
        elif tc.startswith("ROLE-003"):
            indicator_cats[VulnCategory.BROKEN_ACCESS_CONTROL].append(tc)
        elif tc.startswith("PAY-"):
            indicator_cats[VulnCategory.PAYMENT_MANIPULATION].append(tc)
        elif tc.startswith("AUTH-"):
            indicator_cats[VulnCategory.AUTH_BYPASS].append(tc)

    observed = set(indicator_cats.keys())
    matched_chains = match_cve_chains(observed)
    if not matched_chains:
        return []

    findings: list[Finding] = []
    for chain in matched_chains:
        source_ids: list[str] = []
        for step in chain.steps:
            source_ids.extend(indicator_cats.get(step, [])[:5])
        source_ids = sorted(set(source_ids))

        findings.append(
            Finding(
                finding_id=f"DISCOVERY-INDICATOR-CHAIN-{chain.chain_id}",
                title=f"Indicator-level chain: {chain.name}",
                description=(
                    f"sapper-v2 fact-graph correlation: response-level indicators for all "
                    f"{len(chain.steps)} steps of '{chain.name}' were observed. "
                    f"{chain.description}"
                ),
                status=ResultStatus.WARNING,
                observation=(
                    f"Indicator-level categories present: {[s.value for s in chain.steps]}. "
                    f"Combined CVSS: {chain.combined_cvss}."
                ),
                standard_reference=f"{chain.reference}; sapper-v2 Fact-Intent Graph Methodology",
                source_test_case_ids=source_ids[:15],
                recommendation="These indicators collectively suggest a viable attack chain -- investigate each step.",
                evidence={
                    "chain_id": chain.chain_id,
                    "indicator_categories": {s.value: len(indicator_cats.get(s, [])) for s in chain.steps},
                    "combined_cvss": chain.combined_cvss,
                },
                cvss_score=chain.combined_cvss,
                severity_label="high" if chain.combined_cvss >= 7.0 else "medium",
                vuln_category=chain.steps[0].value,
                confidence="needs_validation",
                chain_id=chain.chain_id,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 20. Adversarial validation (Cloudflare six-phase methodology)
# ---------------------------------------------------------------------------


def analyze_adversarial_validation(results: list[TestResult], prior_findings: list[Finding] | None = None) -> list[Finding]:
    """Re-examines all prior findings and applies adversarial validation
    rules: cross-module corroboration, temporal consistency, input
    sensitivity, status code alignment, evidence completeness."""
    if not prior_findings:
        return []

    cat_modules: dict[str, set[str]] = defaultdict(set)
    for f in prior_findings:
        if f.vuln_category:
            for tc in f.source_test_case_ids:
                prefix = tc.split("-")[0] if "-" in tc else tc
                cat_modules[f.vuln_category].add(prefix)

    upgraded = 0
    downgraded = 0
    for f in prior_findings:
        if not f.vuln_category:
            continue

        cross_module = len(cat_modules.get(f.vuln_category, set())) >= 2
        has_evidence = bool(f.evidence)
        status_aligned = f.status in (ResultStatus.FAIL, ResultStatus.WARNING)

        new_confidence = classify_finding_confidence(
            source_count=len(f.source_test_case_ids),
            cross_module=cross_module,
            status_code_aligned=status_aligned,
            evidence_complete=has_evidence,
        )

        old_conf = f.confidence or "needs_validation"
        if new_confidence == "confirmed" and old_conf != "confirmed":
            upgraded += 1
        elif new_confidence == "low_confidence" and old_conf != "low_confidence":
            downgraded += 1

        f.confidence = new_confidence
        f.confidence_factors = {
            "cross_module": cross_module,
            "multi_source": len(f.source_test_case_ids) >= 2,
            "evidence_complete": has_evidence,
            "status_aligned": status_aligned,
        }

    findings: list[Finding] = []
    conf_counts: dict[str, int] = defaultdict(int)
    for f in prior_findings:
        conf_counts[f.confidence] += 1

    findings.append(
        Finding(
            finding_id="DISCOVERY-VALIDATION-SUMMARY",
            title="Adversarial validation summary (Cloudflare six-phase)",
            description=(
                "Applied adversarial validation rules to all prior findings: "
                "cross-module corroboration, status code alignment, evidence completeness."
            ),
            status=ResultStatus.INFO,
            observation=(
                f"Validated {len(prior_findings)} finding(s): "
                f"{dict(conf_counts)}. "
                f"{upgraded} upgraded, {downgraded} downgraded."
            ),
            standard_reference="Cloudflare Security Audit Skill Phase 3 (Adversarial Candidate Validation)",
            source_test_case_ids=[],
            evidence={
                "total_validated": len(prior_findings),
                "confidence_distribution": dict(conf_counts),
                "upgraded": upgraded, "downgraded": downgraded,
            },
            validation_status="verified",
        )
    )
    return findings


# ---------------------------------------------------------------------------
# 21. Attack surface completeness (Shannon + sapper-v2)
# ---------------------------------------------------------------------------


def analyze_attack_surface_completeness(results: list[TestResult]) -> list[Finding]:
    """Checks which critical endpoint categories had zero test coverage."""
    tested_paths: set[str] = set()
    for result in results:
        path = _request_path(result)
        if path:
            tested_paths.add(path)

    findings: list[Finding] = []
    for surface in ATTACK_SURFACE_MAP:
        covered = False
        for path in tested_paths:
            for pattern in surface.path_patterns:
                if pattern.search(path):
                    covered = True
                    break
            if covered:
                break

        if not covered and surface.critical:
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-SURFACE-{surface.category_id}",
                    title=f"Critical attack surface uncovered: {surface.name}",
                    description=(
                        f"Shannon attack-surface mapping: '{surface.name}' is marked critical "
                        "but no tested path this run matched its patterns."
                    ),
                    status=ResultStatus.WARNING,
                    observation=(
                        f"Attack surface '{surface.name}' ({surface.category_id}) had zero "
                        f"test coverage. Relevant vulns: {[c.value for c in surface.vuln_categories]}."
                    ),
                    standard_reference="Shannon Coverage Analysis; AICPA SOC2 CC6.1 Completeness",
                    source_test_case_ids=[],
                    recommendation=f"Add test coverage for the '{surface.name}' surface.",
                    evidence={
                        "surface_id": surface.category_id, "surface_name": surface.name,
                        "relevant_vulns": [c.value for c in surface.vuln_categories],
                        "critical": surface.critical,
                    },
                    vuln_category=surface.vuln_categories[0].value if surface.vuln_categories else None,
                    confidence="confirmed",
                )
            )
        elif not covered and not surface.critical:
            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-SURFACE-{surface.category_id}",
                    title=f"Optional attack surface uncovered: {surface.name}",
                    description=f"Optional surface '{surface.name}' was not covered this run.",
                    status=ResultStatus.INFO,
                    observation=f"No tested paths matched '{surface.name}' patterns.",
                    standard_reference="Shannon Coverage Analysis",
                    source_test_case_ids=[],
                    evidence={"surface_id": surface.category_id, "critical": False},
                    vuln_category=surface.vuln_categories[0].value if surface.vuln_categories else None,
                    confidence="confirmed",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 22. Hunting skill application (BugHunter 24 skills)
# ---------------------------------------------------------------------------


def analyze_hunting_skill_application(results: list[TestResult]) -> list[Finding]:
    """Applies each of the 24 hunting skills against collected evidence."""
    findings: list[Finding] = []
    seen: set[str] = set()

    def _collect_keys(obj: Any, prefix: str = "") -> set[str]:
        keys: set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.add(k)
                keys.add(full)
                keys.update(_collect_keys(v, full))
        elif isinstance(obj, list):
            for item in obj:
                keys.update(_collect_keys(item, prefix))
        return keys

    for result in results:
        if result.response is None or not isinstance(result.response.body, dict):
            continue
        body = result.response.body
        path = _request_path(result)
        all_keys = _collect_keys(body)

        for skill in HUNTING_SKILLS:
            if not skill.indicators:
                continue
            matched = [ind for ind in skill.indicators if ind in all_keys]
            if not matched:
                continue

            dedup = f"skill-{skill.skill_id}-{result.test_case_id}"
            if dedup in seen:
                continue
            seen.add(dedup)

            matched_values: dict[str, Any] = {}
            for ind in matched:
                if ind in body:
                    matched_values[ind] = body[ind]

            cvss_vec = compute_cvss_for_category(skill.category)
            adjusted_score = round(cvss_vec.base_score() * skill.severity_weight, 1)

            findings.append(
                Finding(
                    finding_id=f"DISCOVERY-SKILL-{skill.skill_id}-{result.test_case_id}",
                    title=f"Hunting skill '{skill.name}' triggered",
                    description=skill.description,
                    status=ResultStatus.INFO,
                    observation=f"Skill {skill.skill_id} ({skill.name}) matched indicators {matched}.",
                    standard_reference="BugHunter 681 HackerOne Reports Taxonomy",
                    source_test_case_ids=[result.test_case_id],
                    recommendation=f"Apply {skill.name} hunting methodology to investigate.",
                    evidence={
                        "skill_id": skill.skill_id, "matched_indicators": matched,
                        "matched_values_sample": {k: str(v)[:100] for k, v in list(matched_values.items())[:5]},
                        "path": path,
                    },
                    cvss_score=adjusted_score,
                    severity_label=cvss_vec.severity_label(),
                    vuln_category=skill.category.value,
                    confidence="low_confidence",
                    hunting_skill_id=skill.skill_id,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 23. Entitlement drift detection (THE core access-without-payment chain)
# ---------------------------------------------------------------------------

_TIER_FIELD_RE = re.compile(r'"(?:plan|tier|subscription|product|plan_id|plan_name|subscription_type)":\s*"([^"]+)"', re.I)
_PAYMENT_STATUS_RE = re.compile(r'"(?:status|payment_status|subscription_status)":\s*"([^"]+)"', re.I)
_FEATURE_FLAG_RE = re.compile(r'"(?:feature_flags?|features?|entitlements?|capabilities|access_level)":\s*[\[{"]', re.I)
_PREMIUM_TIER_VALUES = {"premium", "enterprise", "pro", "business", "unlimited", "professional", "team", "growth"}
_UNPAID_STATUSES = {"trialing", "trial", "unpaid", "past_due", "canceled", "cancelled", "inactive", "free", "incomplete", "paused"}


def analyze_entitlement_drift(results: list[TestResult]) -> list[Finding]:
    """Specifically targets the access-without-payment chain (CHAIN-011).
    Looks for subscription/plan responses where tier doesn't match payment state."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for result in results:
        if result.response is None or result.response.body is None:
            continue
        text = _body_as_text(result.response.body)
        path = _request_path(result)

        tier_matches = _TIER_FIELD_RE.findall(text)
        status_matches = _PAYMENT_STATUS_RE.findall(text)
        has_feature_flags = bool(_FEATURE_FLAG_RE.search(text))

        for tier_val in tier_matches:
            tier_lower = tier_val.lower()
            if tier_lower not in _PREMIUM_TIER_VALUES:
                continue

            for status_val in status_matches:
                if status_val.lower() not in _UNPAID_STATUSES:
                    continue

                dedup = f"entitle-{tier_lower}-{status_val.lower()}-{result.test_case_id}"
                if dedup in seen:
                    continue
                seen.add(dedup)

                cvss_vec = compute_cvss_for_category(VulnCategory.ENTITLEMENT_BYPASS)
                findings.append(
                    Finding(
                        finding_id=f"DISCOVERY-ENTITLE-{result.test_case_id}",
                        title=f"Entitlement drift: '{tier_val}' tier with '{status_val}' payment status",
                        description=(
                            "THE core access-without-payment detection (CHAIN-011): "
                            "subscription response shows a premium tier but the payment "
                            "status indicates the subscription is not actively paid for."
                        ),
                        status=ResultStatus.FAIL,
                        observation=(
                            f"Response for {result.test_case_id} shows tier='{tier_val}' "
                            f"with payment_status='{status_val}'. Path: {path}."
                        ),
                        standard_reference="CWE-862 Missing Authorization; CWE-799; CHAIN-011",
                        source_test_case_ids=[result.test_case_id],
                        recommendation=(
                            "Ensure entitlement checks are coupled with payment verification -- "
                            "a subscription's tier MUST be enforced only while payment status is active."
                        ),
                        evidence={
                            "tier": tier_val, "payment_status": status_val,
                            "has_feature_flags": has_feature_flags, "path": path,
                        },
                        cvss_vector=cvss_vec.vector_string(),
                        cvss_score=cvss_vec.base_score(),
                        severity_label=cvss_vec.severity_label(),
                        vuln_category=VulnCategory.ENTITLEMENT_BYPASS.value,
                        confidence="confirmed" if status_val.lower() in ("unpaid", "canceled", "cancelled") else "needs_validation",
                        chain_id="CHAIN-011",
                        attack_complexity="low",
                    )
                )

        if has_feature_flags and not tier_matches and result.response.status_code == 200:
            if isinstance(result.response.body, dict):
                for key in ("feature_flags", "features", "entitlements", "capabilities"):
                    val = result.response.body.get(key)
                    if isinstance(val, (list, dict)) and val:
                        dedup = f"entitle-flags-{key}-{result.test_case_id}"
                        if dedup not in seen:
                            seen.add(dedup)
                            findings.append(
                                Finding(
                                    finding_id=f"DISCOVERY-ENTITLE-FLAGS-{result.test_case_id}",
                                    title=f"Feature flags exposed without tier context: {key}",
                                    description="Feature flags returned without associated subscription tier information.",
                                    status=ResultStatus.INFO,
                                    observation=f"Field '{key}' contains entries without tier context.",
                                    standard_reference="BugHunter HUNT-016 Feature Flag Leakage; CWE-862",
                                    source_test_case_ids=[result.test_case_id],
                                    evidence={"key": key, "path": path},
                                    vuln_category=VulnCategory.ENTITLEMENT_BYPASS.value,
                                    confidence="low_confidence",
                                    hunting_skill_id="HUNT-016",
                                )
                            )
    return findings


# ---------------------------------------------------------------------------
# 24. Response fingerprinting for inconsistent information leakage
# ---------------------------------------------------------------------------


def analyze_response_fingerprinting(results: list[TestResult]) -> list[Finding]:
    """Groups error responses by structural fingerprint and flags when the
    same error type returns different amounts of detail -- inconsistent
    error handling that leaks more data to some callers."""
    findings: list[Finding] = []

    error_fingerprints: dict[int, dict[tuple[str, ...], list[TestResult]]] = defaultdict(lambda: defaultdict(list))
    for result in results:
        if result.response is None or not isinstance(result.response.body, dict):
            continue
        status = result.response.status_code
        if status is None or status < 400:
            continue
        fields = tuple(sorted(result.response.body.keys()))
        error_fingerprints[status][fields].append(result)

    for status_code, shape_groups in error_fingerprints.items():
        if len(shape_groups) < 2:
            continue

        shapes = list(shape_groups.items())
        shapes_by_size = sorted(shapes, key=lambda x: len(x[0]))
        smallest_fields = set(shapes_by_size[0][0])
        largest_fields = set(shapes_by_size[-1][0])
        extra_fields = largest_fields - smallest_fields

        if not extra_fields:
            continue

        sensitive_extras = {f for f in extra_fields if _SENSITIVE_FIELD_NAME_RE.search(f) or re.search(r"(?:debug|internal|trace|stack|error_detail|sql|query|path)", f, re.I)}
        all_sources = sorted({r.test_case_id for group_results in shape_groups.values() for r in group_results})

        severity = ResultStatus.WARNING if sensitive_extras else ResultStatus.INFO
        findings.append(
            Finding(
                finding_id=f"DISCOVERY-FINGERPRINT-{status_code}",
                title=f"Inconsistent error detail for HTTP {status_code}: {len(shape_groups)} different shapes",
                description=(
                    "Response fingerprinting: the same HTTP error status code returns "
                    "different field sets to different callers, indicating inconsistent "
                    "error handling that may leak more detail to some callers."
                ),
                status=severity,
                observation=(
                    f"HTTP {status_code} responses had {len(shape_groups)} distinct field shapes. "
                    f"Extra fields in verbose responses: {sorted(extra_fields)[:10]}."
                    + (f" Sensitive: {sorted(sensitive_extras)}" if sensitive_extras else "")
                ),
                standard_reference="CWE-209 Information Exposure Through Error Message; OWASP API3:2023",
                source_test_case_ids=all_sources[:15],
                recommendation="Standardize error responses: all callers should receive the same field set.",
                evidence={
                    "status_code": status_code, "shape_count": len(shape_groups),
                    "extra_fields": sorted(extra_fields)[:20],
                    "sensitive_extras": sorted(sensitive_extras) if sensitive_extras else [],
                },
                vuln_category=VulnCategory.INFO_DISCLOSURE.value,
                confidence="confirmed" if sensitive_extras else "needs_validation",
            )
        )

    return findings
