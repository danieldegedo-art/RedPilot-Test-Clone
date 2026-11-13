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
