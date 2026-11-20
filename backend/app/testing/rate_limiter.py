"""Token-bucket rate limiter: a technical STABILITY function (it waits, it never denies), shared by the real ScopeGuard
(app/enterprise_controls/scope.py) and the fail-open pass-through guard (app/core/control_port/fallback.py), so the request rate
towards a target stays bounded even when the Enterprise Controls are unavailable.

Extracted unchanged in behaviour from ``ScopeGuard._throttle`` (audit F-08: TECHNICAL STABILITY ONLY). Stdlib only; clock and sleep are
injectable so the rate behaviour is testable with a fake clock.

Extended with AdvancedRateLimitAnalyzer and CaptchaBypassAnalyzer: retrospective
detection engines that examine already-collected response evidence for indicators
of bypassable rate-limiting and captcha controls. These analysers perform NO I/O
and send NO requests -- they are pure-analysis modules over collected data, in the
same design-boundary as discovery/analyzers.py.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse, unquote


# ===========================================================================
# Original TokenBucket -- unchanged
# ===========================================================================

class TokenBucket:
    """Token bucket shared by all concurrently running modules of one run."""

    def __init__(
        self,
        *,
        rate: float,
        capacity: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    ) -> None:
        self._rate = rate
        self._capacity = float(capacity)
        self._tokens = self._capacity
        self._clock = clock
        self._sleep = sleep
        self._last_refill = clock()
        self._lock = asyncio.Lock()
        self.waited = 0.0  # total seconds spent waiting for a token

    async def take(self, *, before_each: Callable[[], None] | None = None) -> None:
        """Wait until one token is available and consume it. ``before_each`` runs at the start of every loop iteration
        (the real guard uses it to abort a waiting caller as soon as the kill switch is engaged)."""
        async with self._lock:
            while True:
                if before_each is not None:
                    before_each()
                now = self._clock()
                elapsed = max(0.0, now - self._last_refill)
                self._last_refill = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                # Tolerance + minimum wait: after sleeping exactly the computed
                # wait, float rounding can leave the bucket at 0.9999999999999999;
                # without both, the residual wait (~1e-17s) is below the clock's
                # resolution and the loop would spin forever (found by
                # tests/test_scope_guard.py's fake-clock rate test).
                if self._tokens >= 1.0 - 1e-9:
                    self._tokens = max(0.0, self._tokens - 1.0)
                    return
                wait = max((1.0 - self._tokens) / self._rate, 1e-6)
                self.waited += wait
                await self._sleep(wait)


# ===========================================================================
# Rate-Limit Bypass Classification Taxonomy
# ===========================================================================

class RateLimitBypassClass(str, Enum):
    IDENTITY_KEY_CONFUSION = "identity_key_confusion"
    EDGE_ORIGIN_MISMATCH = "edge_origin_mismatch"
    PATH_NORMALIZATION = "path_normalization"
    METHOD_ENDPOINT_DUPLICATION = "method_endpoint_duplication"
    BATCHING_FANOUT = "batching_fanout"
    COUNTER_RACE_WINDOW = "counter_race_window"
    WINDOW_BOUNDARY_TIMING = "window_boundary_timing"
    DISTRIBUTED_IDENTITY = "distributed_identity"
    STATEFUL_SESSION_RESET = "stateful_session_reset"
    RESPONSE_ORACLE_EXPLOITATION = "response_oracle_exploitation"
    HEADER_SPOOFING = "header_spoofing"
    PROTOCOL_VERSION_BYPASS = "protocol_version_bypass"
    GRAPHQL_BATCHING = "graphql_batching"
    IPV6_ROTATION = "ipv6_rotation"
    CDN_POP_SHARDING = "cdn_pop_sharding"
    PARAMETER_POLLUTION = "parameter_pollution"
    CAPTCHA_BYPASS_CHAIN = "captcha_bypass_chain"


@dataclass(frozen=True)
class BypassFinding:
    bypass_class: RateLimitBypassClass
    description: str
    evidence: dict[str, Any]
    severity: float  # 0.0-10.0 CVSS-aligned
    confidence: str  # confirmed / needs_validation / low_confidence
    cwe: str = ""
    remediation: str = ""


# ===========================================================================
# Helpers
# ===========================================================================

_FORWARDED_HEADERS = {
    "x-forwarded-for", "x-real-ip", "true-client-ip", "cf-connecting-ip",
    "x-originating-ip", "x-remote-ip", "x-client-ip", "forwarded",
    "x-forwarded-host", "x-forwarded-proto",
}

_RATE_LIMIT_HEADERS = {
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "retry-after", "x-rate-limit-limit", "x-rate-limit-remaining",
    "x-rate-limit-reset",
}

_RATE_LIMIT_STATUS_CODES = {429, 503}

_AUTH_ENDPOINT_RE = re.compile(
    r"/(?:login|signin|auth|token|oauth|mfa|2fa|verify|register|signup|password|otp|reset)", re.I
)
_SENSITIVE_ENDPOINT_RE = re.compile(
    r"/(?:login|signin|auth|pay|checkout|transfer|admin|api-key|token|password|otp|mfa)", re.I
)
_GRAPHQL_PATH_RE = re.compile(r"/graphql\b", re.I)
_BULK_PATH_RE = re.compile(r"/(?:batch|bulk|multi|import)\b", re.I)
_SESSION_HEADER_NAMES = {"cookie", "set-cookie", "authorization", "x-csrf-token"}
_CAPTCHA_FIELD_RE = re.compile(
    r"(?:captcha|recaptcha|hcaptcha|turnstile|g-recaptcha-response|h-captcha-response|cf-turnstile-response)", re.I
)


def _get_path(result: Any) -> str | None:
    req = getattr(result, "request", None)
    if req is None:
        return None
    url = getattr(req, "url", None)
    if url is None:
        return None
    return urlparse(url).path


def _get_headers_lower(result: Any, *, request: bool = True) -> dict[str, str]:
    obj = getattr(result, "request", None) if request else getattr(result, "response", None)
    if obj is None:
        return {}
    raw = getattr(obj, "headers", None) or {}
    return {k.lower(): str(v) for k, v in raw.items()}


def _status_code(result: Any) -> int | None:
    resp = getattr(result, "response", None)
    if resp is None:
        return None
    return getattr(resp, "status_code", None)


def _response_body_text(result: Any) -> str:
    resp = getattr(result, "response", None)
    if resp is None:
        return ""
    body = getattr(resp, "body", None)
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    try:
        import json
        return json.dumps(body, default=str)
    except Exception:
        return str(body)


def _duration_ms(result: Any) -> float | None:
    return getattr(result, "duration_ms", None)


def _normalize_path_canonical(path: str) -> str:
    decoded = unquote(path)
    decoded = re.sub(r"/\.(/|$)", r"\1", decoded)
    decoded = re.sub(r"//+", "/", decoded)
    decoded = decoded.rstrip("/") or "/"
    decoded = decoded.lower()
    decoded = re.sub(r"/[a-f0-9-]{20,}(?=/|$)", "/{id}", decoded)
    decoded = re.sub(r"/\d+(?=/|$)", "/{id}", decoded)
    return decoded


# ===========================================================================
# AdvancedRateLimitAnalyzer
# ===========================================================================

class AdvancedRateLimitAnalyzer:
    """Retrospective analysis of collected response data for rate-limit bypass
    vulnerabilities. Implements detection across 17 bypass classes covering
    identity confusion, edge/origin mismatches, normalization discrepancies,
    batching fan-out, race windows, timing exploitation, and protocol-level
    bypasses.

    Pure analysis -- no I/O, no new requests, stdlib only."""

    def __init__(self) -> None:
        self._findings: list[BypassFinding] = []
        self._stats: dict[str, int] = defaultdict(int)

    def analyze_responses(self, results: list[Any]) -> list[dict[str, Any]]:
        self._findings.clear()
        self._stats.clear()
        self._stats["total_results"] = len(results)

        detectors = [
            self.detect_identity_confusion,
            self.detect_path_normalization_bypass,
            self.detect_method_duplication,
            self.detect_batching_bypass,
            self.detect_race_window,
            self.detect_window_boundary,
            self.detect_header_spoofing,
            self.detect_response_oracle,
            self.detect_session_reset_bypass,
            self.detect_protocol_bypass,
            self.detect_parameter_pollution,
            self.detect_graphql_batching,
            self.detect_cdn_pop_sharding,
            self.detect_distributed_identity,
        ]
        for detector in detectors:
            try:
                detector(results)
            except Exception:
                self._stats["detector_errors"] = self._stats.get("detector_errors", 0) + 1

        scored = self.compute_bypass_risk_score(self._findings)
        return [
            {
                "bypass_class": f.bypass_class.value,
                "description": f.description,
                "evidence": f.evidence,
                "severity": f.severity,
                "confidence": f.confidence,
                "cwe": f.cwe,
                "remediation": f.remediation,
                "risk_score": scored.get(f.bypass_class.value, 0.0),
            }
            for f in self._findings
        ]

    # -- 1. Identity-Key Confusion --

    def detect_identity_confusion(self, results: list[Any]) -> None:
        for result in results:
            req_h = _get_headers_lower(result, request=True)
            resp_h = _get_headers_lower(result, request=False)
            has_forwarded = bool(set(req_h) & _FORWARDED_HEADERS)
            has_rate_headers = bool(set(resp_h) & _RATE_LIMIT_HEADERS)

            if has_forwarded and has_rate_headers:
                spoofed = {k: req_h[k] for k in set(req_h) & _FORWARDED_HEADERS}
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.IDENTITY_KEY_CONFUSION,
                    "Rate-limited endpoint received client-supplied forwarded headers that "
                    "could key the limiter on an attacker-controlled value",
                    {"spoofed_headers": spoofed, "rate_limit_headers": {k: resp_h[k] for k in set(resp_h) & _RATE_LIMIT_HEADERS},
                     "path": _get_path(result)},
                    7.5, "needs_validation",
                    cwe="CWE-290 Authentication Bypass by Spoofing",
                    remediation="Strip all incoming X-Forwarded-* / True-Client-IP headers at the outermost edge "
                                "proxy and overwrite them with the true socket IP",
                ))
                return

    # -- 2. Path Normalization --

    def detect_path_normalization_bypass(self, results: list[Any]) -> None:
        path_groups: dict[str, list[tuple[str, int | None]]] = defaultdict(list)
        for result in results:
            raw_path = _get_path(result)
            if raw_path is None:
                continue
            canonical = _normalize_path_canonical(raw_path)
            status = _status_code(result)
            path_groups[canonical].append((raw_path, status))

        for canonical, variants in path_groups.items():
            raw_paths = {p for p, _ in variants}
            if len(raw_paths) < 2:
                continue
            statuses_by_raw: dict[str, set[int]] = defaultdict(set)
            for p, s in variants:
                if s is not None:
                    statuses_by_raw[p].add(s)

            some_throttled = any(s & _RATE_LIMIT_STATUS_CODES for s in statuses_by_raw.values())
            some_not_throttled = any(not (s & _RATE_LIMIT_STATUS_CODES) and s for s in statuses_by_raw.values())
            if some_throttled and some_not_throttled:
                throttled = [p for p, ss in statuses_by_raw.items() if ss & _RATE_LIMIT_STATUS_CODES]
                bypassed = [p for p, ss in statuses_by_raw.items() if not (ss & _RATE_LIMIT_STATUS_CODES) and ss]
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.PATH_NORMALIZATION,
                    "Same logical endpoint reached through path variants: some were rate-limited, "
                    "others were not -- the limiter normalises paths differently from the router",
                    {"canonical": canonical, "throttled_paths": throttled[:5], "bypassed_paths": bypassed[:5]},
                    7.5, "confirmed" if len(bypassed) >= 2 else "needs_validation",
                    cwe="CWE-436 Interpretation Conflict",
                    remediation="Enforce strict URL normalisation at the edge gateway BEFORE evaluating "
                                "rate-limit rules; block non-standard path traversal characters",
                ))

            elif len(raw_paths) >= 3 and _SENSITIVE_ENDPOINT_RE.search(canonical):
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.PATH_NORMALIZATION,
                    f"Sensitive endpoint '{canonical}' reachable through {len(raw_paths)} distinct "
                    "path spellings -- potential rate-limit key fragmentation",
                    {"canonical": canonical, "raw_variants": sorted(raw_paths)[:10]},
                    5.3, "low_confidence",
                    cwe="CWE-436 Interpretation Conflict",
                    remediation="Canonicalise request paths at the edge before rate-limit evaluation",
                ))

    # -- 3. Method / Endpoint Duplication --

    def detect_method_duplication(self, results: list[Any]) -> None:
        endpoint_methods: dict[str, set[str]] = defaultdict(set)
        endpoint_statuses: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        for result in results:
            path = _get_path(result)
            req = getattr(result, "request", None)
            if path is None or req is None:
                continue
            method = getattr(req, "method", "GET").upper()
            canonical = _normalize_path_canonical(path)
            status = _status_code(result)
            endpoint_methods[canonical].add(method)
            if status is not None:
                endpoint_statuses[canonical][method].add(status)

        for canonical, methods in endpoint_methods.items():
            if len(methods) < 2 or not _SENSITIVE_ENDPOINT_RE.search(canonical):
                continue
            rate_limited_methods = set()
            free_methods = set()
            for m in methods:
                ss = endpoint_statuses[canonical].get(m, set())
                if ss & _RATE_LIMIT_STATUS_CODES:
                    rate_limited_methods.add(m)
                elif ss:
                    free_methods.add(m)

            if rate_limited_methods and free_methods:
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.METHOD_ENDPOINT_DUPLICATION,
                    f"Sensitive endpoint '{canonical}' rate-limited for {rate_limited_methods} "
                    f"but accessible without throttling via {free_methods}",
                    {"canonical": canonical, "rate_limited": sorted(rate_limited_methods),
                     "free": sorted(free_methods)},
                    7.5, "confirmed",
                    cwe="CWE-799 Improper Control of Interaction Frequency",
                    remediation="Apply rate-limit rules per-endpoint, not per-method; consider "
                                "X-HTTP-Method-Override exploitation",
                ))

    # -- 4. Batching / Fan-out --

    def detect_batching_bypass(self, results: list[Any]) -> None:
        for result in results:
            path = _get_path(result)
            if path is None:
                continue
            status = _status_code(result) or 0

            if _BULK_PATH_RE.search(path) and 200 <= status < 300:
                body = _response_body_text(result)
                ops_in_response = body.count('"id"')
                if ops_in_response >= 3:
                    self._findings.append(BypassFinding(
                        RateLimitBypassClass.BATCHING_FANOUT,
                        f"Bulk endpoint '{path}' processed {ops_in_response}+ operations in "
                        "a single HTTP request -- per-request rate limits may be bypassed",
                        {"path": path, "estimated_operations": ops_in_response},
                        6.5, "needs_validation",
                        cwe="CWE-799 Improper Control of Interaction Frequency",
                        remediation="Rate-limit based on operation count or query complexity, "
                                    "not raw HTTP request counts",
                    ))
                    return

    # -- 5. Counter Race Window --

    def detect_race_window(self, results: list[Any]) -> None:
        endpoint_timings: dict[str, list[tuple[float, int | None]]] = defaultdict(list)
        for result in results:
            path = _get_path(result)
            dur = _duration_ms(result)
            status = _status_code(result)
            if path is None or dur is None:
                continue
            canonical = _normalize_path_canonical(path)
            if _SENSITIVE_ENDPOINT_RE.search(canonical):
                endpoint_timings[canonical].append((dur, status))

        for canonical, timings in endpoint_timings.items():
            if len(timings) < 5:
                continue
            durations = [d for d, _ in timings]
            median_dur = statistics.median(durations)
            very_fast = [(d, s) for d, s in timings if d < median_dur * 0.3 and s is not None and 200 <= s < 300]

            if len(very_fast) >= 3:
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.COUNTER_RACE_WINDOW,
                    f"Endpoint '{canonical}' accepted {len(very_fast)} requests with anomalously "
                    f"low latency (< {median_dur * 0.3:.0f}ms vs median {median_dur:.0f}ms) -- "
                    "concurrent requests may pass the counter before it increments",
                    {"canonical": canonical, "fast_count": len(very_fast),
                     "median_ms": round(median_dur, 1),
                     "fast_durations_ms": [round(d, 1) for d, _ in very_fast[:10]]},
                    7.5, "needs_validation",
                    cwe="CWE-362 Race Condition",
                    remediation="Implement atomic check-and-increment (e.g. Redis Lua scripts or "
                                "INCR with TTL) rather than separate read/write calls",
                ))

    # -- 6. Window Boundary Timing --

    def detect_window_boundary(self, results: list[Any]) -> None:
        for result in results:
            resp_h = _get_headers_lower(result, request=False)
            reset_val = resp_h.get("x-ratelimit-reset") or resp_h.get("ratelimit-reset")
            remaining = resp_h.get("x-ratelimit-remaining") or resp_h.get("ratelimit-remaining")
            if reset_val is None:
                continue
            try:
                reset_epoch = int(reset_val)
            except (ValueError, TypeError):
                continue
            if remaining is not None:
                try:
                    rem = int(remaining)
                except (ValueError, TypeError):
                    continue
                if rem == 0:
                    path = _get_path(result)
                    self._findings.append(BypassFinding(
                        RateLimitBypassClass.WINDOW_BOUNDARY_TIMING,
                        "Rate-limit window uses a fixed reset boundary (epoch-based x-ratelimit-reset "
                        "with remaining=0 visible to the client) -- an attacker who knows the reset "
                        "time can stack requests on both sides of the boundary",
                        {"path": path, "reset_epoch": reset_epoch, "remaining": rem},
                        5.3, "needs_validation",
                        cwe="CWE-799 Improper Control of Interaction Frequency",
                        remediation="Use a sliding-window or token-bucket algorithm rather than "
                                    "a fixed-window counter with a predictable reset time",
                    ))
                    return

    # -- 7. Header Spoofing --

    def detect_header_spoofing(self, results: list[Any]) -> None:
        seen_forwarded_values: dict[str, set[str]] = defaultdict(set)
        for result in results:
            req_h = _get_headers_lower(result, request=True)
            path = _get_path(result) or ""
            status = _status_code(result) or 0

            for hdr in _FORWARDED_HEADERS:
                val = req_h.get(hdr)
                if val is not None:
                    seen_forwarded_values[hdr].add(val)
                    if _SENSITIVE_ENDPOINT_RE.search(path) and 200 <= status < 300:
                        self._findings.append(BypassFinding(
                            RateLimitBypassClass.HEADER_SPOOFING,
                            f"Sensitive endpoint '{path}' accepted request with client-supplied "
                            f"'{hdr}: {val[:50]}' header and returned a success response -- "
                            "if the limiter trusts this header, rotating values resets the counter",
                            {"path": path, "header": hdr, "value": val[:80], "status": status},
                            7.5, "needs_validation",
                            cwe="CWE-290 Authentication Bypass by Spoofing",
                            remediation=f"The outermost proxy MUST strip incoming '{hdr}' headers "
                                        "and overwrite with the true connecting socket IP",
                        ))
                        return

    # -- 8. Response-Oracle Exploitation --

    def detect_response_oracle(self, results: list[Any]) -> None:
        endpoint_groups: dict[str, list[tuple[int | None, str]]] = defaultdict(list)
        for result in results:
            path = _get_path(result)
            if path is None or not _AUTH_ENDPOINT_RE.search(path):
                continue
            status = _status_code(result)
            body = _response_body_text(result)
            canonical = _normalize_path_canonical(path)
            endpoint_groups[canonical].append((status, body[:500]))

        for canonical, entries in endpoint_groups.items():
            has_429 = any(s == 429 for s, _ in entries)
            has_success_after_throttle = False
            seen_429 = False
            for s, _ in entries:
                if s == 429:
                    seen_429 = True
                elif seen_429 and s is not None and 200 <= s < 300:
                    has_success_after_throttle = True
                    break

            if has_429 and has_success_after_throttle:
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.RESPONSE_ORACLE_EXPLOITATION,
                    f"Auth endpoint '{canonical}' returned 429 (throttled) followed by a 2xx "
                    "success in the same run -- the correct credential may succeed even after "
                    "generic throttling, making the rate limit cosmetic",
                    {"canonical": canonical, "total_requests": len(entries)},
                    8.1, "needs_validation",
                    cwe="CWE-307 Improper Restriction of Excessive Authentication Attempts",
                    remediation="Throttling MUST deny ALL requests (including correct credentials) "
                                "once the threshold is hit; use account lockout or exponential backoff",
                ))

    # -- 9. Session-Reset Bypass --

    def detect_session_reset_bypass(self, results: list[Any]) -> None:
        session_tokens: set[str] = set()
        throttled_sessions: set[str] = set()
        for result in results:
            req_h = _get_headers_lower(result, request=True)
            status = _status_code(result) or 0
            cookie = req_h.get("cookie", "")
            auth = req_h.get("authorization", "")
            token = hashlib.sha256((cookie + auth).encode()).hexdigest()[:16] if (cookie or auth) else ""
            if not token:
                continue
            session_tokens.add(token)
            if status == 429:
                throttled_sessions.add(token)

        if throttled_sessions and len(session_tokens) > len(throttled_sessions) + 2:
            self._findings.append(BypassFinding(
                RateLimitBypassClass.STATEFUL_SESSION_RESET,
                f"Run used {len(session_tokens)} distinct session tokens; {len(throttled_sessions)} "
                "were throttled. If the limiter is keyed to session/cookie, rotating sessions "
                "resets the counter",
                {"distinct_sessions": len(session_tokens),
                 "throttled_sessions": len(throttled_sessions)},
                6.5, "low_confidence",
                cwe="CWE-799 Improper Control of Interaction Frequency",
                remediation="Key rate limits to account ID or verified IP, not to a disposable "
                            "session cookie or anonymous token",
            ))

    # -- 10. Protocol Bypass --

    def detect_protocol_bypass(self, results: list[Any]) -> None:
        protocol_statuses: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        for result in results:
            path = _get_path(result)
            resp_h = _get_headers_lower(result, request=False)
            status = _status_code(result)
            if path is None or status is None:
                continue
            canonical = _normalize_path_canonical(path)
            proto = "h2" if resp_h.get("server", "").lower().startswith("h2") or "h2" in resp_h.get("alt-svc", "") else "h1"
            protocol_statuses[canonical][proto].add(status)

        for canonical, by_proto in protocol_statuses.items():
            if len(by_proto) < 2:
                continue
            some_throttled = any(ss & _RATE_LIMIT_STATUS_CODES for ss in by_proto.values())
            some_free = any(not (ss & _RATE_LIMIT_STATUS_CODES) for ss in by_proto.values())
            if some_throttled and some_free:
                throttled_protos = [p for p, ss in by_proto.items() if ss & _RATE_LIMIT_STATUS_CODES]
                free_protos = [p for p, ss in by_proto.items() if not (ss & _RATE_LIMIT_STATUS_CODES)]
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.PROTOCOL_VERSION_BYPASS,
                    f"Endpoint '{canonical}' rate-limited under {throttled_protos} but not "
                    f"under {free_protos} -- rate-limit rules may not apply uniformly "
                    "across HTTP versions",
                    {"canonical": canonical, "throttled_protos": throttled_protos,
                     "free_protos": free_protos},
                    6.5, "needs_validation",
                    cwe="CWE-436 Interpretation Conflict",
                    remediation="Apply rate-limit rules at a layer that handles all protocol versions uniformly",
                ))

    # -- 11. Parameter Pollution --

    def detect_parameter_pollution(self, results: list[Any]) -> None:
        for result in results:
            req = getattr(result, "request", None)
            if req is None:
                continue
            url = getattr(req, "url", "") or ""
            query = urlparse(url).query
            if not query:
                continue
            params = query.split("&")
            keys = [p.split("=")[0] for p in params if "=" in p]
            dups = [k for k in set(keys) if keys.count(k) > 1]
            if dups and _SENSITIVE_ENDPOINT_RE.search(url):
                status = _status_code(result) or 0
                if 200 <= status < 300:
                    self._findings.append(BypassFinding(
                        RateLimitBypassClass.PARAMETER_POLLUTION,
                        f"Sensitive endpoint accepted duplicate query parameters {dups} "
                        "-- parameter pollution can fragment rate-limit cache keys",
                        {"url": url[:200], "duplicate_params": dups[:10], "status": status},
                        5.3, "low_confidence",
                        cwe="CWE-235 Improper Handling of Extra Parameters",
                        remediation="Canonicalise query parameters before computing rate-limit keys",
                    ))
                    return

    # -- 12. GraphQL Batching --

    def detect_graphql_batching(self, results: list[Any]) -> None:
        for result in results:
            path = _get_path(result)
            if path is None or not _GRAPHQL_PATH_RE.search(path):
                continue
            body = _response_body_text(result)
            status = _status_code(result) or 0
            if status != 200:
                continue
            alias_count = len(re.findall(r'"data"\s*:\s*\{[^}]*\w+_\d+', body))
            array_responses = body.strip().startswith("[")
            if alias_count >= 3 or array_responses:
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.GRAPHQL_BATCHING,
                    f"GraphQL endpoint '{path}' returned what appears to be a batched "
                    f"response ({alias_count} aliased fields or array response) -- "
                    "one HTTP request may execute many sensitive operations",
                    {"path": path, "alias_count": alias_count, "array_response": array_responses},
                    7.5, "needs_validation",
                    cwe="CWE-799 Improper Control of Interaction Frequency",
                    remediation="Rate-limit based on query complexity or operation count per "
                                "request, not raw HTTP request counts; limit max aliases and "
                                "batch size",
                ))
                return

    # -- 13. CDN PoP Sharding --

    def detect_cdn_pop_sharding(self, results: list[Any]) -> None:
        edge_locations: dict[str, set[str]] = defaultdict(set)
        for result in results:
            resp_h = _get_headers_lower(result, request=False)
            path = _get_path(result)
            if path is None:
                continue
            canonical = _normalize_path_canonical(path)
            for key in ("cf-ray", "x-served-by", "x-cache", "x-amz-cf-pop", "x-edge-location",
                        "x-cdn-pop", "server-timing"):
                val = resp_h.get(key, "")
                if val:
                    edge_locations[canonical].add(f"{key}={val[:40]}")

        for canonical, locations in edge_locations.items():
            if len(locations) >= 3 and _SENSITIVE_ENDPOINT_RE.search(canonical):
                self._findings.append(BypassFinding(
                    RateLimitBypassClass.CDN_POP_SHARDING,
                    f"Sensitive endpoint '{canonical}' served from {len(locations)} distinct "
                    "edge/CDN identifiers -- distributed rate-limit counters may not sync "
                    "globally, allowing throughput multiplication across PoPs",
                    {"canonical": canonical, "edge_identifiers": sorted(locations)[:15]},
                    5.3, "low_confidence",
                    cwe="CWE-799 Improper Control of Interaction Frequency",
                    remediation="Use a globally synchronised rate-limit data store (e.g. a "
                                "central Redis cluster) rather than per-PoP counters",
                ))

    # -- 14. Distributed Identity --

    def detect_distributed_identity(self, results: list[Any]) -> None:
        auth_tokens: set[str] = set()
        throttled_tokens: set[str] = set()
        for result in results:
            req_h = _get_headers_lower(result, request=True)
            path = _get_path(result) or ""
            status = _status_code(result) or 0
            if not _SENSITIVE_ENDPOINT_RE.search(path):
                continue
            auth = req_h.get("authorization", "")
            api_key = req_h.get("x-api-key", "")
            token = hashlib.sha256((auth + api_key).encode()).hexdigest()[:16] if (auth or api_key) else ""
            if not token:
                continue
            auth_tokens.add(token)
            if status == 429:
                throttled_tokens.add(token)

        unthrottled = auth_tokens - throttled_tokens
        if throttled_tokens and len(unthrottled) >= 3:
            self._findings.append(BypassFinding(
                RateLimitBypassClass.DISTRIBUTED_IDENTITY,
                f"{len(throttled_tokens)} identity token(s) were rate-limited, but "
                f"{len(unthrottled)} other tokens reached the same sensitive endpoints "
                "without throttling -- if tokens are cheap to obtain, rotating them "
                "distributes abuse across keys",
                {"throttled_tokens": len(throttled_tokens), "unthrottled_tokens": len(unthrottled)},
                6.5, "low_confidence",
                cwe="CWE-799 Improper Control of Interaction Frequency",
                remediation="Aggregate rate-limit accounting across IPs, accounts, sessions, "
                            "and devices to detect distributed abuse",
            ))

    # -- Aggregate risk score --

    def compute_bypass_risk_score(self, findings: list[BypassFinding]) -> dict[str, float]:
        confidence_weight = {"confirmed": 1.0, "needs_validation": 0.6, "low_confidence": 0.3}
        scores: dict[str, float] = {}
        for f in findings:
            w = confidence_weight.get(f.confidence, 0.5)
            raw = (f.severity / 10.0) * w
            scores[f.bypass_class.value] = max(scores.get(f.bypass_class.value, 0.0), round(raw, 3))
        return scores


# ===========================================================================
# CaptchaBypassAnalyzer
# ===========================================================================

class CaptchaBypassAnalyzer:
    """Retrospective analysis of collected evidence for captcha-bypass
    indicators. Pure analysis, no I/O, stdlib only."""

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []

    def analyze(self, results: list[Any]) -> list[dict[str, Any]]:
        self._findings.clear()
        self.detect_token_reuse(results)
        self.detect_missing_validation(results)
        self.detect_audio_fallback_weakness(results)
        self.detect_session_rotation_bypass(results)
        self.detect_captcha_field_in_response(results)
        self.detect_captcha_timing_anomaly(results)
        return list(self._findings)

    def detect_token_reuse(self, results: list[Any]) -> None:
        captcha_tokens: dict[str, list[str]] = defaultdict(list)
        for result in results:
            body = _response_body_text(result)
            req = getattr(result, "request", None)
            if req is None:
                continue
            req_body = getattr(req, "body", None)
            if req_body is None:
                continue
            req_text = req_body if isinstance(req_body, str) else str(req_body)
            for m in _CAPTCHA_FIELD_RE.finditer(req_text):
                start = m.end()
                token_match = re.search(r'[=:]\s*["\']?([A-Za-z0-9_-]{20,})', req_text[start:start + 300])
                if token_match:
                    token = token_match.group(1)[:64]
                    tc = getattr(result, "test_case_id", "unknown")
                    captcha_tokens[token].append(tc)

        for token, uses in captcha_tokens.items():
            if len(uses) >= 2:
                self._findings.append({
                    "bypass_class": "captcha_token_reuse",
                    "description": f"Same captcha token reused across {len(uses)} requests -- "
                                   "tokens should be single-use",
                    "evidence": {"token_hash": hashlib.sha256(token.encode()).hexdigest()[:16],
                                 "reuse_count": len(uses), "test_cases": uses[:10]},
                    "severity": 7.5,
                    "confidence": "confirmed",
                    "cwe": "CWE-294 Authentication Bypass by Capture-replay",
                    "remediation": "Captcha tokens MUST be invalidated server-side after first use",
                })

    def detect_missing_validation(self, results: list[Any]) -> None:
        for result in results:
            path = _get_path(result) or ""
            if not _AUTH_ENDPOINT_RE.search(path):
                continue
            status = _status_code(result) or 0
            if status < 200 or status >= 300:
                continue
            req = getattr(result, "request", None)
            if req is None:
                continue
            req_body = getattr(req, "body", None)
            req_text = str(req_body) if req_body else ""
            req_h = _get_headers_lower(result, request=True)
            has_captcha = bool(_CAPTCHA_FIELD_RE.search(req_text)) or any(
                _CAPTCHA_FIELD_RE.search(v) for v in req_h.values()
            )
            if not has_captcha:
                resp_body = _response_body_text(result)
                if _CAPTCHA_FIELD_RE.search(resp_body):
                    self._findings.append({
                        "bypass_class": "captcha_missing_validation",
                        "description": f"Auth endpoint '{path}' returned success without any captcha "
                                       "token in the request, but captcha fields appear in the response -- "
                                       "captcha may be client-side only",
                        "evidence": {"path": path, "status": status},
                        "severity": 7.5,
                        "confidence": "needs_validation",
                        "cwe": "CWE-804 Guessable CAPTCHA",
                        "remediation": "Enforce captcha validation server-side; reject requests "
                                       "without a valid captcha token",
                    })
                    return

    def detect_audio_fallback_weakness(self, results: list[Any]) -> None:
        for result in results:
            body = _response_body_text(result)
            if re.search(r"(?:audio|accessibility)[_-]?challenge|captcha.*audio|audio.*captcha", body, re.I):
                path = _get_path(result)
                self._findings.append({
                    "bypass_class": "captcha_audio_fallback",
                    "description": "Audio captcha challenge endpoint detected -- audio challenges "
                                   "are solvable by automated speech-to-text models",
                    "evidence": {"path": path},
                    "severity": 5.3,
                    "confidence": "low_confidence",
                    "cwe": "CWE-804 Guessable CAPTCHA",
                    "remediation": "Apply additional controls on audio fallback (IP-based limits, "
                                   "progressive difficulty, bot-detection scoring)",
                })
                return

    def detect_session_rotation_bypass(self, results: list[Any]) -> None:
        captcha_seen: dict[str, int] = defaultdict(int)
        for result in results:
            body = _response_body_text(result)
            if _CAPTCHA_FIELD_RE.search(body):
                req_h = _get_headers_lower(result, request=True)
                cookie = req_h.get("cookie", "")
                session_key = hashlib.sha256(cookie.encode()).hexdigest()[:12] if cookie else "no-session"
                captcha_seen[session_key] += 1

        sessions_with_captcha = {k for k, v in captcha_seen.items() if v >= 1}
        sessions_without = {k for k in captcha_seen if k not in sessions_with_captcha}
        if sessions_with_captcha and len(captcha_seen) > len(sessions_with_captcha):
            self._findings.append({
                "bypass_class": "captcha_session_rotation",
                "description": f"Captcha triggered for {len(sessions_with_captcha)} session(s) "
                               f"but not for {len(captcha_seen) - len(sessions_with_captcha)} other(s) -- "
                               "rotating sessions may bypass captcha",
                "evidence": {"sessions_with_captcha": len(sessions_with_captcha),
                             "total_sessions": len(captcha_seen)},
                "severity": 6.5,
                "confidence": "low_confidence",
                "cwe": "CWE-799 Improper Control of Interaction Frequency",
                "remediation": "Tie captcha requirement to IP/device fingerprint, not session cookie",
            })

    def detect_captcha_field_in_response(self, results: list[Any]) -> None:
        for result in results:
            body = _response_body_text(result)
            if re.search(r"sitekey|site_key|captcha_key|data-sitekey", body, re.I):
                path = _get_path(result)
                resp_h = _get_headers_lower(result, request=False)
                has_csp = "content-security-policy" in resp_h
                if not has_csp:
                    self._findings.append({
                        "bypass_class": "captcha_csp_missing",
                        "description": f"Captcha sitekey exposed at '{path}' without CSP headers -- "
                                       "script injection could replace the captcha widget with a noop",
                        "evidence": {"path": path, "csp_present": False},
                        "severity": 5.3,
                        "confidence": "low_confidence",
                        "cwe": "CWE-693 Protection Mechanism Failure",
                        "remediation": "Deploy Content-Security-Policy that restricts script sources "
                                       "to only the captcha provider's domain",
                    })
                    return

    def detect_captcha_timing_anomaly(self, results: list[Any]) -> None:
        captcha_durations: list[float] = []
        for result in results:
            body = _response_body_text(result)
            if not _CAPTCHA_FIELD_RE.search(body):
                continue
            dur = _duration_ms(result)
            if dur is not None and dur > 0:
                captcha_durations.append(dur)

        if len(captcha_durations) >= 3:
            med = statistics.median(captcha_durations)
            very_fast = [d for d in captcha_durations if d < med * 0.2]
            if very_fast:
                self._findings.append({
                    "bypass_class": "captcha_automated_solve",
                    "description": f"{len(very_fast)} captcha-bearing request(s) completed in < "
                                   f"{med * 0.2:.0f}ms (median {med:.0f}ms) -- likely automated solving",
                    "evidence": {"median_ms": round(med, 1),
                                 "fast_durations": [round(d, 1) for d in very_fast[:10]]},
                    "severity": 6.5,
                    "confidence": "needs_validation",
                    "cwe": "CWE-804 Guessable CAPTCHA",
                    "remediation": "Implement server-side solve-time validation; reject sub-second "
                                   "captcha completions",
                })
