"""Async HTTP client used by every test module.

Wraps httpx.AsyncClient to (a) apply suite-wide settings -- timeout, proxy,
custom headers, User-Agent -- and (b) capture RequestEvidence/ResponseEvidence
for every call, which becomes the "Evidence" section of each test result.

Transport-level failures (timeouts, connection errors) are caught here and
turned into a populated `ResponseEvidence.error`, never raised, so a single
unreachable environment doesn't crash the whole run.

RESILIENCE (added alongside the fault-isolation pass -- see
CHANGELOG_COGNITIVE_UPGRADE.md): a shared `CircuitBreaker` (resilience.py)
gates every call, and a bounded, full-jitter retry wraps calls this client can
prove are safe to repeat. "Safe to repeat" is deliberately narrow and opt-in:

  - GET / HEAD / OPTIONS retry automatically -- they're safe by definition.
  - POST / PUT / PATCH / DELETE are retried ONLY when the caller passes
    `idempotent=True`, meaning the caller has already made this exact call safe
    to repeat (e.g. it carries its own idempotency key). The default is False.

This matters specifically because this is a PAYMENT test suite: silently
retrying a mutating POST that timed out risks a duplicate write the target
actually received. PROC-001 (idempotency-key replay) is deliberately NOT built
on this flag: it sends the deliberate duplicate itself, as the test.

The circuit breaker's failure/success signal: EVERY call (retried or not)
reports exactly one success/failure, and only a transport-level error
(`ResponseEvidence.error is not None`) counts -- a deliberate negative-test
payload that correctly receives a 4xx/5xx is NOT a failure.

SCOPE GUARD (Payment-Integrity upgrade, Phase-0 finding G3): when a
`RunGuard` (from the Control Adapter) is supplied, EVERY wire-level attempt -- first try, retry and
redirect hop -- is authorised by it first (host/scheme allowlist, request
budget, rate limit, deadline, kill switch). A denial is returned as
`ResponseEvidence.error = "scope_violation[<code>]: ..."`, never raised, never
retried, and never counted as a target failure by the circuit breaker.
With a guard, redirects are followed manually and ONLY within the same host: a
redirect to another host is not followed (the 3xx itself is the evidence), an
https->http downgrade is not followed, and every followed hop counts against
the budget. Without a guard (unit tests, legacy callers) behaviour is exactly
what it was: httpx follows redirects itself.
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from app.testing.models import RequestEvidence, ResponseEvidence
from app.testing.resilience import CircuitBreaker, retry_on
from app.core.control_port import NEGATIVE_ACCESS_CONTROL, SCOPE_ERROR_PREFIX, RunGuard, ScopeViolation, get_control_adapter

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _header(headers: Any, name: str) -> str | None:
    """Case-insensitive header lookup that works for httpx.Headers and plain dicts."""
    try:
        for key, value in headers.items():
            if str(key).lower() == name:
                return str(value)
    except AttributeError:
        return None
    return None


def _scope_denied(violation: ScopeViolation) -> ResponseEvidence:
    return ResponseEvidence(error=f"{SCOPE_ERROR_PREFIX}[{violation.code}]: {violation.message}")


def _is_scope_denial(evidence: ResponseEvidence) -> bool:
    return evidence.error is not None and evidence.error.startswith(SCOPE_ERROR_PREFIX)


class QAHttpClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float,
        proxy_url: str | None,
        headers: dict[str, str],
        user_agent: str,
        max_retries: int = 2,
        retry_base_delay_seconds: float = 0.5,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_cooldown_seconds: float = 20.0,
        transport: httpx.BaseTransport | None = None,
        guard: RunGuard | None = None,
        stateless: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._guard = guard
        # stateless=True: the cookie jar is emptied after EVERY response, so nothing a target sets (Set-Cookie) can ever travel with a later request.
        # Required by the pure black-box engine: a "clean session" must carry only the identity's own bearer token (httpx keeps cookies per client by default).
        self._stateless = stateless
        merged_headers = {"User-Agent": user_agent, **headers}
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout_seconds),
            proxy=proxy_url,
            headers=merged_headers,
            # With a guard, redirects are followed manually (same host only,
            # every hop authorised); without one, httpx behaves as before.
            follow_redirects=guard is None,
            # None (default/production) keeps httpx's normal transport.
            # Tests inject httpx.MockTransport here instead of hitting the
            # network -- see tests/test_http_client_resilience.py.
            transport=transport,
        )
        self._max_retries = max(0, max_retries)
        self._retry_base_delay_seconds = max(0.0, retry_base_delay_seconds)
        self._breaker = CircuitBreaker(circuit_breaker_threshold, circuit_breaker_cooldown_seconds)

    @property
    def guard(self) -> RunGuard | None:
        return self._guard

    @property
    def stateless(self) -> bool:
        return self._stateless

    def _drop_cookies(self) -> None:
        jar = getattr(self._client, "cookies", None)
        clear = getattr(jar, "clear", None)
        if callable(clear):
            clear()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        raw_body: bytes | None = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        idempotent: bool = False,
        probe_class: str | None = None,
    ) -> tuple[RequestEvidence, ResponseEvidence]:
        """Send one HTTP request and return (RequestEvidence, ResponseEvidence).

        `raw_body`, when provided, is sent verbatim as the request body
        (bypassing JSON serialization) -- used for malformed-JSON negative
        tests and for byte-exact signed payloads. `json_body` is ignored when
        `raw_body` is set.

        `idempotent`: set True only when THIS call is already safe to repeat
        verbatim (see module docstring). Defaults to False. GET/HEAD/OPTIONS
        are always treated as safe regardless of this flag.
        """
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        if params:
            url = f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"
        evidence_body: Any = raw_body.decode("utf-8", errors="replace") if raw_body is not None else json_body
        request_evidence = RequestEvidence(method=method, url=url, headers=extra_headers or {}, body=evidence_body)

        # Everything knowable before touching the network is decided BEFORE the
        # circuit breaker is consulted: a denied request must not consume a
        # half-open probe slot (which only record_success/failure release).
        if self._guard is not None:
            try:
                self._guard.preflight(url, probe_class)
            except ScopeViolation as violation:
                return request_evidence, _scope_denied(violation)

        if not self._breaker.try_acquire():
            return request_evidence, ResponseEvidence(
                error="circuit_open: target treated as unavailable after repeated transport failures"
            )

        safe_to_retry = idempotent or method.upper() in _SAFE_METHODS

        async def _attempt() -> ResponseEvidence:
            if self._guard is not None:
                try:
                    await self._guard.acquire(url, method, probe_class)  # counts one wire attempt (retries too)
                except ScopeViolation as violation:
                    return _scope_denied(violation)
            return await self._send_once(
                method, path, url=url, json_body=json_body, raw_body=raw_body, params=params, extra_headers=extra_headers,
                probe_class=probe_class,
            )

        if safe_to_retry:
            response_evidence = await retry_on(
                _attempt,
                should_retry=lambda r: r.error is not None and not _is_scope_denial(r),
                max_retries=self._max_retries,
                base_delay_seconds=self._retry_base_delay_seconds,
            )
        else:
            response_evidence = await _attempt()

        if _is_scope_denial(response_evidence):
            self._breaker.release_probe_without_result()
        elif response_evidence.error is not None:
            self._breaker.record_failure()
        else:
            self._breaker.record_success()

        return request_evidence, response_evidence

    async def _dispatch(
        self,
        method: str,
        target: str,
        *,
        json_body: Any,
        raw_body: bytes | None,
        params: dict[str, Any] | None,
        extra_headers: dict[str, str] | None,
    ) -> Any:
        if raw_body is not None:
            send_headers = {"Content-Type": "application/json", **(extra_headers or {})}
            response = await self._client.request(method, target, content=raw_body, params=params, headers=send_headers)
        else:
            response = await self._client.request(method, target, json=json_body, params=params, headers=extra_headers)
        if self._stateless:
            self._drop_cookies()
        return response

    async def _follow_same_host_redirects(
        self,
        response: Any,
        method: str,
        url: str,
        json_body: Any,
        raw_body: bytes | None,
        extra_headers: dict[str, str] | None,
        probe_class: str | None = None,
    ) -> Any:
        """Follow redirects manually, same host only, each hop authorised by the guard."""
        assert self._guard is not None
        current_url, current_method = url, method.upper()
        hops = 0
        while response.status_code in _REDIRECT_STATUSES:
            location = _header(response.headers, "location")
            if not location or hops >= self._guard.policy.max_redirects:
                break
            next_url = urljoin(current_url, location)
            cur, nxt = urlparse(current_url), urlparse(next_url)
            if (cur.hostname or "").lower() != (nxt.hostname or "").lower():
                break  # never follow across hosts: the 3xx response is returned as evidence
            if cur.scheme == "https" and nxt.scheme != "https":
                break  # never follow a TLS downgrade
            try:
                await self._guard.acquire(next_url, current_method, probe_class)
            except ScopeViolation:
                break
            hops += 1
            if response.status_code == 303 or (response.status_code in (301, 302) and current_method not in ("GET", "HEAD")):
                current_method = "HEAD" if current_method == "HEAD" else "GET"
                json_body, raw_body = None, None
            response = await self._dispatch(
                current_method, next_url, json_body=json_body, raw_body=raw_body, params=None, extra_headers=extra_headers
            )
            current_url = next_url
        return response

    async def _send_once(
        self,
        method: str,
        path: str,
        *,
        url: str,
        json_body: Any,
        raw_body: bytes | None,
        params: dict[str, Any] | None,
        extra_headers: dict[str, str] | None,
        probe_class: str | None = None,
    ) -> ResponseEvidence:
        """Exactly one wire-level attempt (plus authorised same-host redirect
        hops when a guard is set). Never raises: transport failures become a
        populated `ResponseEvidence.error`."""
        start = time.perf_counter()
        try:
            response = await self._dispatch(
                method, path, json_body=json_body, raw_body=raw_body, params=params, extra_headers=extra_headers
            )
            if self._guard is not None:
                response = await self._follow_same_host_redirects(response, method, url, json_body, raw_body, extra_headers, probe_class)

            elapsed_ms = (time.perf_counter() - start) * 1000
            try:
                body: Any = response.json()
            except ValueError:
                body = response.text
            if probe_class == NEGATIVE_ACCESS_CONTROL:
                body = get_control_adapter().withhold_body(body)  # Pure Black-Box: never ingest the content of a (possibly internal) probed surface

            return ResponseEvidence(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=body,
                elapsed_ms=round(elapsed_ms, 2),
            )
        except httpx.TimeoutException as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return ResponseEvidence(elapsed_ms=round(elapsed_ms, 2), error=f"timeout: {exc}")
        except httpx.HTTPError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return ResponseEvidence(elapsed_ms=round(elapsed_ms, 2), error=f"transport_error: {exc}")

    def get_resilience_statistics(self) -> dict[str, Any]:
        """Circuit-breaker state for this client's lifetime -- surfaced on
        the run summary so a wall of ERROR results against a target that
        went down mid-run is distinguishable, after the fact, from N
        independent test failures (see collector.py's summary())."""
        return self._breaker.get_statistics()

    def get_scope_statistics(self) -> dict[str, Any] | None:
        return self._guard.stats() if self._guard is not None else None

    async def aclose(self) -> None:
        await self._client.aclose()
