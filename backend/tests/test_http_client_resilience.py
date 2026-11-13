"""Tests for http_client.py's retry + circuit-breaker behavior, added
alongside the fault-isolation/hardening pass (see
CHANGELOG_COGNITIVE_UPGRADE.md and the accompanying report).

Every test injects `httpx.MockTransport` (httpx's own first-class testing
mechanism -- see QAHttpClient's `transport` constructor parameter) instead
of touching a real network, the same "never a real call in a test" rule
test_ambiguous_case_resolution.py follows too (that module no longer has
a network call to test around at all -- see its own module docstring).

NOTE ON THIS SANDBOX: unlike test_resilience.py (stdlib-only, actually
executed during this pass -- see that file and the report), this module
needs the real `httpx`/`pydantic` packages to even import QAHttpClient,
which are not installable in the offline sandbox this pass was authored
in (no package-manager network access -- see the project's own "A note on
this build" section in README.md for the identical constraint on every
previous pass). Written and reviewed against the real
QAHttpClient/CircuitBreaker/retry_on source, and syntax-checked
(`ast.parse`), but not executed here -- run with
`pip install -r requirements.txt -r requirements-dev.txt --break-system-packages
&& pytest tests/test_http_client_resilience.py -v` in an environment with
network access before relying on it.
"""
from __future__ import annotations

import httpx
import pytest

from app.testing.http_client import QAHttpClient


def _client(handler, **overrides) -> QAHttpClient:
    kwargs = dict(
        base_url="https://target.example",
        timeout_seconds=1.0,
        proxy_url=None,
        headers={},
        user_agent="test-agent",
        max_retries=2,
        retry_base_delay_seconds=0.01,  # keep tests fast
        circuit_breaker_threshold=3,
        circuit_breaker_cooldown_seconds=0.1,
    )
    kwargs.update(overrides)
    client = QAHttpClient(**kwargs)
    client._client = httpx.AsyncClient(
        base_url=kwargs["base_url"], transport=httpx.MockTransport(handler), follow_redirects=True
    )
    return client


class TestRetrySafety:
    """The idempotency contract: GET/HEAD/OPTIONS always retry; a mutating
    method only retries when the CALLER explicitly says this exact call is
    safe to repeat. Getting this wrong in either direction is a real
    correctness risk for a payment test suite -- see http_client.py's
    module docstring."""

    @pytest.mark.asyncio
    async def test_get_retries_on_timeout_and_eventually_succeeds(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] < 3:
                raise httpx.ConnectTimeout("simulated", request=request)
            return httpx.Response(200, json={"ok": True})

        client = _client(handler)
        _, response = await client.request("GET", "/health")
        assert response.error is None
        assert response.status_code == 200
        assert calls["n"] == 3

    @pytest.mark.asyncio
    async def test_post_without_idempotent_flag_never_retries(self):
        """The important negative case: a payment-mutating POST that times
        out must be reported as a single ERROR, not silently retried --
        retrying risks a duplicate write the client can never confirm one
        way or the other. This must reproduce the exact pre-resilience
        behavior for every module that doesn't opt in."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            raise httpx.ConnectTimeout("simulated", request=request)

        client = _client(handler)
        _, response = await client.request("POST", "/api/v1/charges", json_body={"amount": 100})
        assert calls["n"] == 1, "a mutating call without idempotent=True must attempt exactly once"
        assert response.error is not None
        assert response.status_code is None

    @pytest.mark.asyncio
    async def test_post_with_idempotent_flag_retries(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] < 2:
                raise httpx.ConnectTimeout("simulated", request=request)
            return httpx.Response(200, json={"ok": True})

        client = _client(handler)
        _, response = await client.request(
            "POST", "/api/v1/charges", json_body={"amount": 100}, idempotent=True
        )
        assert calls["n"] == 2
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_legitimate_4xx_response_is_never_retried(self):
        """A deliberate negative-test payload correctly rejected with 400 is
        NOT a transport failure -- retrying it would be actively wrong (it's
        the expected, correct result the test is checking for), and it must
        not count against the circuit breaker either."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(400, json={"error": "invalid amount"})

        client = _client(handler)
        _, response = await client.request("GET", "/api/v1/charges/-1")
        assert calls["n"] == 1, "a real HTTP response, even an error one, must never trigger a retry"
        assert response.status_code == 400
        assert response.error is None


class TestCircuitBreakerIntegration:
    @pytest.mark.asyncio
    async def test_repeated_transport_failures_trip_the_breaker_and_fail_fast(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            raise httpx.ConnectTimeout("simulated", request=request)

        client = _client(handler, max_retries=0, circuit_breaker_threshold=3)

        for _ in range(3):
            _, response = await client.request("GET", "/health")
            assert response.error is not None
        assert client.get_resilience_statistics()["state"] == "open"

        calls_before = calls["n"]
        _, response = await client.request("GET", "/health")
        assert calls["n"] == calls_before, "breaker open: must not attempt the network call at all"
        assert response.error is not None and response.error.startswith("circuit_open:")

    @pytest.mark.asyncio
    async def test_deliberate_error_responses_never_trip_the_breaker(self):
        """A burst of correctly-returned 4xx/5xx results (e.g. NEG-001
        through NEG-007 exercising deliberately invalid inputs) must never
        be mistaken for the target being down."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(422, json={"error": "validation failed"})

        client = _client(handler, circuit_breaker_threshold=2)
        for _ in range(10):
            _, response = await client.request("GET", "/negative-test-case")
            assert response.status_code == 422
        assert client.get_resilience_statistics()["state"] == "closed"

    @pytest.mark.asyncio
    async def test_breaker_recovers_after_cooldown_and_a_real_success(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] <= 2:
                raise httpx.ConnectTimeout("simulated", request=request)
            return httpx.Response(200, json={"ok": True})

        client = _client(handler, max_retries=0, circuit_breaker_threshold=2, circuit_breaker_cooldown_seconds=0.05)

        await client.request("GET", "/health")
        await client.request("GET", "/health")
        assert client.get_resilience_statistics()["state"] == "open"

        import asyncio

        await asyncio.sleep(0.06)
        _, response = await client.request("GET", "/health")  # half-open probe -- 3rd call, succeeds
        assert response.status_code == 200
        assert client.get_resilience_statistics()["state"] == "closed"
