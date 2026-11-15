"""Axis 2 (robustness) end-to-end verification: fires real faults (timeout,
corrupted JSON, truncated response, connection refused) at the real,
unmodified app/testing/http_client.py over real sockets and asserts zero
unhandled exceptions plus correct circuit-breaker behavior.

Run directly (see this directory's README.md and
test_state_machine_exploration_e2e.py's docstring for why: pytest is not
installable in the offline sandbox this was authored in):

    PYTHONPATH=tests/verification_infrastructure/shims:. python3 \\
        tests/verification_infrastructure/test_fault_injection_e2e.py
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from reference_target import ReferenceTarget, start_reference_target  # noqa: E402

from app.testing.http_client import QAHttpClient  # noqa: E402


async def _fire_one(fault_mode: str | None, *, base_url_override: str | None = None, **client_kwargs) -> tuple[bool, object, float]:
    """Returns (crashed, response_or_exception, elapsed_seconds)."""
    server = None
    if base_url_override is None:
        target, server, port = await start_reference_target(ReferenceTarget(fault_mode=fault_mode))
        base_url = f"http://127.0.0.1:{port}"
    else:
        base_url = base_url_override

    client = QAHttpClient(
        base_url=base_url, timeout_seconds=client_kwargs.pop("timeout_seconds", 0.5), proxy_url=None, headers={},
        user_agent="FaultInjectionTest/1.0", **client_kwargs,
    )
    start = time.perf_counter()
    crashed = False
    result: object
    try:
        _, result = await client.request("POST", "/api/v1/payments", json_body={"amount": 10.0}, idempotent=True)
    except Exception as exc:  # this is exactly what must NEVER happen -- see the test functions below
        crashed, result = True, exc
    elapsed = time.perf_counter() - start
    await client.aclose()
    if server is not None:
        server.close()
        await server.wait_closed()
    return crashed, result, elapsed


def test_timeout_never_crashes_and_reports_a_clear_error() -> None:
    crashed, resp, elapsed = asyncio.run(_fire_one("timeout", max_retries=0))
    assert not crashed, f"a timeout must never raise out of QAHttpClient.request(); got {resp!r}"
    assert resp.error is not None and "timeout" in resp.error
    assert resp.status_code is None


def test_corrupt_json_never_crashes_falls_back_to_text() -> None:
    crashed, resp, _ = asyncio.run(_fire_one("corrupt_json", max_retries=0))
    assert not crashed, f"a non-JSON 200 body must never raise out of QAHttpClient.request(); got {resp!r}"
    assert resp.status_code == 200
    assert resp.error is None
    assert isinstance(resp.body, str), "non-JSON body must fall back to raw text, not raise"


def test_truncated_response_never_crashes() -> None:
    crashed, resp, _ = asyncio.run(_fire_one("truncate", max_retries=0))
    assert not crashed, f"a truncated/dropped-mid-response body must never raise out of QAHttpClient.request(); got {resp!r}"


def test_connection_refused_never_crashes_and_reports_a_clear_error() -> None:
    # Port 1 is a privileged, essentially always-unbound port -- a real,
    # not simulated, ECONNREFUSED.
    crashed, resp, _ = asyncio.run(_fire_one(None, base_url_override="http://127.0.0.1:1", max_retries=0))
    assert not crashed, f"a connection refusal must never raise out of QAHttpClient.request(); got {resp!r}"
    assert resp.error is not None and "transport_error" in resp.error


def test_idempotent_request_actually_retries_on_transport_failure() -> None:
    """Confirms retry_on genuinely re-attempts (not just that the final
    outcome looks the same either way): a timeout with max_retries=1
    against a 0.3s client timeout must take noticeably longer than one
    attempt alone (~0.3s) -- roughly 2x, one attempt plus one retry."""
    crashed, resp, elapsed = asyncio.run(_fire_one("timeout", timeout_seconds=0.3, max_retries=1, retry_base_delay_seconds=0.01))
    assert not crashed
    assert elapsed > 0.5, f"expected ~2 attempts (~0.6s) at a 0.3s timeout with 1 retry, took only {elapsed:.2f}s"


def test_circuit_breaker_opens_after_threshold_and_then_fails_fast() -> None:
    async def go():
        target, server, port = await start_reference_target(ReferenceTarget(fault_mode="timeout"))
        base_url = f"http://127.0.0.1:{port}"
        client = QAHttpClient(
            base_url=base_url, timeout_seconds=0.2, proxy_url=None, headers={}, user_agent="x",
            max_retries=0, retry_base_delay_seconds=0.01,
            circuit_breaker_threshold=3, circuit_breaker_cooldown_seconds=10.0,
        )
        for _ in range(3):
            _, resp = await client.request("GET", "/health")
            assert resp.error is not None and "timeout" in resp.error

        stats = client.get_resilience_statistics()
        assert stats["state"] == "open", f"expected circuit breaker OPEN after 3 consecutive failures, got {stats}"

        start = time.perf_counter()
        _, resp = await client.request("GET", "/health")
        elapsed = time.perf_counter() - start

        await client.aclose()
        server.close()
        await server.wait_closed()
        return resp, elapsed

    resp, elapsed = asyncio.run(go())
    assert resp.error is not None and "circuit_open" in resp.error
    assert elapsed < 0.05, f"an open circuit must fail fast with no real network attempt; took {elapsed:.3f}s"


def test_all_fault_modes_are_deterministic_across_repeated_runs() -> None:
    for fault_mode in ("timeout", "corrupt_json", "truncate"):
        outcomes = set()
        for _ in range(5):
            crashed, resp, _ = asyncio.run(_fire_one(fault_mode, max_retries=0))
            outcomes.add((crashed, resp.status_code if not crashed else None, (resp.error is not None) if not crashed else None))
        assert len(outcomes) == 1, f"fault mode {fault_mode!r} produced inconsistent outcomes across 5 runs: {outcomes}"


def _run(fn) -> None:
    try:
        fn()
        print(f"[PASS] {fn.__name__}")
    except AssertionError as exc:
        print(f"[FAIL] {fn.__name__}: {exc}")
        raise


if __name__ == "__main__":
    for _name, _fn in list(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _run(_fn)
    print("Alle Fault-Injection-E2E-Tests bestanden: zero unhandled exceptions, Circuit Breaker verifiziert.")
