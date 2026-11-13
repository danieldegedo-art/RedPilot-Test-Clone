"""Scope guard: allowlist, budget, rate, deadline, kill switch, and the QAHttpClient integration.

Runs under pytest AND as a plain script (`python3 tests/test_scope_guard.py`) so it works in
sandboxes without pytest. Async work is driven with asyncio.run inside sync tests for that reason.
The HTTP tests talk to a REAL local asyncio server over real sockets (via the httpx shim or real httpx).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.testing.http_client import QAHttpClient  # noqa: E402
from app.enterprise_controls.scope import ScopeGuard, ScopePolicy, ScopeViolation  # noqa: E402


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.t += seconds


class LocalServer:
    """Tiny real HTTP/1.1 server: handler(method, target, headers, body) -> (status, headers, body_bytes)."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.log: list[tuple[str, str]] = []
        self.port = 0
        self._server = None

    async def __aenter__(self) -> "LocalServer":
        self._server = await asyncio.start_server(self._on_conn, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self._server.close()
        await self._server.wait_closed()

    async def _on_conn(self, reader, writer) -> None:
        try:
            line = await reader.readline()
            method, target, _ = line.decode().split(" ", 2)
            headers: dict[str, str] = {}
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode().partition(":")
                headers[k.strip().lower()] = v.strip()
            n = int(headers.get("content-length", "0"))
            body = await reader.readexactly(n) if n else b""
            self.log.append((method, target))
            status, extra, payload = self.handler(method, target, headers, body)
            head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n"
            head += "".join(f"{k}: {v}\r\n" for k, v in extra.items())
            writer.write(head.encode() + b"\r\n" + payload)
            await writer.drain()
        finally:
            writer.close()


def _client(port: int, guard: ScopeGuard | None, **kw) -> QAHttpClient:
    return QAHttpClient(
        base_url=f"http://127.0.0.1:{port}", timeout_seconds=3.0, proxy_url=None, headers={},
        user_agent="scope-test", max_retries=0, retry_base_delay_seconds=0.0, guard=guard, **kw,
    )


def _policy(**kw) -> ScopePolicy:
    kw.setdefault("allowed_hosts", ("127.0.0.1",))
    kw.setdefault("max_requests_per_second", 10_000.0)
    return ScopePolicy(**kw)


# ----------------------------------------------------------------------------- policy
def test_policy_host_matching() -> None:
    p = ScopePolicy(allowed_hosts=("api.example.com", "staging.example.com:8443", "*.pay.example.org", "[::1]", "127.0.0.1"))
    assert p.host_allowed("https://api.example.com/v1/x")
    assert p.host_allowed("http://API.EXAMPLE.COM:9999/x"), "bare host entry matches any port, case-insensitively"
    assert p.host_allowed("https://staging.example.com:8443/x")
    assert not p.host_allowed("https://staging.example.com/x"), "host:port entry must not match the default port"
    assert p.host_allowed("https://eu.pay.example.org/x")
    assert not p.host_allowed("https://pay.example.org/x"), "wildcard matches subdomains, not the apex"
    assert not p.host_allowed("https://evilpay.example.org/x"), "wildcard must respect the dot boundary"
    assert p.host_allowed("http://[::1]:8080/x")
    assert not p.host_allowed("https://api.example.com.evil.io/x")
    assert not p.host_allowed("https://api.example.com@evil.io/x"), "userinfo tricks are rejected"
    assert not p.host_allowed("ftp://api.example.com/x"), "scheme outside the allowlist"
    assert not p.host_allowed("not a url")


def test_policy_validation_and_environment_default() -> None:
    for bad in (dict(allowed_hosts=()), dict(allowed_hosts=("http://x.com",)), dict(allowed_hosts=("x.com/path",)),
                dict(allowed_hosts=("x.com:abc",)), dict(allowed_hosts=("x.com",), max_requests=0),
                dict(allowed_hosts=("x.com",), max_requests_per_second=0), dict(allowed_hosts=("x.com",), deadline_seconds=-1)):
        try:
            ScopePolicy(**bad)
        except ValueError:
            continue
        raise AssertionError(f"policy accepted invalid config {bad}")
    p = ScopePolicy.for_environment("https://staging.acme.io:8443/checkout?x=1", extra_hosts=["cdn.acme.io", ""])
    assert p.host_allowed("https://staging.acme.io:1234/a"), "default scope keeps any port of the typed host"
    assert p.host_allowed("https://cdn.acme.io/a")
    assert not p.host_allowed("https://stripe.com/a"), "third-party hosts are OUT of scope unless declared"


# ----------------------------------------------------------------------------- guard
def test_budget_exhaustion_and_stats() -> None:
    async def scenario() -> None:
        g = ScopeGuard(_policy(max_requests=3))
        for _ in range(3):
            await g.acquire("http://127.0.0.1/x")
        try:
            await g.acquire("http://127.0.0.1/x")
            raise AssertionError("4th request must be denied")
        except ScopeViolation as v:
            assert v.code == "budget_exhausted"
        s = g.stats()
        assert s["requests_used"] == 3 and s["denied_by_code"] == {"budget_exhausted": 1}
        assert g.stop_reason() == "budget_exhausted"

    asyncio.run(scenario())


def test_budget_is_exact_under_concurrency() -> None:
    async def scenario() -> None:
        g = ScopeGuard(_policy(max_requests=5))
        results = await asyncio.gather(*(g.acquire("http://127.0.0.1/x") for _ in range(20)), return_exceptions=True)
        denied = [r for r in results if isinstance(r, ScopeViolation)]
        assert len(denied) == 15 and g.requests_used == 5, (len(denied), g.requests_used)

    asyncio.run(scenario())


def test_token_bucket_rate_limit_with_fake_clock() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        g = ScopeGuard(ScopePolicy(allowed_hosts=("127.0.0.1",), max_requests_per_second=10.0), clock=clock, sleep=clock.sleep)
        for _ in range(25):
            await g.acquire("http://127.0.0.1/x")
        waited = clock.t - 1000.0
        # burst of 10 is immediate, the remaining 15 are spaced 0.1s apart => 1.5s
        assert abs(waited - 1.5) < 1e-6, waited
        assert abs(g.stats()["rate_wait_seconds"] - 1.5) < 1e-3

    asyncio.run(scenario())


def test_kill_switch_and_deadline() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        g = ScopeGuard(ScopePolicy(allowed_hosts=("127.0.0.1",), deadline_seconds=5.0, max_requests_per_second=1000.0),
                       clock=clock, sleep=clock.sleep)
        await g.acquire("http://127.0.0.1/x")
        clock.t += 6.0
        try:
            await g.acquire("http://127.0.0.1/x")
            raise AssertionError("deadline must deny")
        except ScopeViolation as v:
            assert v.code == "deadline_exceeded"
        g2 = ScopeGuard(_policy())
        await g2.acquire("http://127.0.0.1/x")
        g2.kill("operator stop")
        assert g2.killed and g2.stop_reason().startswith("killed")
        try:
            await g2.acquire("http://127.0.0.1/x")
            raise AssertionError("kill must deny")
        except ScopeViolation as v:
            assert v.code == "killed" and "operator stop" in v.message

    asyncio.run(scenario())


# ----------------------------------------------------------------------------- client integration
def test_client_denies_off_scope_url_without_touching_the_network() -> None:
    async def scenario() -> None:
        async with LocalServer(lambda *a: (200, {}, b"{}")) as srv:
            client = _client(srv.port, ScopeGuard(_policy()))
            _, resp = await client.request("GET", "http://evil.example.invalid/steal")
            assert resp.error and resp.error.startswith("scope_violation[host_not_allowed]"), resp.error
            assert resp.status_code is None
            _, ok = await client.request("GET", "/fine")
            assert ok.status_code == 200 and srv.log == [("GET", "/fine")], srv.log
            await client.aclose()

    asyncio.run(scenario())


def test_client_redirect_policy() -> None:
    def handler(method, target, headers, body):
        if target == "/old":
            return 302, {"Location": "/new"}, b""
        if target == "/new":
            return 200, {"Content-Type": "application/json"}, b'{"ok": true}'
        if target == "/cross":
            return 302, {"Location": f"http://localhost:{PORT[0]}/new"}, b""
        if target == "/loop":
            return 302, {"Location": "/loop"}, b""
        if target == "/p302":
            return 302, {"location": "/new"}, b""  # lower-case header name on purpose
        return 404, {}, b"{}"

    PORT = [0]

    async def scenario() -> None:
        async with LocalServer(handler) as srv:
            PORT[0] = srv.port
            guard = ScopeGuard(_policy(allowed_hosts=("127.0.0.1", "localhost"), max_redirects=5))
            client = _client(srv.port, guard)

            _, r = await client.request("GET", "/old")
            assert r.status_code == 200 and r.body == {"ok": True}, "same-host redirect is followed"
            assert guard.requests_used == 2, "every hop counts against the budget"

            srv.log.clear()
            _, r = await client.request("GET", "/cross")
            assert r.status_code == 302, "cross-host redirect must NOT be followed"
            assert srv.log == [("GET", "/cross")], srv.log

            srv.log.clear()
            _, r = await client.request("GET", "/loop")
            assert r.status_code == 302 and len(srv.log) == 6, ("loop stops after max_redirects", len(srv.log))

            srv.log.clear()
            _, r = await client.request("POST", "/p302", json_body={"a": 1})
            assert r.status_code == 200 and srv.log == [("POST", "/p302"), ("GET", "/new")], srv.log
            await client.aclose()

    asyncio.run(scenario())


def test_redirect_hop_respects_budget() -> None:
    async def scenario() -> None:
        async with LocalServer(lambda m, t, h, b: (302, {"Location": "/new"}, b"") if t == "/old" else (200, {}, b"{}")) as srv:
            guard = ScopeGuard(_policy(max_requests=1))
            client = _client(srv.port, guard)
            _, r = await client.request("GET", "/old")
            assert r.status_code == 302, "budget exhausted before the hop: the 3xx is returned unfollowed"
            assert guard.stats()["denied_by_code"].get("budget_exhausted") == 1
            await client.aclose()

    asyncio.run(scenario())


def test_scope_denials_never_trip_or_wedge_the_circuit_breaker() -> None:
    async def scenario() -> None:
        async with LocalServer(lambda *a: (200, {}, b"{}")) as srv:
            guard = ScopeGuard(_policy())
            client = _client(srv.port, guard, circuit_breaker_threshold=2, circuit_breaker_cooldown_seconds=0.0)
            guard.kill("stop")
            for _ in range(10):
                _, r = await client.request("GET", "/x")
                assert r.error.startswith("scope_violation[killed]")
            stats = client.get_resilience_statistics()
            assert not any(v for k, v in stats.items() if "open" in k and isinstance(v, bool) and v), stats
            assert srv.log == [], "no wire traffic after kill"
            await client.aclose()

    asyncio.run(scenario())


def test_client_without_guard_keeps_legacy_behaviour() -> None:
    async def scenario() -> None:
        async with LocalServer(lambda m, t, h, b: (200, {}, b'{"legacy": true}')) as srv:
            client = _client(srv.port, None)
            _, r = await client.request("GET", "/x")
            assert r.status_code == 200 and r.body == {"legacy": True}
            assert client.guard is None and client.get_scope_statistics() is None
            await client.aclose()

    asyncio.run(scenario())


if __name__ == "__main__":
    import inspect
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and inspect.isfunction(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{'ALL PASSED' if not failures else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
