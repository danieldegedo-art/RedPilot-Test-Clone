"""Local-only ASGI guard: Host (DNS rebinding), Origin (cross-site), optional API token."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.enterprise_controls.http_perimeter import LocalOnlyGuardMiddleware  # noqa: E402


async def _ok_app(scope, receive, send):
    if scope["type"] == "http":
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(*, host="localhost:8420", origin=None, method="GET", path="/api/v1/runs", auth=None, qs=b"", kind="http", extra=None):
    headers = []
    if host is not None:
        headers.append((b"host", host.encode()))
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    if auth is not None:
        headers.append((b"authorization", auth.encode()))
    for k, v in (extra or {}).items():
        headers.append((k.encode(), v.encode()))
    return {"type": kind, "method": method, "path": path, "headers": headers, "query_string": qs}


def _call(mw, scope) -> list[dict]:
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(msg):
        sent.append(msg)

    asyncio.run(mw(scope, receive, send))
    return sent


def _status(sent) -> int | None:
    for m in sent:
        if m["type"] == "http.response.start":
            return m["status"]
    return None


def test_default_policy_blocks_dns_rebinding_and_cross_site_origins() -> None:
    mw = LocalOnlyGuardMiddleware(_ok_app)
    assert _status(_call(mw, _scope())) == 200
    assert _status(_call(mw, _scope(host="127.0.0.1:8420", origin="http://localhost:5173"))) == 200
    assert _status(_call(mw, _scope(host="[::1]:8420", origin="http://[::1]:5173"))) == 200
    assert _status(_call(mw, _scope(host="evil.example:8420"))) == 403, "DNS rebinding: foreign Host header"
    assert _status(_call(mw, _scope(origin="https://evil.example"))) == 403, "cross-site page calling the local API"
    assert _status(_call(mw, _scope(origin="http://localhost.evil.example"))) == 403, "look-alike origin"
    assert _status(_call(mw, _scope(origin="http://127.0.0.1:5173", method="OPTIONS"))) == 200, "local preflight passes"
    assert _status(_call(mw, _scope(origin="https://evil.example", method="OPTIONS"))) == 403, "foreign preflight is refused"


def test_null_origin_policy_is_explicit() -> None:
    assert _status(_call(LocalOnlyGuardMiddleware(_ok_app), _scope(origin="null"))) == 200, "default: packaged Electron (file://) keeps working"
    strict = LocalOnlyGuardMiddleware(_ok_app, allow_null_origin=False)
    assert _status(_call(strict, _scope(origin="null"))) == 403
    tokened = LocalOnlyGuardMiddleware(_ok_app, allow_null_origin=False, api_token="s3cret-token")
    assert _status(_call(tokened, _scope(origin="null", auth="Bearer s3cret-token"))) == 200, "null origin is fine WITH the token"


def test_api_token_modes() -> None:
    mw = LocalOnlyGuardMiddleware(_ok_app, api_token="s3cret-token")
    assert _status(_call(mw, _scope())) == 403, "token configured => anonymous requests are refused"
    assert _status(_call(mw, _scope(auth="Bearer wrong"))) == 403
    assert _status(_call(mw, _scope(auth="Bearer s3cret-token"))) == 200
    assert _status(_call(mw, _scope(extra={"x-qa-token": "s3cret-token"}))) == 200
    assert _status(_call(mw, _scope(path="/health"))) == 200, "health stays exempt"
    assert _status(_call(mw, _scope(method="OPTIONS", origin="http://localhost:5173"))) == 200, "preflight cannot carry credentials"


def test_websocket_is_guarded_and_can_use_query_token() -> None:
    mw = LocalOnlyGuardMiddleware(_ok_app, api_token="s3cret-token")
    denied = _call(mw, _scope(kind="websocket", path="/api/v1/ws/runs/1"))
    assert denied == [{"type": "websocket.close", "code": 1008}]
    seen: list[str] = []

    async def ws_app(scope, receive, send):
        seen.append(scope["type"])

    allowed = LocalOnlyGuardMiddleware(ws_app, api_token="s3cret-token")
    _call(allowed, _scope(kind="websocket", path="/api/v1/ws/runs/1", qs=b"token=s3cret-token"))
    assert seen == ["websocket"]
    rebinding = _call(LocalOnlyGuardMiddleware(ws_app), _scope(kind="websocket", host="evil.example"))
    assert rebinding == [{"type": "websocket.close", "code": 1008}]


def test_extra_origins_are_exact_matches_only() -> None:
    mw = LocalOnlyGuardMiddleware(_ok_app, extra_allowed_origins=["https://qa.corp.example"])
    assert _status(_call(mw, _scope(origin="https://qa.corp.example"))) == 200
    assert _status(_call(mw, _scope(origin="https://qa.corp.example.evil.io"))) == 403


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
