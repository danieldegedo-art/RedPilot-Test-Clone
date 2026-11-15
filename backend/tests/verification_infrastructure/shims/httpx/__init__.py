"""Minimal httpx-compatible shim, backed by a REAL async HTTP/1.1 client
over real TCP sockets (asyncio.open_connection) -- not a mock of
responses. Exists for the same reason shims/pydantic/__init__.py does:
this sandbox has no network access to `pip install httpx` (verified
empirically). Loopback sockets (127.0.0.1) work fine in this sandbox --
the restriction is on reaching the outside network, not on the container
talking to itself -- which is what makes this shim meaningfully different
from a canned-response mock: app/testing/http_client.py, completely
unmodified, sends this shim a request, this shim opens a real socket,
writes real HTTP/1.1 request bytes, and parses real response bytes read
back off the wire.

SCOPE, MATCHED EXACTLY TO WHAT app/testing/http_client.py USES (checked
against that file's source directly, not guessed): AsyncClient(base_url=,
timeout=, proxy=, headers=, follow_redirects=, transport=), Timeout(),
BaseTransport (type-hint only, unused), client.request(method, path,
json=, params=, headers=, content=), a response with .status_code,
.headers, .json(), .text, TimeoutException, HTTPError, client.aclose().
No connection pooling/keep-alive (every request opens a fresh connection
and the request line asks the server to close it -- correctness and
simplicity over performance, appropriate for a test harness), no
redirect-following (follow_redirects is accepted for signature
compatibility and not implemented -- nothing in this project's test
scenarios needs it), no HTTPS/TLS (the reference target this shim was
verified against is plain HTTP on 127.0.0.1; a real deployment target
would need the real httpx package regardless). `proxy` is accepted and
ignored for the same reason.
"""
from __future__ import annotations

import asyncio
import json as _json
from typing import Any
from urllib.parse import urlencode, urlparse


class TimeoutException(Exception):
    def __init__(self, message: str = "", *, request: Any = None) -> None:
        super().__init__(message)
        self.request = request


class ConnectTimeout(TimeoutException):
    pass


class ReadTimeout(TimeoutException):
    pass


class HTTPError(Exception):
    def __init__(self, message: str = "", *, request: Any = None) -> None:
        super().__init__(message)
        self.request = request


class ConnectError(HTTPError):
    pass


class Timeout:
    def __init__(self, seconds: float | None = None, **_kwargs):
        self.seconds = seconds if seconds is not None else 30.0


class BaseTransport:
    """Type-hint compatibility only -- see module docstring."""


class MockTransport(BaseTransport):
    """httpx.MockTransport: route every request through a handler(request) -> Response (sync or async),
    with NO socket involved. A handler may raise TimeoutException/HTTPError subclasses, exactly as with httpx."""

    def __init__(self, handler: Any) -> None:
        self.handler = handler

    async def handle_async_request(self, request: Request) -> "Response":
        import inspect

        outcome = self.handler(request)
        if inspect.isawaitable(outcome):
            outcome = await outcome
        return outcome


class Headers(dict):
    """Case-insensitive-enough for this project's usage (it only ever
    reads by exact lowercase key or iterates); a real CaseInsensitiveDict
    is unnecessary complexity for what this shim needs to prove."""


class Request:
    """What a MockTransport handler receives (a subset of httpx.Request: method, url, headers, content)."""

    def __init__(self, method: str, url: str, headers: dict[str, str] | None = None, content: bytes = b"") -> None:
        self.method, self.url, self.headers, self.content = method, url, Headers(headers or {}), content


class Response:
    def __init__(
        self,
        status_code: int,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        *,
        json: Any = None,
        text: str | None = None,
        request: Any = None,
    ):
        # Positional (status, headers, content) stays compatible with _real_http_request's construction;
        # the keyword forms json=/text= are what tests using httpx.MockTransport write (httpx.Response(200, json={...})).
        headers = dict(headers or {})
        if json is not None:
            content = _json.dumps(json).encode("utf-8")
            headers.setdefault("content-type", "application/json")
        elif text is not None:
            content = text.encode("utf-8")
        content = content or b""
        self.status_code = status_code
        self.headers = Headers(headers)
        self._content = content
        self.request = request
        self.text = content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return _json.loads(self.text)


async def _real_http_request(
    method: str, url: str, headers: dict[str, str], body: bytes, timeout: float
) -> Response:
    """Exactly one real wire-level HTTP/1.1 request/response over a real
    TCP socket. Connection: close is forced so reading-until-EOF is a
    correct way to know the response is complete, without needing to
    parse Content-Length or chunked transfer-encoding -- a deliberate
    simplification a test-harness client can make that a general-purpose
    one (like real httpx, which this is standing in for) cannot."""
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise TimeoutException(f"connect timeout to {host}:{port}") from exc
    except OSError as exc:
        raise ConnectError(f"could not connect to {host}:{port}: {exc}") from exc

    send_headers = {"Host": f"{host}:{port}", "Connection": "close", **headers}
    if body:
        send_headers.setdefault("Content-Length", str(len(body)))
    request_lines = [f"{method.upper()} {path} HTTP/1.1"]
    request_lines += [f"{k}: {v}" for k, v in send_headers.items()]
    request_bytes = ("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8") + (body or b"")

    try:
        writer.write(request_bytes)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        writer.close()
        raise TimeoutException(f"read timeout after {timeout}s") from exc
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if not raw:
        raise ConnectError("connection closed with no response (server crashed or refused mid-request)")

    head, _, resp_body = raw.partition(b"\r\n\r\n")
    head_lines = head.decode("iso-8859-1").split("\r\n")
    status_code = int(head_lines[0].split(" ", 2)[1])
    resp_headers: dict[str, str] = {}
    for line in head_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip()] = v.strip()
    return Response(status_code, resp_headers, resp_body)


class AsyncClient:
    def __init__(
        self,
        base_url: str = "",
        timeout: "Timeout | float | None" = None,
        proxy: str | None = None,  # accepted, unused -- see module docstring
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,  # accepted, unused -- see module docstring
        transport: "BaseTransport | None" = None,  # MockTransport is honoured; anything else falls back to real sockets
    ) -> None:
        self._transport = transport
        self.base_url = base_url
        self._default_headers = dict(headers or {})
        self._timeout = timeout.seconds if isinstance(timeout, Timeout) else float(timeout or 30.0)

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> Response:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        if params:
            url = f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"

        send_headers = dict(self._default_headers)
        send_headers.update(headers or {})
        if content is not None:
            body = content
        elif json is not None:
            body = _json.dumps(json).encode("utf-8")
            send_headers.setdefault("Content-Type", "application/json")
        else:
            body = b""

        if isinstance(self._transport, MockTransport):
            return await self._transport.handle_async_request(Request(method, url, send_headers, body))
        return await _real_http_request(method, url, send_headers, body, timeout=self._timeout)

    async def aclose(self) -> None:
        pass  # no persistent connection/pool to release -- see module docstring
