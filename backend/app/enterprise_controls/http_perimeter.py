"""Local-only guard for the backend API (pure ASGI middleware, no framework import).

WHY (Phase-0 finding G3): the API had no authentication, CORS was ``*``, the
compose file published the port on every interface, and ``POST /runs`` starts
an outbound test run against ANY URL and stores session cookies. Any web page
the operator visited could therefore drive the tool from the browser
(cross-site request) or, via DNS rebinding, talk to it as ``evil.example``.

WHAT IT DOES
  1. Host check (DNS-rebinding protection): the ``Host`` header must be one of
     the configured local hostnames.
  2. Origin check (cross-site protection): a browser-supplied ``Origin`` must be
     ``http(s)://localhost|127.0.0.1|[::1][:port]`` or explicitly allow-listed.
  3. Optional API token (``QA_API_TOKEN``): ``Authorization: Bearer``,
     ``X-QA-Token`` or ``?token=`` (for WebSocket). Preflight (OPTIONS) and the
     health/docs paths are exempt because browsers cannot attach credentials there.

RESIDUAL RISK, stated plainly: the packaged Electron dashboard loads from
``file://`` and therefore sends ``Origin: null``. ``null`` is also what a
sandboxed iframe sends, so by default (``allow_null_origin=True``) a hostile
page could still reach the API from such an iframe. Setting ``QA_API_TOKEN``
closes it completely (every non-exempt request then needs the token);
``QA_STRICT_LOCAL_ORIGINS=true`` rejects ``null`` origins outright at the cost
of the packaged dashboard until it sends the token. The dashboard does not
send a token yet -- that wiring is NOT part of this change.
"""
from __future__ import annotations

import hmac
import json
import re
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import parse_qs

DEFAULT_ALLOWED_HOSTNAMES: tuple[str, ...] = ("localhost", "127.0.0.1", "[::1]", "testserver")
DEFAULT_EXEMPT_PATHS: tuple[str, ...] = ("/health", "/api/v1/health", "/docs", "/redoc", "/openapi.json")

_LOCAL_ORIGIN_RE = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$", re.IGNORECASE)
_HOST_RE = re.compile(r"^(\[[^\]]+\]|[^:\s]+)(?::\d{1,5})?$")

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class LocalOnlyGuardMiddleware:
    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        *,
        allowed_hostnames: Iterable[str] = DEFAULT_ALLOWED_HOSTNAMES,
        extra_allowed_origins: Iterable[str] = (),
        allow_null_origin: bool = True,
        api_token: str | None = None,
        exempt_paths: Iterable[str] = DEFAULT_EXEMPT_PATHS,
    ) -> None:
        self.app = app
        self._hostnames = frozenset(h.strip().lower() for h in allowed_hostnames if h and h.strip())
        self._extra_origins = frozenset(o.strip().rstrip("/").lower() for o in extra_allowed_origins if o and o.strip())
        self._allow_null = allow_null_origin
        self._token = api_token or None
        self._exempt = frozenset(exempt_paths)

    @staticmethod
    def _hostname(host_header: str) -> str:
        match = _HOST_RE.match(host_header.strip())
        return match.group(1).lower() if match else ""

    def _token_valid(self, scope: Scope, headers: dict[str, str]) -> bool:
        if not self._token:
            return False
        supplied = ""
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        if not supplied:
            supplied = headers.get("x-qa-token", "").strip()
        if not supplied:
            query = parse_qs((scope.get("query_string") or b"").decode("latin-1"))
            supplied = (query.get("token") or [""])[0]
        return bool(supplied) and hmac.compare_digest(supplied.encode(), self._token.encode())

    def _reject_reason(self, scope: Scope, headers: dict[str, str]) -> str | None:
        host = headers.get("host")
        if host is not None and self._hostname(host) not in self._hostnames:
            return f"Host header {host!r} is not an allowed local hostname (DNS-rebinding protection)"

        method = (scope.get("method") or "GET").upper() if scope["type"] == "http" else "GET"
        path = scope.get("path", "")
        exempt = path in self._exempt or method == "OPTIONS"

        origin = headers.get("origin")
        if origin is not None:
            o = origin.strip().rstrip("/").lower()
            if o == "null" or o.startswith("file://"):
                if not self._allow_null and not (not exempt and self._token_valid(scope, headers)):
                    return "opaque (null/file) origin is not allowed in strict mode"
            elif not (_LOCAL_ORIGIN_RE.match(o) or o in self._extra_origins):
                return f"origin {origin!r} is not allowed (cross-site request protection)"

        if self._token and not exempt and not self._token_valid(scope, headers):
            return "missing or invalid API token"
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        reason = self._reject_reason(scope, headers)
        if reason is None:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"detail": f"Request rejected by local-only guard: {reason}"}).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})
