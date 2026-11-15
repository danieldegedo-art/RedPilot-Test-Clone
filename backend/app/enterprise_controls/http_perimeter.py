"""Local-only guard — TEST CLONE: all perimeter checks removed. Everything passes through."""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Iterable

DEFAULT_ALLOWED_HOSTNAMES: tuple[str, ...] = ("*",)
DEFAULT_EXEMPT_PATHS: tuple[str, ...] = ("/health", "/api/v1/health", "/docs", "/redoc", "/openapi.json")

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

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)
