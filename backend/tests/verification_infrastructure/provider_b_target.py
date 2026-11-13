"""A SECOND, deliberately differently-conventioned reference target --
built fresh, not a copy-with-renames of reference_target.py -- to test
axis 4's "a new provider = implementing one interface, nothing else"
claim against something genuinely different, not the same target twice.

Deliberate differences from reference_target.py's "Provider A":
  - Refund id goes in the URL PATH ("/v2/transactions/{id}/refund"), not
    the body -- reference_target.py's "paymentId"-in-body convention is
    NOT universal, and a module that only worked with one or the other
    shape would not have proven the "one interface" claim.
  - The refund amount field is "cents" and is an INTEGER in the currency's
    minor unit, not "amount" as a decimal -- a real, common real-world
    difference (Stripe-style minor-unit integers vs. a decimal-amount API).
  - Capture and cancel are named "settle" and "void" -- different verbs
    entirely, not just different paths for the same word.

Deliberately UNCHANGED: the state vocabulary itself (authorized, captured,
cancelled, refunded, partially_refunded) and the same two planted bugs
from reference_target.py's ReferenceTarget, reused via composition (see
ProviderBTarget.__init__) rather than re-implemented, so a difference in
result between running against Provider A and Provider B would mean the
WIRING is wrong, not that the underlying bug logic diverged. Mapping a
DIFFERENT state vocabulary between providers (e.g. "SETTLED" instead of
"captured") is a real, separate, NOT-yet-solved problem -- see the
project's before/after report for why that is out of scope here rather
than quietly assumed away.
"""
from __future__ import annotations

import asyncio
import json
import re
from decimal import Decimal

from reference_target import ReferenceTarget, _read_http_request, _TrackedServer

_ID_RE = re.compile(r"^/v2/transactions/([^/]+)(?:/(settle|void|refund))?/?$")


class ProviderBTarget:
    """Wraps a ReferenceTarget (composition, not inheritance -- this is
    deliberately NOT a subclass overriding a couple of methods, which
    would risk silently sharing more behavior than intended; every route
    below is spelled out explicitly) and exposes it over Provider B's own
    URL/field conventions."""

    def __init__(self, *, fault_mode: str | None = None) -> None:
        self._inner = ReferenceTarget(fault_mode=fault_mode)

    @property
    def payments(self):
        return self._inner.payments

    async def handle(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        if path.rstrip("/") == "/v2/transactions" and method == "POST":
            amount_dollars = (body or {}).get("amountCents", 0) / 100
            return await self._inner._create({"amount": amount_dollars})

        match = _ID_RE.match(path)
        if not match:
            return 404, {"error": "not_found"}
        txn_id, action = match.group(1), match.group(2)
        if txn_id not in self._inner.payments:
            return 404, {"error": "not_found"}

        if action is None and method == "GET":
            return 200, self._inner._view(txn_id)
        if action == "settle" and method == "POST":
            return await self._inner._capture(txn_id)
        if action == "void" and method == "POST":
            return await self._inner._cancel(txn_id)
        if action == "refund" and method == "POST":
            cents = (body or {}).get("cents", 0)
            return await self._inner._refund_by_body({"paymentId": txn_id, "amount": cents / 100})
        return 404, {"error": "not_found"}


async def _serve_connection_b(target: ProviderBTarget, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        method, path, body, _headers = await _read_http_request(reader)
        status_code, response_body = await target.handle(method, path, body)
    except Exception as exc:
        status_code, response_body = 400, {"error": "bad_request", "detail": str(exc)}
    payload = json.dumps(response_body).encode("utf-8")
    response = (
        f"HTTP/1.1 {status_code} X\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    ).encode("utf-8") + payload
    try:
        writer.write(response)
        await writer.drain()
    finally:
        writer.close()


async def start_provider_b_target(target: ProviderBTarget | None = None) -> tuple[ProviderBTarget, _TrackedServer, int]:
    target = target or ProviderBTarget()
    tracked = _TrackedServer(None)

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve_connection_b(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    port = server.sockets[0].getsockname()[1]
    return target, tracked, port
