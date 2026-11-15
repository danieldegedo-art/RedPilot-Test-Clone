"""A minimal, real, local reference payment API -- pure asyncio + stdlib,
no framework -- implementing the SAME lifecycle
app/testing/lifecycle_model.py describes, with deliberately realistic
bugs planted for the exploration/invariant engines to actually catch over
a real socket connection.

This is test infrastructure, not part of the shipped suite: a stand-in
for "some real payment API" so this project's own exploration/invariant
code can be verified end-to-end (generate scenario -> real HTTP request
-> real response -> checked against a real invariant) without a live
payment provider or the real httpx/pydantic packages this sandbox cannot
install. See the project's before/after report for exactly what running
against this target does and does not prove about a REAL target.

PLANTED BUGS (deliberate, documented, not accidental):
  1. capture() checks `state != "refunded"` instead of requiring
     `state == "authorized"` -- a cancelled payment can be wrongly
     captured. One of the 44 illegal-payment-transition cases
     state_exploration.py finds that STATE-002's single hand-written case
     (refunded->captured) does not cover.
  2. refund() has a real time-of-check-to-time-of-use window: it reads
     `refunded_total`, `await`s (simulating a real DB round-trip), THEN
     writes -- so two concurrent refunds can both read the pre-write
     total and both succeed, together exceeding the captured amount.

FAULT INJECTION (axis 2): `fault_mode` on ReferenceTarget/`_serve_connection`
optionally makes EVERY request on that target instance misbehave one
specific way -- "timeout" never responds (holds the connection open past
any reasonable client timeout), "corrupt_json" returns 200 with a body
that is not valid JSON, "truncate" writes the status line and headers
then closes the connection before writing the promised body (a partial
write/dropped-mid-response, distinct from "corrupt_json": here the
Content-Length header itself promises more bytes than actually arrive).
Exists so app/testing/http_client.py's real, unmodified resilience code
(_send_once's httpx.TimeoutException/httpx.HTTPError handling, retry_on,
CircuitBreaker) can be exercised against real failure modes over a real
socket, not asserted to handle them.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from decimal import Decimal

_ID_RE = re.compile(r"^/api/v1/payments/([^/]+)(?:/(capture|cancel))?/?$")


class ReferenceTarget:
    def __init__(self, *, simulated_db_latency_seconds: float = 0.01, fault_mode: str | None = None) -> None:
        self.payments: dict[str, dict] = {}
        self._idempotency_keys: dict[str, str] = {}  # idempotency key -> payment_id
        self.ledger: list[dict] = []  # [{payment_id, kind, amount}] -- see _capture/_refund_by_body
        self._simulated_db_latency_seconds = simulated_db_latency_seconds
        self.fault_mode = fault_mode

    def ledger_total_for(self, payment_id: str) -> Decimal:
        return sum((Decimal(str(e["amount"])) for e in self.ledger if e["payment_id"] == payment_id), Decimal(0))

    async def handle(self, method: str, path: str, body: dict | None, headers: dict[str, str] | None = None) -> tuple[int, dict]:
        idempotency_key = (headers or {}).get("idempotency-key")
        if path.rstrip("/") == "/api/v1/payments" and method == "POST":
            return await self._create(body or {}, idempotency_key)

        # Matches EndpointMap's actual default: create_refund is
        # POST /api/v1/refunds with the target payment id IN THE BODY
        # ("paymentId"), not in the URL -- unlike capture/cancel below,
        # which are NOT in EndpointMap's default vocabulary at all and
        # exist here only at the URL shape the demo's override points at.
        if path.rstrip("/") == "/api/v1/refunds" and method == "POST":
            return await self._refund_by_body(body or {})

        match = _ID_RE.match(path)
        if not match:
            return 404, {"error": "not_found"}
        payment_id, action = match.group(1), match.group(2)

        if payment_id not in self.payments:
            return 404, {"error": "not_found"}

        if action is None and method == "GET":
            return 200, self._view(payment_id)
        if action == "capture" and method == "POST":
            return await self._capture(payment_id)
        if action == "cancel" and method == "POST":
            return await self._cancel(payment_id)
        return 404, {"error": "not_found"}

    async def _create(self, body: dict, idempotency_key: str | None = None) -> tuple[int, dict]:
        # DOUBLE DELIVERY: if the same idempotency key was already used,
        # return the SAME payment rather than creating a second one. This
        # branch existing at all (as opposed to always creating a new
        # payment) is deliberate -- removing it is how you turn
        # test_idempotent_replay_prevents_double_delivery below from a
        # passing test into a caught regression.
        if idempotency_key is not None and idempotency_key in self._idempotency_keys:
            return 201, self._view(self._idempotency_keys[idempotency_key])

        amount = body.get("amount")
        if not isinstance(amount, (int, float)) or amount <= 0:
            return 400, {"error": "invalid_amount"}
        payment_id = f"pay_{uuid.uuid4().hex[:16]}"
        self.payments[payment_id] = {
            "state": "authorized",
            "amount": Decimal(str(amount)),
            "refunded_total": Decimal(0),
        }
        if idempotency_key is not None:
            self._idempotency_keys[idempotency_key] = payment_id
        return 201, self._view(payment_id)

    async def _capture(self, payment_id: str) -> tuple[int, dict]:
        p = self.payments[payment_id]
        # BUG 1 (deliberate): should require p["state"] == "authorized".
        # Excluding only "refunded" lets a CANCELLED payment through.
        if p["state"] == "refunded":
            return 409, {"error": "invalid_state", "state": p["state"]}
        p["state"] = "captured"
        # PARTIAL WRITE (axis 2, fault_mode="partial_write"): a real,
        # common bug shape -- two separate writes (payment status, ledger
        # entry) with no transaction wrapping both. The state write above
        # always happens and is always reported as a 200 success; the
        # ledger write below is the one that "crashes" under this fault
        # mode, exactly the way a real system with an unwrapped second
        # write would: the caller sees success, the system's own
        # bookkeeping is now silently inconsistent. This is deliberately
        # NOT modeled as an error response -- a partial write that the
        # caller can SEE failed (a 500) is a much easier bug to catch than
        # one the caller can't, which is the realistic and more dangerous
        # case this fault mode exists to represent.
        if self.fault_mode != "partial_write":
            self.ledger.append({"payment_id": payment_id, "kind": "capture", "amount": float(p["amount"])})
        return 200, self._view(payment_id)

    async def _cancel(self, payment_id: str) -> tuple[int, dict]:
        p = self.payments[payment_id]
        if p["state"] not in ("pending", "authorized"):
            return 409, {"error": "invalid_state", "state": p["state"]}
        p["state"] = "cancelled"
        return 200, self._view(payment_id)

    async def _refund_by_body(self, body: dict) -> tuple[int, dict]:
        payment_id = body.get("paymentId")
        if payment_id not in self.payments:
            return 404, {"error": "not_found"}
        p = self.payments[payment_id]
        if p["state"] not in ("captured", "partially_refunded"):
            return 409, {"error": "invalid_state", "state": p["state"]}
        amount = body.get("amount")
        if not isinstance(amount, (int, float)) or amount <= 0:
            return 400, {"error": "invalid_amount"}

        current_refunded = p["refunded_total"]  # "read" -- TOCTOU window starts
        # BUG 2 (deliberate): a real await point between read and write,
        # simulating an actual DB round-trip with no row lock. The
        # captured-amount check below uses the value read BEFORE this
        # await, so a concurrent refund that reads in this same window
        # sees the same stale total.
        await asyncio.sleep(self._simulated_db_latency_seconds)

        requested = Decimal(str(amount))
        if current_refunded + requested > p["amount"]:
            return 409, {"error": "refund_exceeds_captured_amount"}

        p["refunded_total"] = current_refunded + requested  # "write" -- lost-update risk
        p["state"] = "refunded" if p["refunded_total"] >= p["amount"] else "partially_refunded"
        # See _capture's comment: same unwrapped-second-write fault mode.
        if self.fault_mode != "partial_write":
            self.ledger.append({"payment_id": payment_id, "kind": "refund", "amount": -float(requested)})
        return 200, self._view(payment_id)

    def _view(self, payment_id: str) -> dict:
        p = self.payments[payment_id]
        return {
            "id": payment_id,
            "status": p["state"],
            "amount": float(p["amount"]),
            "refunded_total": float(p["refunded_total"]),
        }


async def _read_http_request(reader: asyncio.StreamReader) -> tuple[str, str, dict]:
    """Minimal real HTTP/1.1 request parser: reads the request line and
    headers, then reads exactly Content-Length body bytes if present.
    Sufficient for what shims/httpx sends (Connection: close, explicit
    Content-Length) -- not a general-purpose parser."""
    request_line = (await reader.readline()).decode("iso-8859-1").strip()
    method, path, _ = request_line.split(" ", 2)
    headers = {}
    while True:
        line = (await reader.readline()).decode("iso-8859-1").strip()
        if not line:
            break
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    content_length = int(headers.get("content-length", "0"))
    raw_body = await reader.readexactly(content_length) if content_length else b""
    body = json.loads(raw_body) if raw_body else None
    return method, path, body, headers


async def _serve_connection(target: ReferenceTarget, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        method, path, body, headers = await _read_http_request(reader)

        if target.fault_mode == "timeout":
            # Never responds. The client's own timeout (not this server)
            # is what ends this -- holds the connection open indefinitely
            # rather than closing it, since a closed connection would be
            # a (different, faster) ConnectError, not a timeout.
            await asyncio.sleep(3600)
            return
        if target.fault_mode == "truncate":
            # Promises a body via Content-Length that never fully
            # arrives -- a partial write / dropped-mid-response, not a
            # clean error response.
            promised = b'{"status": "ok", "padding": "' + b"x" * 200 + b'"}'
            header = (
                f"HTTP/1.1 200 X\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(promised)}\r\nConnection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(header + promised[:10])  # only 10 of the promised bytes
            await writer.drain()
            writer.close()
            return
        if target.fault_mode == "corrupt_json":
            payload = b"{not: valid json, this is garbage###"
            response = (
                f"HTTP/1.1 200 X\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode("utf-8") + payload
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        status_code, response_body = await target.handle(method, path, body, headers)
    except Exception as exc:  # a malformed/corrupted request must get a real response, never hang or crash the server
        status_code, response_body = 400, {"error": "bad_request", "detail": str(exc)}
    payload = json.dumps(response_body).encode("utf-8")
    response = (
        f"HTTP/1.1 {status_code} X\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8") + payload
    try:
        writer.write(response)
        await writer.drain()
    finally:
        writer.close()


class _TrackedServer:
    """Wraps asyncio.Server so close()/wait_closed() can't hang forever on
    a connection handler deliberately stuck in fault_mode="timeout"'s
    asyncio.sleep(3600) -- a real bug found while building this file's own
    test suite: plain `server.close(); await server.wait_closed()` blocked
    for the full sleep duration (observed hang: 300+ seconds) because
    wait_closed() waits for every in-flight connection handler to finish,
    and a "never responds" fault handler never does on its own. Explicitly
    cancelling every tracked task makes teardown near-instant regardless
    of which fault mode a test used."""

    def __init__(self, server: asyncio.base_events.Server) -> None:
        self._server = server
        self.tasks: set[asyncio.Task] = set()

    @property
    def sockets(self):
        return self._server.sockets

    async def aclose(self) -> None:
        self._server.close()
        for task in list(self.tasks):
            task.cancel()
        for task in list(self.tasks):
            try:
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=1.0)
            except asyncio.TimeoutError:
                pass
        try:
            await asyncio.wait_for(self._server.wait_closed(), timeout=1.0)
        except asyncio.TimeoutError:
            pass

    # Kept for call sites written against the plain asyncio.Server API
    # (close() is synchronous there; aclose() above is the real teardown).
    def close(self) -> None:
        self._server.close()

    async def wait_closed(self) -> None:
        await self.aclose()


async def start_reference_target(target: ReferenceTarget | None = None) -> tuple[ReferenceTarget, _TrackedServer, int]:
    """Starts the reference target on 127.0.0.1 with an OS-assigned free
    port. Returns (target, server, port); caller is responsible for
    `await server.aclose()` (or the compatible `server.close()` +
    `await server.wait_closed()` pair, which now tears down promptly even
    if a fault_mode="timeout" connection is still "in flight" server-side
    -- see _TrackedServer)."""
    target = target or ReferenceTarget()
    tracked = _TrackedServer(None)  # placeholder; real server set below

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    port = server.sockets[0].getsockname()[1]
    return target, tracked, port
