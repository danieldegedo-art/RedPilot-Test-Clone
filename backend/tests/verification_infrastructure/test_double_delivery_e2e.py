"""Axis 2: double-delivery -- the same logical request arriving twice
(client retry after a false timeout, message-queue redelivery) must
produce exactly one underlying resource, verified over real sockets
against reference_target.py's idempotency-key handling, and cross-checked
with app.testing.invariants.check_idempotent_replay (the same invariant
axis 1 built, now exercised against a real double-delivery instead of
hand-built AttemptRecord fixtures).
"""
from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from reference_target import start_reference_target  # noqa: E402

from app.testing.http_client import QAHttpClient  # noqa: E402
from app.testing.invariants import AttemptRecord, check_idempotent_replay  # noqa: E402


async def _send_same_request_twice(idempotency_key: str) -> tuple:
    target, server, port = await start_reference_target()
    client = QAHttpClient(base_url=f"http://127.0.0.1:{port}", timeout_seconds=2.0, proxy_url=None, headers={}, user_agent="x")
    _, first = await client.request(
        "POST", "/api/v1/payments", json_body={"amount": 42.0}, extra_headers={"Idempotency-Key": idempotency_key}
    )
    _, second = await client.request(
        "POST", "/api/v1/payments", json_body={"amount": 42.0}, extra_headers={"Idempotency-Key": idempotency_key}
    )
    await client.aclose()
    server.close()
    await server.wait_closed()
    return first, second


def test_double_delivery_with_same_idempotency_key_creates_exactly_one_payment():
    key = str(uuid.uuid4())
    first, second = asyncio.run(_send_same_request_twice(key))
    assert first.status_code == 201 and second.status_code == 201
    assert first.body["id"] == second.body["id"], "double delivery must return the SAME payment id, not create a second one"


def test_double_delivery_without_idempotency_key_creates_two_payments():
    """Documents the baseline this project's own idempotency invariant
    exists to catch: reference_target.py's create endpoint has no way to
    recognize a retry as "the same request" without a key -- this is a
    property of the API contract (whether the caller sent a key), not a
    bug in the target, and is exactly why check_idempotent_replay only
    ever groups AttemptRecords that DO carry an idempotency_key (see
    invariants.py's own docstring)."""

    async def go():
        target, server, port = await start_reference_target()
        client = QAHttpClient(base_url=f"http://127.0.0.1:{port}", timeout_seconds=2.0, proxy_url=None, headers={}, user_agent="x")
        _, first = await client.request("POST", "/api/v1/payments", json_body={"amount": 42.0})
        _, second = await client.request("POST", "/api/v1/payments", json_body={"amount": 42.0})
        await client.aclose()
        server.close()
        await server.wait_closed()
        return first, second

    first, second = asyncio.run(go())
    assert first.body["id"] != second.body["id"]


def test_invariants_check_idempotent_replay_confirms_the_real_double_delivery_result():
    """Bridges the real HTTP result back to axis 1's invariant library:
    the same check that would flag a REGRESSION (a future edit that
    removes reference_target.py's idempotency handling) is exercised here
    against a real response, not just the hand-built AttemptRecord
    fixtures in tests/test_invariants.py."""
    key = str(uuid.uuid4())
    first, second = asyncio.run(_send_same_request_twice(key))
    attempts = [
        AttemptRecord(operation="create_payment", idempotency_key=key, succeeded=True, resulting_resource_id=first.body["id"]),
        AttemptRecord(operation="create_payment", idempotency_key=key, succeeded=True, resulting_resource_id=second.body["id"]),
    ]
    assert check_idempotent_replay(attempts) == []


def _run(fn):
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
    print("Alle Double-Delivery-Tests bestanden.")
