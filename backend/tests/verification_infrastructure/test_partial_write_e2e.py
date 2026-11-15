"""Axis 2: partial writes -- a state-changing operation succeeds (from the
caller's point of view: 200, state correctly updated) while a SEPARATE,
unwrapped write (the ledger entry) silently fails, over real sockets
against reference_target.py's fault_mode="partial_write", cross-checked
with app.testing.invariants.check_ledger_consistency.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from reference_target import ReferenceTarget, start_reference_target  # noqa: E402

from app.testing.http_client import QAHttpClient  # noqa: E402
from app.testing.endpoints import EndpointMap, EndpointSpec  # noqa: E402
from app.testing.invariants import check_ledger_consistency  # noqa: E402

OVERRIDES = EndpointMap(overrides={"capture_payment": EndpointSpec("POST", "/api/v1/payments/{payment_id}/capture")})


async def _capture_under_fault(fault_mode: str | None) -> tuple:
    """Returns (capture_response, ledger_total, payment_amount)."""
    target, server, port = await start_reference_target(ReferenceTarget(fault_mode=fault_mode))
    client = QAHttpClient(base_url=f"http://127.0.0.1:{port}", timeout_seconds=2.0, proxy_url=None, headers={}, user_agent="x")

    _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 100.0})
    payment_id = create_resp.body["id"]

    spec = OVERRIDES.get("capture_payment")
    _, capture_resp = await client.request(spec.method, spec.path.format(payment_id=payment_id))

    ledger_total = target.ledger_total_for(payment_id)
    amount = target.payments[payment_id]["amount"]

    await client.aclose()
    server.close()
    await server.wait_closed()
    return capture_resp, ledger_total, amount


def test_normal_capture_writes_a_matching_ledger_entry():
    resp, ledger_total, amount = asyncio.run(_capture_under_fault(None))
    assert resp.status_code == 200
    violations = check_ledger_consistency(ledger_total, [amount])
    assert violations == [], f"expected the ledger to match the captured amount, got {violations}"


def test_partial_write_reports_success_but_leaves_the_ledger_inconsistent():
    """The core of the bug this fault mode represents: the API call
    itself gives NO signal anything went wrong (200, correct new state in
    the response body) -- the inconsistency is only visible by separately
    checking the ledger, which is exactly why check_ledger_consistency
    exists as an independent, composable check rather than something
    folded into "did the HTTP call succeed"."""
    resp, ledger_total, amount = asyncio.run(_capture_under_fault("partial_write"))
    assert resp.status_code == 200, "the caller-visible response must show success -- that's the whole danger of this bug shape"
    assert resp.body["status"] == "captured"
    violations = check_ledger_consistency(ledger_total, [amount])
    assert len(violations) == 1, "the ledger must be caught as inconsistent even though the API call reported success"
    assert "0" in violations[0].message and "100" in violations[0].message


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
    print("Alle Partial-Write-Tests bestanden.")
