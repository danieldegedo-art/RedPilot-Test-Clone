"""New findings from applying enterprise_payment_discovery_engine's Truth
Model / Truth Divergence / reconciliation concepts to entitlement_target.py.
Two genuinely new bug classes beyond test_payment_integrity_mission.py's
three (which were all about GRANTING wrongly) -- these are about FAILING
TO REVOKE, and about two components disagreeing after a correct revoke.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from entitlement_target import EntitlementTarget, start_entitlement_target  # noqa: E402

from app.testing.http_client import QAHttpClient  # noqa: E402
from app.testing.reconciliation import reconcile  # noqa: E402


async def _client_for(target: EntitlementTarget | None = None):
    target, server, port = await start_entitlement_target(target)
    client = QAHttpClient(base_url=f"http://127.0.0.1:{port}", timeout_seconds=2.0, proxy_url=None, headers={}, user_agent="discovery-engine/1.0")
    return target, server, client


async def _teardown(server, client) -> None:
    await client.aclose()
    server.close()
    await server.wait_closed()


async def _paid_and_entitled(target_kwargs: dict, user_id: str = "user_refund_test") -> tuple:
    """Shared setup: a genuine, correctly-granted entitlement (via
    grant_direct, the ruled-out-safe path) backing a real captured
    payment -- so any divergence found afterward is caused by the refund
    path, not by a shortcut in how the entitlement was created."""
    target, server, client = await _client_for(EntitlementTarget(**target_kwargs))
    _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 30.0})
    payment_id = create_resp.body["id"]
    await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
    await client.request("POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": user_id, "payment_id": payment_id})
    return target, server, client, payment_id


# ---------------------------------------------------------------------------
# CONFIRMED P0 (BUG D): refund does not revoke entitlement -- the exact
# "Refunds... mit noch aktivem Paid Entitlement" reconciliation hypothesis.
# ---------------------------------------------------------------------------


def test_confirmed_p0_refund_does_not_revoke_entitlement():
    async def go():
        target, server, client, payment_id = await _paid_and_entitled({})  # revoke_entitlement_on_refund defaults False
        await client.request("POST", "/api/v1/refunds", json_body={"paymentId": payment_id, "amount": 30.0})
        _, entitlement_resp = await client.request("GET", "/api/v1/entitlements/user_refund_test")
        authoritative = target.authoritative_status(payment_id)
        await _teardown(server, client)
        return entitlement_resp, authoritative

    entitlement_resp, authoritative = asyncio.run(go())
    assert authoritative == "refunded", "authoritative payment record correctly shows refunded"
    assert entitlement_resp.body["active"] is True, "but entitlement is STILL ACTIVE -- confirmed P0"
    print(f"  Confirmed P0: payment authoritative_status={authoritative!r}, entitlement.active=True")


def test_fix_revoke_entitlement_on_refund_closes_bug_d():
    async def go():
        target, server, client, payment_id = await _paid_and_entitled({"revoke_entitlement_on_refund": True})
        await client.request("POST", "/api/v1/refunds", json_body={"paymentId": payment_id, "amount": 30.0})
        _, entitlement_resp = await client.request("GET", "/api/v1/entitlements/user_refund_test")
        await _teardown(server, client)
        return entitlement_resp

    entitlement_resp = asyncio.run(go())
    assert entitlement_resp.body["active"] is False, "fix verified: entitlement correctly revoked on refund"


# ---------------------------------------------------------------------------
# CONFIRMED P0 (BUG E): TRUTH DIVERGENCE. Even with bug D fixed, the
# AUTHORITATIVE entitlement record and the DERIVED access_cache disagree,
# and the component that actually gates access (check_access) reads the
# WRONG one.
# ---------------------------------------------------------------------------


def test_confirmed_p0_truth_divergence_access_cache_survives_a_correct_revoke():
    async def go():
        # Bug D FIXED (entitlement correctly revoked), Bug E still present
        # (cache not invalidated) -- isolates bug E specifically.
        target, server, client, payment_id = await _paid_and_entitled({"revoke_entitlement_on_refund": True})
        await client.request("POST", "/api/v1/refunds", json_body={"paymentId": payment_id, "amount": 30.0})

        _, entitlement_resp = await client.request("GET", "/api/v1/entitlements/user_refund_test")
        _, access_resp = await client.request("GET", "/api/v1/access/user_refund_test")
        await _teardown(server, client)
        return entitlement_resp, access_resp

    entitlement_resp, access_resp = asyncio.run(go())
    assert entitlement_resp.body["active"] is False, "AUTHORITATIVE source (correctly fixed): entitlement is revoked"
    assert access_resp.body["has_access"] is True, "DERIVED source (cache): still says yes -- TRUTH DIVERGENCE, confirmed P0"
    print(
        f"  Confirmed P0 Truth Divergence: entitlements.active={entitlement_resp.body['active']} "
        f"vs access_cache.has_access={access_resp.body['has_access']} for the SAME user, same instant"
    )


def test_fix_invalidating_the_cache_closes_bug_e_too():
    async def go():
        target, server, client, payment_id = await _paid_and_entitled(
            {"revoke_entitlement_on_refund": True, "invalidate_cache_on_revoke": True}
        )
        await client.request("POST", "/api/v1/refunds", json_body={"paymentId": payment_id, "amount": 30.0})
        _, access_resp = await client.request("GET", "/api/v1/access/user_refund_test")
        await _teardown(server, client)
        return access_resp

    access_resp = asyncio.run(go())
    assert access_resp.body["has_access"] is False, "fix verified: cache now agrees with the authoritative record"


# ---------------------------------------------------------------------------
# Reconciliation, applied for real: scans a target with BOTH bugs D and E
# present and confirms the general-purpose reconciliation.py function
# (not a bespoke check) independently surfaces the same P0.
# ---------------------------------------------------------------------------


def test_reconciliation_independently_surfaces_the_same_p0_without_a_bespoke_check():
    async def go():
        target, server, client, payment_id = await _paid_and_entitled({})
        await client.request("POST", "/api/v1/refunds", json_body={"paymentId": payment_id, "amount": 30.0})
        await _teardown(server, client)
        payments_view = {pid: {"state": p["state"]} for pid, p in target.payments.items()}
        entitlements_view = {
            uid: {"active": e.active, "granted_for_payment_id": e.granted_for_payment_id}
            for uid, e in target.entitlements.items()
        }
        return payments_view, entitlements_view

    payments_view, entitlements_view = asyncio.run(go())
    findings = reconcile(payments_view, entitlements_view)
    p0s = [f for f in findings if f.severity == "P0"]
    assert len(p0s) == 1
    assert p0s[0].finding_id == "active_entitlement_with_non_captured_payment"
    print(f"  Reconciliation independently confirms: {p0s[0].message}")


def test_reconciliation_finds_no_p0_once_both_fixes_are_enabled():
    async def go():
        target, server, client, payment_id = await _paid_and_entitled({"revoke_entitlement_on_refund": True})
        await client.request("POST", "/api/v1/refunds", json_body={"paymentId": payment_id, "amount": 30.0})
        await _teardown(server, client)
        payments_view = {pid: {"state": p["state"]} for pid, p in target.payments.items()}
        entitlements_view = {
            uid: {"active": e.active, "granted_for_payment_id": e.granted_for_payment_id}
            for uid, e in target.entitlements.items()
        }
        return payments_view, entitlements_view

    payments_view, entitlements_view = asyncio.run(go())
    findings = reconcile(payments_view, entitlements_view)
    assert [f for f in findings if f.severity == "P0"] == []


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
    print("Alle Truth-Divergence/Reconciliation-Tests bestanden.")
