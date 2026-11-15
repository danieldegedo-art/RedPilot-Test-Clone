"""Closes the four items explicitly named as open in the previous round:
amount/currency-integrity, tenant isolation, real HMAC signatures, and
genuine (not sequential) concurrency between refund and access-check.
Same evidence standard as every other file here: Confirmed findings are
exactly what running the test produces; fixes are separately verified.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from entitlement_target import CATALOG_CURRENCY, PRODUCT_CATALOG, EntitlementTarget, start_entitlement_target  # noqa: E402

from app.testing.check_trust_boundary import check_amount_matches_product_tier, check_currency_matches_catalog  # noqa: E402
from app.testing.http_client import QAHttpClient  # noqa: E402


async def _client_for(target: EntitlementTarget | None = None):
    target, server, port = await start_entitlement_target(target)
    client = QAHttpClient(base_url=f"http://127.0.0.1:{port}", timeout_seconds=2.0, proxy_url=None, headers={}, user_agent="gap-closure/1.0")
    return target, server, client


async def _teardown(server, client) -> None:
    await client.aclose()
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# GAP 1: Amount / product-tier integrity (mission hypothesis 8).
# ---------------------------------------------------------------------------


def test_confirmed_p0_underpayment_grants_the_highest_tier():
    async def go():
        target, server, client = await _client_for()  # verify_amount_matches_tier defaults False
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 9.99})  # basic-tier price
        payment_id = create_resp.body["id"]
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        _, webhook_resp = await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": "cheapskate", "status": "succeeded", "product": "enterprise"},
        )
        await _teardown(server, client)
        return webhook_resp

    resp = asyncio.run(go())
    assert resp.body["tier"] == "enterprise", f"paid $9.99 (basic price) but was granted {resp.body['tier']!r}"
    violations = check_amount_matches_product_tier(9.99, "enterprise", PRODUCT_CATALOG)
    assert len(violations) == 1
    print(f"  Confirmed P0: {violations[0].message}")


def test_fix_verify_amount_matches_tier_blocks_underpayment():
    async def go():
        target, server, client = await _client_for(EntitlementTarget(verify_amount_matches_tier=True))
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 9.99})
        payment_id = create_resp.body["id"]
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        _, resp = await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": "cheapskate2", "status": "succeeded", "product": "enterprise"},
        )
        await _teardown(server, client)
        return resp

    resp = asyncio.run(go())
    assert resp.status_code == 409
    assert resp.body["error"] == "amount_below_tier"


def test_ruled_out_overpayment_is_not_flagged_only_underpayment_is():
    """The invariant is deliberately one-directional -- confirms it
    doesn't false-positive on a legitimate overpayment (a $99.99 payment
    correctly claiming "basic")."""
    violations = check_amount_matches_product_tier(99.99, "basic", PRODUCT_CATALOG)
    assert violations == []


# ---------------------------------------------------------------------------
# GAP 2: Tenant isolation.
# ---------------------------------------------------------------------------


def test_confirmed_p0_payment_from_one_tenant_grants_entitlement_claiming_another():
    async def go():
        target, server, client = await _client_for()  # enforce_tenant_isolation defaults False
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 9.99, "tenant_id": "tenant_A"})
        payment_id = create_resp.body["id"]
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        _, resp = await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": "cross_tenant_user", "status": "succeeded", "tenant_id": "tenant_B"},
        )
        await _teardown(server, client)
        return resp, target.authoritative_tenant(payment_id)

    resp, authoritative_tenant = asyncio.run(go())
    assert authoritative_tenant == "tenant_A"
    assert resp.body["tier"] is not None and resp.status_code == 200, "granted despite claiming a DIFFERENT tenant than the payment's own"
    print(f"  Confirmed P0: payment under {authoritative_tenant!r}, entitlement granted under claimed tenant_B")


def test_fix_enforce_tenant_isolation_blocks_cross_tenant_grant():
    async def go():
        target, server, client = await _client_for(EntitlementTarget(enforce_tenant_isolation=True))
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 9.99, "tenant_id": "tenant_A"})
        payment_id = create_resp.body["id"]
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        _, resp = await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": "u", "status": "succeeded", "tenant_id": "tenant_B"},
        )
        await _teardown(server, client)
        return resp

    resp = asyncio.run(go())
    assert resp.status_code == 409
    assert resp.body["error"] == "tenant_mismatch"


def test_ruled_out_grant_direct_already_enforced_tenant_matching():
    """grant_direct() checked tenant unconditionally from the moment
    tenant_id was introduced to this file -- confirms that claim rather
    than assuming it."""
    async def go():
        target, server, client = await _client_for()
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 9.99, "tenant_id": "tenant_A"})
        payment_id = create_resp.body["id"]
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        resp = await client.request("POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": "u2", "payment_id": payment_id, "tenant_id": "tenant_B"})
        await _teardown(server, client)
        return resp[1]

    resp = asyncio.run(go())
    assert resp.status_code == 409
    assert resp.body["error"] == "tenant_mismatch"


# ---------------------------------------------------------------------------
# GAP 3: real HMAC -- tamper detection, not just "some string present".
# ---------------------------------------------------------------------------


def test_confirmed_tampered_payload_with_a_stolen_valid_signature_is_rejected():
    """The point real HMAC exists to prove: a signature valid for ONE
    payload must not validate a DIFFERENT payload, even one differing by
    a single field. A shared-secret-equality check (this file's earlier
    revision) could not distinguish this from a genuine signature at all."""
    async def go():
        target, server, client = await _client_for(EntitlementTarget(require_webhook_signature=True))
        genuine = {"event_id": str(uuid.uuid4()), "payment_id": "pay_1", "user_id": "victim", "status": "succeeded"}
        genuine["signature"] = target.sign(genuine)

        tampered = dict(genuine)
        tampered["user_id"] = "attacker"  # one field changed, signature reused verbatim

        _, genuine_resp = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=genuine)
        _, tampered_resp = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=tampered)
        await _teardown(server, client)
        return genuine_resp, tampered_resp

    genuine_resp, tampered_resp = asyncio.run(go())
    assert genuine_resp.status_code != 401, "the genuinely signed payload must be accepted (not itself rejected)"
    assert tampered_resp.status_code == 401, "a tampered payload reusing a valid signature for a DIFFERENT payload must be rejected"
    print("  Confirmed: real HMAC rejects a tampered payload; the old equality-only check could not have")


def test_ruled_out_the_signature_is_not_simply_the_shared_secret_string():
    """Documents the actual migration: the raw secret itself is no
    longer a valid signature for anything (it was, in the prior revision
    of this file)."""
    async def go():
        target, server, client = await _client_for(EntitlementTarget(require_webhook_signature=True))
        body = {"event_id": str(uuid.uuid4()), "payment_id": "pay_1", "user_id": "u", "status": "succeeded", "signature": "whsec_test_only_do_not_use_in_prod"}
        _, resp = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=body)
        await _teardown(server, client)
        return resp

    resp = asyncio.run(go())
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GAP 1b: the CURRENCY half of "amount/currency integrity" -- omitted from
# the first version of this file (which only tested amount), caught
# while writing the report and added here. Deliberately a DISTINCT bug
# from the amount check: 99.99 JPY numerically covers a 99.99 USD price,
# so the amount check passes it. That independence is what these tests
# pin down -- with verify_amount_matches_tier ON, the wrong currency
# still gets through.
# ---------------------------------------------------------------------------


async def _wrong_currency_grant(target_kwargs: dict, currency: str):
    target, server, client = await _client_for(EntitlementTarget(**target_kwargs))
    _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 99.99, "currency": currency})
    payment_id = create_resp.body["id"]
    await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
    _, resp = await client.request(
        "POST", "/api/v1/webhooks/payment-confirmed",
        json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": "fx_user", "status": "succeeded", "product": "enterprise"},
    )
    await _teardown(server, client)
    return resp


def test_confirmed_p0_wrong_currency_passes_even_with_the_amount_check_enabled():
    resp = asyncio.run(_wrong_currency_grant({"verify_amount_matches_tier": True}, "JPY"))
    assert resp.status_code == 200 and resp.body["tier"] == "enterprise", "amount check alone must NOT catch a wrong currency"
    # The two invariants disagree on the SAME facts -- that is the finding.
    assert check_amount_matches_product_tier(99.99, "enterprise", PRODUCT_CATALOG) == []
    assert len(check_currency_matches_catalog("JPY", CATALOG_CURRENCY)) == 1
    print("  Confirmed P0: 99.99 JPY granted the enterprise tier priced at 99.99 USD; amount invariant passes, currency invariant fails")


def test_fix_verify_currency_matches_tier_blocks_it():
    resp = asyncio.run(_wrong_currency_grant({"verify_amount_matches_tier": True, "verify_currency_matches_tier": True}, "JPY"))
    assert resp.status_code == 409 and resp.body["error"] == "currency_mismatch"


def test_ruled_out_correct_currency_is_not_flagged():
    resp = asyncio.run(_wrong_currency_grant({"verify_amount_matches_tier": True, "verify_currency_matches_tier": True}, "USD"))
    assert resp.status_code == 200 and resp.body["tier"] == "enterprise"


def test_ruled_out_grant_direct_already_rejected_the_wrong_currency():
    async def go():
        target, server, client = await _client_for()
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 99.99, "currency": "JPY"})
        payment_id = create_resp.body["id"]
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        resp = await client.request("POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": "u3", "payment_id": payment_id, "tier": "enterprise"})
        await _teardown(server, client)
        return resp[1]

    resp = asyncio.run(go())
    assert resp.status_code == 409 and resp.body["error"] == "currency_mismatch"


# ---------------------------------------------------------------------------
# GAP 4 (REWRITTEN): the revocation-lag window.
#
# CORRECTION OF AN EARLIER CLAIM IN THIS SAME FILE: the first version fired
# refund and access-check together via asyncio.gather and called the
# observed has_access=True a "confirmed" race. It was not established: the
# access check is serviced at t~1ms, the refund's AUTHORITATIVE write lands
# at t~10ms, so True was simply the correct answer to a question asked
# BEFORE the refund took effect -- ordinary linearizability, not a bug.
# The test never created the condition that would make True wrong.
#
# What actually constitutes the bug: authoritative truth has ALREADY
# changed to "refunded" while entitlement revocation is still pending, and
# the access decision still says yes. The helper below establishes exactly
# that window DETERMINISTICALLY (poll until the authoritative status has
# flipped, with revocation held open by an explicit 400ms await) and
# records that the window really was open before AND after the check,
# instead of assuming it.
# ---------------------------------------------------------------------------


async def _access_during_revocation_lag(target_kwargs: dict, *, also_check_before_refund: bool = False) -> dict:
    target, server, client = await _client_for(
        EntitlementTarget(revoke_entitlement_on_refund=True, invalidate_cache_on_revoke=True, **target_kwargs)
    )
    _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 9.99})
    payment_id = create_resp.body["id"]
    await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
    await client.request("POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": "racer", "payment_id": payment_id})

    out: dict = {}
    if also_check_before_refund:
        _, before = await client.request("GET", "/api/v1/access/racer")
        out["access_before_refund"] = before.body["has_access"]

    refund_task = asyncio.ensure_future(
        client.request("POST", "/api/v1/refunds", json_body={"paymentId": payment_id, "amount": 9.99, "_revoke_delay_seconds": 0.4})
    )
    deadline = time.monotonic() + 3.0
    while target.authoritative_status(payment_id) != "refunded":
        if time.monotonic() > deadline:
            raise AssertionError("the authoritative refund never completed -- cannot establish the window")
        await asyncio.sleep(0.005)

    window_open_before = target.authoritative_status(payment_id) == "refunded" and target.entitlements["racer"].active
    _, access_resp = await client.request("GET", "/api/v1/access/racer")
    window_open_after = target.authoritative_status(payment_id) == "refunded" and target.entitlements["racer"].active
    await refund_task

    out.update(
        window_open_before_check=window_open_before,
        window_open_after_check=window_open_after,
        has_access_in_window=access_resp.body["has_access"],
        entitlement_active_after_revocation=target.entitlements["racer"].active,
    )
    await _teardown(server, client)
    return out


def test_ruled_out_ordering_alone_is_not_a_bug_a_check_before_the_refund_is_correctly_true():
    """The conflation this section corrects: an access check that runs
    BEFORE the refund is even sent must answer True -- with or without the
    fix. If the fix turned this into False it would be over-denying."""
    for kwargs in ({}, {"check_access_verifies_authoritative": True}):
        out = asyncio.run(_access_during_revocation_lag(kwargs, also_check_before_refund=True))
        assert out["access_before_refund"] is True, f"a pre-refund check must be True (config={kwargs})"


def test_confirmed_p0_access_is_granted_after_the_authoritative_refund_during_revocation_lag():
    out = asyncio.run(_access_during_revocation_lag({}))
    assert out["window_open_before_check"] and out["window_open_after_check"], "the window must be PROVEN open around the check, not assumed"
    assert out["has_access_in_window"] is True, "authoritative status is already 'refunded' yet access is still granted"
    assert out["entitlement_active_after_revocation"] is False, "sanity: revocation does complete eventually -- this is a WINDOW, not a permanent failure"
    print("  Confirmed P0: authoritative=refunded, entitlement still active, access check answered True (window proven open before and after)")


def test_fix_check_access_verifies_authoritative_closes_the_window():
    out = asyncio.run(_access_during_revocation_lag({"check_access_verifies_authoritative": True}))
    assert out["window_open_before_check"] and out["window_open_after_check"], "same window, proven open -- so this is a like-for-like comparison"
    assert out["has_access_in_window"] is False, "with the authoritative re-check, access is denied the moment the authoritative refund lands"


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
    print("Alle Gap-Closure-Tests bestanden (Amount/Tier/Currency, Tenant, echtes HMAC, Revocation-Lag-Fenster).")
