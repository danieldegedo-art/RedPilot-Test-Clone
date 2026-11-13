"""Payment-integrity adversarial test round, run for real against
entitlement_target.py over real sockets. Follows the evidence standard
the mission itself specifies: Confirmed (reproduced here, in this file),
Ruled out (tested and refuted, also here), never an invented finding.

Every "Confirmed" test below is exactly what running it produces --
delete the bug's guard flag in entitlement_target.py (flip
require_webhook_signature/dedupe_webhook_events to True, or fix Bug B's
missing authoritative check) and the corresponding test fails, which is
the point: these are live regression tests for the fixes, not a report
about a hypothetical.
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

from app.testing.check_trust_boundary import (  # noqa: E402
    check_claimed_status_matches_authoritative,
    check_entitlement_requires_authoritative_final_state,
)
from app.testing.http_client import QAHttpClient  # noqa: E402


async def _client_for(target: EntitlementTarget | None = None):
    target, server, port = await start_entitlement_target(target)
    client = QAHttpClient(base_url=f"http://127.0.0.1:{port}", timeout_seconds=2.0, proxy_url=None, headers={}, user_agent="payment-integrity/1.0")
    return target, server, client


async def _teardown(server, client) -> None:
    await client.aclose()
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# CONFIRMED P0 #1: full paywall bypass -- a forged webhook for a payment that
# was NEVER captured (in fact never even created) still grants entitlement.
# Chains bugs A (no signature) + B (trust boundary) into the mission's
# single most dangerous outcome: paid access with zero real payment.
# ---------------------------------------------------------------------------


def test_confirmed_p0_forged_webhook_grants_entitlement_with_zero_real_payment():
    async def go():
        target, server, client = await _client_for()  # defaults: signature NOT required, no dedup
        fake_payment_id = "pay_this_never_existed"
        user_id = "user_victim_or_attacker_own_account"
        _, resp = await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": fake_payment_id, "user_id": user_id, "status": "succeeded"},
        )
        _, entitlement_resp = await client.request("GET", f"/api/v1/entitlements/{user_id}")
        await _teardown(server, client)
        return resp, entitlement_resp, target.authoritative_status(fake_payment_id)

    webhook_resp, entitlement_resp, authoritative = asyncio.run(go())
    assert webhook_resp.status_code == 200
    assert entitlement_resp.body["active"] is True, "full bypass: entitlement active with no payment record ever created"
    assert authoritative is None, "authoritative record for this payment_id does not exist -- confirms zero real payment"

    violations = check_entitlement_requires_authoritative_final_state(True, authoritative)
    assert len(violations) == 1
    print(f"  Confirmed P0 evidence: {violations[0].message}")


# ---------------------------------------------------------------------------
# CONFIRMED P0 #2: webhook trusts a "succeeded" claim for a payment that is
# real but NOT final (still "authorized", never captured) -- the trust-
# boundary check catches exactly this even without the "fake id" framing.
# ---------------------------------------------------------------------------


def test_confirmed_p0_webhook_trusts_claim_over_a_real_but_non_final_payment():
    async def go():
        target, server, client = await _client_for()
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 49.99})
        payment_id = create_resp.body["id"]
        # Deliberately NOT captured -- still "authorized".
        user_id = "user_1"
        await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": user_id, "status": "succeeded"},
        )
        _, entitlement_resp = await client.request("GET", f"/api/v1/entitlements/{user_id}")
        authoritative = target.authoritative_status(payment_id)
        await _teardown(server, client)
        return entitlement_resp, authoritative

    entitlement_resp, authoritative = asyncio.run(go())
    assert authoritative == "authorized", "payment must genuinely still be non-final for this test to mean anything"
    assert entitlement_resp.body["active"] is True, "entitlement wrongly granted while payment is only 'authorized'"

    violations = check_claimed_status_matches_authoritative("succeeded", authoritative, claim_source="webhook")
    assert len(violations) == 1
    print(f"  Confirmed P0 evidence: {violations[0].message}")


# ---------------------------------------------------------------------------
# CONFIRMED P1 (escalates to P0 when chained with the above): webhook replay
# grants additional entitlement periods for one real, genuine payment.
# ---------------------------------------------------------------------------


def test_confirmed_replay_of_the_same_webhook_event_grants_multiple_periods():
    async def go():
        target, server, client = await _client_for()  # dedupe_webhook_events defaults False
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 9.99})
        payment_id = create_resp.body["id"]
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        user_id = "user_2"
        event_id = str(uuid.uuid4())
        payload = {"event_id": event_id, "payment_id": payment_id, "user_id": user_id, "status": "succeeded"}
        first = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=payload)
        second = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=payload)
        third = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=payload)
        await _teardown(server, client)
        return first[1], second[1], third[1]

    first, second, third = asyncio.run(go())
    assert first.body["periods"] == 1
    assert second.body["periods"] == 2, "replaying the IDENTICAL event must not grant a second period"
    assert third.body["periods"] == 3, "and again for a third replay -- unbounded, not a one-time double-grant"
    print(f"  Confirmed: one real payment, 3 identical webhook deliveries, {third.body['periods']} periods granted")


# ---------------------------------------------------------------------------
# CHAIN ESCALATION: bug A alone (no signature) is P1 at most on its own --
# an attacker who can't forge a valid webhook payload shape still can't do
# anything. Combined with bug B (no authoritative check), it becomes the
# P0 in test #1 above. This test isolates that bug A's absence is what
# makes the chain reachable by anyone, not just an internal misconfiguration.
# ---------------------------------------------------------------------------


def test_chain_escalation_signature_check_alone_would_have_blocked_the_p0():
    async def go():
        # Same forged-webhook scenario as the P0 test, but with signature
        # enforcement ON and no valid signature supplied.
        target, server, client = await _client_for(EntitlementTarget(require_webhook_signature=True))
        _, resp = await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": "pay_forged", "user_id": "attacker", "status": "succeeded"},
        )
        _, entitlement_resp = await client.request("GET", "/api/v1/entitlements/attacker")
        await _teardown(server, client)
        return resp, entitlement_resp

    resp, entitlement_resp = asyncio.run(go())
    assert resp.status_code == 401
    assert entitlement_resp.body["active"] is False
    print("  Chain evidence: enabling signature enforcement alone breaks the P0 chain at its first link")


# ---------------------------------------------------------------------------
# RULED OUT: the internal/admin grant_direct() path. Tested, not assumed.
# ---------------------------------------------------------------------------


def test_ruled_out_direct_grant_path_correctly_requires_captured_state():
    async def go():
        target, server, client = await _client_for()
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 20.0})
        payment_id = create_resp.body["id"]
        # Attempt 1: still authorized -- must be rejected.
        rejected = await client.request("POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": "user_3", "payment_id": payment_id})
        # Now actually capture it, then retry -- must succeed.
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        accepted = await client.request("POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": "user_3", "payment_id": payment_id})
        await _teardown(server, client)
        return rejected[1], accepted[1]

    rejected, accepted = asyncio.run(go())
    assert rejected.status_code == 409, "grant_direct must reject a non-final payment -- ruled out as a P0 path"
    assert accepted.status_code == 200, "and correctly accept once the SAME payment is genuinely captured"
    print("  Ruled out: grant_direct() checks the authoritative record; ONLY the webhook path is broken")


def test_ruled_out_direct_grant_path_is_not_fooled_by_a_fake_payment_id():
    async def go():
        target, server, client = await _client_for()
        resp = await client.request("POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": "user_4", "payment_id": "pay_does_not_exist"})
        await _teardown(server, client)
        return resp[1]

    resp = asyncio.run(go())
    assert resp.status_code == 409
    print("  Ruled out: grant_direct() also rejects a nonexistent payment_id, not just a non-final one")


# ---------------------------------------------------------------------------
# THE FIX, VERIFIED: all three flags enabled must block the full P0 chain,
# not just weaken it. Real before/after: the exact same forged-webhook
# attack from test #1 above, replayed here against the FIXED configuration.
# ---------------------------------------------------------------------------


def test_fix_all_three_protections_enabled_blocks_the_full_p0_chain():
    async def go():
        fixed_target = EntitlementTarget(require_webhook_signature=True, dedupe_webhook_events=True, verify_authoritative_status=True)
        target, server, client = await _client_for(fixed_target)

        # Attack 1 (was Confirmed P0 #1): forged webhook, fake payment, no signature.
        _, forged = await client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": "pay_forged", "user_id": "attacker_1", "status": "succeeded"},
        )

        # Attack 2 (was Confirmed P0 #2): VALID signature, real payment, but NOT captured.
        _, create_resp = await client.request("POST", "/api/v1/payments", json_body={"amount": 49.99})
        payment_id = create_resp.body["id"]
        body2 = {"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": "attacker_2", "status": "succeeded"}
        body2["signature"] = target.sign(body2)
        _, not_final = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=body2)

        # Attack 3 (was Confirmed replay): genuine capture, valid signature, sent 3x.
        await client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        payload = {"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": "user_5", "status": "succeeded"}
        payload["signature"] = target.sign(payload)
        first = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=payload)
        second = await client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=payload)

        entitlement_1, entitlement_2, entitlement_5 = (
            (await client.request("GET", "/api/v1/entitlements/attacker_1"))[1],
            (await client.request("GET", "/api/v1/entitlements/attacker_2"))[1],
            (await client.request("GET", "/api/v1/entitlements/user_5"))[1],
        )
        await _teardown(server, client)
        return forged, not_final, first[1], second[1], entitlement_1, entitlement_2, entitlement_5

    forged, not_final, first, second, entitlement_1, entitlement_2, entitlement_5 = asyncio.run(go())
    assert forged.status_code == 401, "attack 1 (no signature) must now be rejected at the door"
    assert entitlement_1.body["active"] is False
    assert not_final.status_code == 409, "attack 2 (real signature, non-final payment) must now be rejected by the authoritative check"
    assert entitlement_2.body["active"] is False
    assert first.body["periods"] == 1
    assert second.body["status"] == "already_processed", "attack 3 (replay) must be recognized and short-circuited, not reprocessed"
    assert entitlement_5.body["paid_through_periods"] == 1, "and critically: the replay must not have incremented periods to 2"
    print("  Fix verified: all three original P0/confirmed attacks are blocked with all three protections enabled")


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
    print("Alle Payment-Integrity-Mission-Tests bestanden (Confirmed + Ruled-out, real ausgefuehrt).")
