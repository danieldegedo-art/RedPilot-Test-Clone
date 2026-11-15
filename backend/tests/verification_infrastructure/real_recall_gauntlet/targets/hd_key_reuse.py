"""HOLDOUT reconstruction: a single-use confirmation credential is replayable (re-grants).

Real source (independent, public fix):
  mppx GHSA-8mhj-rffc-rcvw / CVE-2026-34210 -- the stripe/charge method "did not check Stripe's
  Idempotent-Replayed response header when creating PaymentIntents", so an attacker could "pay once
  and consume unlimited resources by replaying the credential." Fixed in 0.4.11.

Hardened context: the grant-affecting credit/top-up op requires an idempotency key (defense 2) and
a settled payment owned by the caller (defense 6). flaw_on flips exactly one check: the key is never
recorded, so each replay of the same credential re-applies the grant -- entitlement beyond the
single qualifying payment.

Author-blind HOLDOUT instance: own module, own seed; the single flipped check lives in `_record_idem`.
"""
from __future__ import annotations

from _hardened import _CONFIRM_ROUTES, _IDEM_FIELDS, _REF_FIELDS, HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "hd_key_reuse"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}


class Target(HardenedCommerce):
    def _record_idem(self, key):
        if self.flaw_on:
            # BUG: the idempotency key is never recorded, so every replay is treated as first use.
            return True
        return super()._record_idem(key)


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme, declare_glue=True):
    return hardened_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    tok, _ = await c.signup()
    _st, co = await c.call("POST", S.route("checkout"), token=tok, body={F("plan"): "basic", F("currency"): "USD"})
    pid = co.get(F("payment_id"))
    await c.call("POST", S.route("pay") + f"/{pid}", token=tok, body={"outcome": "success"})
    confirm = S.custom(_CONFIRM_ROUTES, "h_confirm")
    idem, ref = S.one(_IDEM_FIELDS, "h_idem"), S.one(_REF_FIELDS, "h_ref")
    key = f"holdout-reuse-{scheme.seed}"
    _s1, r1 = await c.call("POST", confirm, token=tok, body={idem: key, ref: pid})
    q1 = r1.get("remaining")
    # replay the SAME single-use credential twice more -- no new payment occurs.
    await c.call("POST", confirm, token=tok, body={idem: key, ref: pid})
    _s3, r3 = await c.call("POST", confirm, token=tok, body={idem: key, ref: pid})
    q3 = r3.get("remaining")
    return isinstance(q1, int) and isinstance(q3, int) and q3 > q1  # extra entitlement from pure replay
