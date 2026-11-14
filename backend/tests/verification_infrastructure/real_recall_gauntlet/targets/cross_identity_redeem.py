"""Anonymised reconstruction of: A PAYMENT CAN BE REDEEMED BY A NON-OWNING IDENTITY.

Real source (independent, public fix):
  Solidus GHSA-vgwx-9pm9-8qvj -- "customers can attach another user's stored gateway
  payment profile to their own payment". The payment object was not bound to the identity
  that created it, so one identity could redeem/attach another's payment. Fixed by binding
  the payment to its owner.

Faithful logic: flaw_on drops the owner check in the return/redeem step -- any authenticated
identity that presents a captured payment reference is granted the plan.

Engine class: PBB-X (cross_identity_binding). Expected a-priori: FIND.
"""
from __future__ import annotations

from _core import CREDITS_PER_PAYMENT, BaseCommerce, spine_brief
from _probe import Client

FAMILY = "cross_identity_redeem"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}


class Target(BaseCommerce):
    def grant_on_return(self, caller_tenant, payment, q, body):
        if self.flaw_on:
            # BUG: no check that the CALLER owns the payment -> the redeemer is granted.
            if payment.get("captured") and (q.get(self.s.field("status")) or q.get("status")) == "success" \
               and not payment.get("granted"):
                payment["granted"] = True
                t = self.tenants[caller_tenant]
                self._grant_plan(t, payment["plan"])
                t["quota"] = t.get("quota", 0) + CREDITS_PER_PAYMENT
                return caller_tenant
            return None
        return super().grant_on_return(caller_tenant, payment, q, body)


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme, declare_glue=False):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    owner, _ = await c.signup()
    _st, co = await c.call("POST", S.route("checkout"), token=owner, body={F("plan"): "basic", F("currency"): "USD"})
    pid = co.get(F("payment_id"))
    await c.call("POST", S.route("pay") + f"/{pid}", token=owner, body={"outcome": "success"})  # owner pays, does NOT redeem
    attacker, _ = await c.signup()
    if await c.feature_allowed(attacker, "feature_basic", "export_id"):
        return False
    await c.call("GET", S.route("return"), token=attacker, query={F("payment_id"): pid, F("status"): "success"})
    return await c.feature_allowed(attacker, "feature_basic", "export_id")
