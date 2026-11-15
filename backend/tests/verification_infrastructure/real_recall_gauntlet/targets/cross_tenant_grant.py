"""Anonymised reconstruction of: ACTIVATION TRUSTS A CLIENT-NAMED BENEFICIARY ORG.

Real source (independent, public fix):
  @better-auth/stripe GHSA-h3rm-78g3-j7cp -- "cross-organization billing tampering in
  subscription actions". A subscription action carried a client-supplied reference/org id
  that was not verified to belong to the caller, so one org could change/benefit another
  org's billing. Fixed by authorizing the reference id against the caller.

Faithful logic: the activation (return flow) accepts an optional beneficiary-tenant field
that a legit user passes as their OWN org (so it IS observable in an authorised trace and
the brief declares it). flaw_on: the server does not verify the named tenant belongs to the
caller -> grants the paid plan to an arbitrary named tenant.

Engine class: PBB-G (cross_tenant_binding). Expected a-priori: FIND.
"""
from __future__ import annotations

from _core import CREDITS_PER_PAYMENT, BaseCommerce, spine_brief
from _probe import Client

FAMILY = "cross_tenant_grant"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}


class Target(BaseCommerce):
    def grant_on_return(self, caller_tenant, payment, q, body):
        named = q.get(self.s.field("tenant")) or q.get("tenant")
        if self.flaw_on and named and named in self.tenants:
            if payment["tenant"] == caller_tenant and payment.get("captured") \
               and (q.get(self.s.field("status")) or q.get("status")) == "success" and not payment.get("granted"):
                payment["granted"] = True  # BUG: no check that `named` belongs to the caller
                t = self.tenants[named]
                self._grant_plan(t, payment["plan"])
                t["quota"] = t.get("quota", 0) + CREDITS_PER_PAYMENT
                return named
            return None
        return super().grant_on_return(caller_tenant, payment, q, body)


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme, declare_glue=False):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES, map_tenant=True)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    victim, victim_tid = await c.signup()
    if await c.feature_allowed(victim, "feature_basic", "export_id"):
        return False
    attacker, _ = await c.signup()
    _st, co = await c.call("POST", S.route("checkout"), token=attacker, body={F("plan"): "basic", F("currency"): "USD"})
    pid = co.get(F("payment_id"))
    await c.call("POST", S.route("pay") + f"/{pid}", token=attacker, body={"outcome": "success"})
    await c.call("GET", S.route("return"), token=attacker,
                 query={F("payment_id"): pid, F("status"): "success", F("tenant"): victim_tid})
    return await c.feature_allowed(victim, "feature_basic", "export_id")
