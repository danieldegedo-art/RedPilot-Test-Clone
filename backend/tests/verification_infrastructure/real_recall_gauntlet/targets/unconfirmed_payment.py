"""Anonymised reconstruction of: ENTITLEMENT GRANTED ON AN UNCONFIRMED PAYMENT.

Real source (independent, public fix):
  @payloadcms/plugin-ecommerce GHSA-8r29-2mp2-pmrw -- a flaw in validating order
  confirmations let an order be treated as paid without a valid captured payment. Fixed by
  verifying the payment really succeeded before confirming the order.

Faithful logic: flaw_on trusts the client-presented return ``status`` and grants the plan
even though the sandbox payment was declined / never captured.

Engine class: PBB-U (unconfirmed_payment_grants_access). Expected a-priori: FIND.
"""
from __future__ import annotations

from _core import CREDITS_PER_PAYMENT, BaseCommerce, spine_brief
from _probe import Client

FAMILY = "unconfirmed_payment"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}


class Target(BaseCommerce):
    def grant_on_return(self, caller_tenant, payment, q, body):
        if self.flaw_on:
            # BUG: grants on the client-claimed status without requiring real capture.
            if payment["tenant"] == caller_tenant \
               and (q.get(self.s.field("status")) or q.get("status")) == "success" and not payment.get("granted"):
                payment["granted"] = True
                t = self.tenants[payment["tenant"]]
                self._grant_plan(t, payment["plan"])
                t["quota"] = t.get("quota", 0) + CREDITS_PER_PAYMENT
                return payment["tenant"]
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
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_basic", "export_id"):
        return False
    _st, co = await c.call("POST", S.route("checkout"), token=tok, body={F("plan"): "basic", F("currency"): "USD"})
    pid = co.get(F("payment_id"))
    await c.call("POST", S.route("pay") + f"/{pid}", token=tok, body={"outcome": "declined"})  # payment did NOT succeed
    await c.call("GET", S.route("return"), token=tok, query={F("payment_id"): pid, F("status"): "success"})
    return await c.feature_allowed(tok, "feature_basic", "export_id")
