"""Anonymised reconstruction of: A PAID ENTITLEMENT IS OBTAINABLE VIA A CHEAP ALTERNATE FLOW.

Real source (independent, public fix):
  Ghost GHSA-xm43-3m56-w3wf -- paid gift memberships could be obtained at minimal cost
  through the donations feature (an alternate flow that granted a paid entitlement without
  going through the priced subscription path).

Faithful logic: a 'support/donate' route accepts any small amount. flaw_on: making any
donation side-effects a paid-plan grant. The donation route is glue-specific and undeclared;
the engine models the SUBSCRIPTION flow, not an unrelated donation flow granting entitlement.

Engine class: outside the fixed 10 (alternate-flow entitlement). Expected a-priori: MISS.
"""
from __future__ import annotations

from _core import BaseCommerce, spine_brief
from _probe import Client

FAMILY = "alt_flow_entitlement"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ROUTES = ["support/donate", "tip", "contribute", "gift/send"]
_AMTF = ["amount", "sum", "value", "gift_amount"]


class Target(BaseCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ROUTES, "donate")
        if method == "POST" and path == route:
            tenant = self.tenants[ident["tenant"]]
            amt = body.get(self.s.one(_AMTF, "donate_field")) or body.get("amount") or 0
            if not isinstance(amt, (int, float)) or amt <= 0:
                return 400, {"error": "bad_amount"}
            if self.flaw_on:
                self._grant_plan(tenant, "pro")  # BUG: a donation grants a paid plan
                return 200, {"thanks": True, "granted": "pro"}
            return 200, {"thanks": True}  # correct: a donation grants nothing
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    return {"op_support": {"method": "POST", "path": scheme.custom(_ROUTES, "donate"),
                          "observed_via": "product_ui",
                          "request_fields": {"amount": scheme.one(_AMTF, "donate_field")}}}


def brief(base_url, scheme, declare_glue=False):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES,
                       extra_ops=glue_ops(scheme) if declare_glue else None)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    route, af = S.custom(_ROUTES, "donate"), S.one(_AMTF, "donate_field")
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False
    await c.call("POST", route, token=tok, body={af: 1.0})
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
