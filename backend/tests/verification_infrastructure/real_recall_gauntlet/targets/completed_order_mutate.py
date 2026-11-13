"""Anonymised reconstruction of: AN ALREADY-COMPLETED ORDER CAN STILL BE MUTATED.

Real source (independent, public fix):
  Sylius GHSA-5597-7rmh-97q5 -- the cart component could modify or delete an order that was
  already completed. A terminal-state order must be immutable.

Faithful logic: after a basic order is paid and granted, a 'cart/amend' route lets the buyer
change the order's plan to a higher tier without paying the difference. flaw_on skips the
terminal-state check. The amend route is glue-specific and undeclared.

Engine class: outside the fixed 10 (order state-machine integrity). Expected a-priori: MISS.
"""
from __future__ import annotations

from _core import BaseCommerce, spine_brief
from _probe import Client

FAMILY = "completed_order_mutate"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ROUTES = ["cart/amend", "order/edit", "basket/update", "order/change-plan"]
_PLANF = ["plan", "tier", "sku", "new_plan"]
_IDF = ["order_ref", "order_id", "cart_id", "ref"]


class Target(BaseCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ROUTES, "amend")
        if method == "POST" and path == route:
            tid = ident["tenant"]
            tenant = self.tenants[tid]
            pid = body.get(self.s.one(_IDF, "amend_id")) or body.get("order_ref")
            new_plan = body.get(self.s.one(_PLANF, "amend_plan")) or body.get("plan")
            p = self.payments.get(pid or "")
            if p is None or p["tenant"] != tid or new_plan not in self.prices:
                return 404, {"error": "unknown_order"}
            if not self.flaw_on and p.get("granted"):
                return 409, {"error": "order_completed_immutable"}  # correct: terminal state
            # BUG when flaw_on: mutate a completed order's plan and re-grant, no new charge.
            p["plan"] = new_plan
            self._grant_plan(tenant, new_plan)
            return 200, {"status": "amended", "plan": new_plan}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    tok, _ = await c.signup()
    _st, co = await c.call("POST", S.route("checkout"), token=tok, body={F("plan"): "basic", F("currency"): "USD"})
    pid = co.get(F("payment_id"))
    await c.call("POST", S.route("pay") + f"/{pid}", token=tok, body={"outcome": "success"})
    await c.call("GET", S.route("return"), token=tok, query={F("payment_id"): pid, F("status"): "success"})
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False  # basic buyer must not already have pro
    await c.call("POST", S.custom(_ROUTES, "amend"), token=tok,
                 body={S.one(_IDF, "amend_id"): pid, S.one(_PLANF, "amend_plan"): "pro"})
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
