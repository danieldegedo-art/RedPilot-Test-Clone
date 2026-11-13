"""Anonymised reconstruction of: A SINGLE-USE COUPON CAN BE REDEEMED REPEATEDLY.

Real source (independent, public fix):
  microweber GHSA-3p9j-442x-hjp7 -- a single-use coupon could be used multiple times
  (business-logic error), fixed in microweber 1.2.11.

Faithful logic: a promo code grants a paid plan and is meant to be consumable once. flaw_on
forgets to mark/enforce consumption, so any number of fresh identities redeem the same code
and get the paid plan for free. The coupon ROUTE and CODE are glue-code specific and are NOT
in the brief (a blind tester has neither) -- so the engine must discover both.

Engine class: outside the fixed 10 (coupon/promo lifecycle -- a declared BLOCKED gap in the
current scorecard). Expected a-priori: MISS.
"""
from __future__ import annotations

from _core import BaseCommerce, spine_brief
from _probe import Client

FAMILY = "coupon_reuse"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ROUTES = ["coupon/redeem", "promo/apply", "voucher/claim", "redeem"]
_CODEF = ["code", "coupon", "promo", "voucher"]
_CODES = ["SPRING50", "FREEPRO", "WELCOME100", "VIPPASS"]


def _code(scheme):
    return scheme.one(_CODES, "coupon_value")


class Target(BaseCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ROUTES, "coupon")
        if method == "POST" and path == route:
            tenant = self.tenants[ident["tenant"]]
            code = body.get(self.s.one(_CODEF, "coupon_field")) or body.get("code")
            if code != _code(self.s):
                return 400, {"error": "invalid_coupon"}
            used = getattr(self, "_coupon_used", False)
            if not self.flaw_on and used:
                return 409, {"error": "coupon_already_used"}  # correct: single-use enforced
            self._coupon_used = True  # BUG when flaw_on: flag set but never consulted to reject
            self._grant_plan(tenant, "pro")
            return 200, {"granted": "pro"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    route, cf, code = S.custom(_ROUTES, "coupon"), S.one(_CODEF, "coupon_field"), _code(S)
    a, _ = await c.signup()
    await c.call("POST", route, token=a, body={cf: code})            # first (legit) use
    b, _ = await c.signup()
    if await c.feature_allowed(b, "feature_tier", "report_id", method="GET"):
        return False
    st, _r = await c.call("POST", route, token=b, body={cf: code})    # reuse by a second identity
    return st == 200 and await c.feature_allowed(b, "feature_tier", "report_id", method="GET")
