"""Anonymised reconstruction of: A DISABLED DISCOUNT IS STILL HONORED VIA THE API.

Real source (independent, public fix):
  microweber GHSA-qjfx-fvx7-3wvw -- disabling coupon functionality in the admin does not
  stop API requests from applying it, so a lower price / entitlement is still obtained.

Faithful logic: the coupon is administratively DISABLED. flaw_on: the API redemption path
does not consult the enabled flag and still grants. The route/code are glue-specific and
undeclared.

Engine class: outside the fixed 10 (coupon lifecycle). Expected a-priori: MISS.
"""
from __future__ import annotations

from _core import BaseCommerce, spine_brief
from _probe import Client

FAMILY = "discount_disabled_api"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ROUTES = ["coupon/apply", "discount/use", "promo/redeem", "apply-code"]
_CODEF = ["code", "discount", "promo", "coupon"]
_CODES = ["LAUNCH", "BLACKFRIDAY", "EARLYBIRD", "SAVER"]


def _code(scheme):
    return scheme.one(_CODES, "disc_value")


class Target(BaseCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ROUTES, "disc")
        if method == "POST" and path == route:
            tenant = self.tenants[ident["tenant"]]
            code = body.get(self.s.one(_CODEF, "disc_field")) or body.get("code")
            if code != _code(self.s):
                return 400, {"error": "invalid_discount"}
            enabled = False  # admin has DISABLED this coupon
            if not self.flaw_on and not enabled:
                return 403, {"error": "discount_disabled"}  # correct: API honors the flag
            self._grant_plan(tenant, "pro")  # BUG when flaw_on: flag never checked on the API path
            return 200, {"granted": "pro"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    return {"op_discount": {"method": "POST", "path": scheme.custom(_ROUTES, "disc"),
                           "observed_via": "authorized_browser_trace",
                           "request_fields": {"code": scheme.one(_CODEF, "disc_field")}}}


def brief(base_url, scheme, declare_glue=False):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES,
                       extra_ops=glue_ops(scheme) if declare_glue else None)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    route, cf, code = S.custom(_ROUTES, "disc"), S.one(_CODEF, "disc_field"), _code(S)
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False
    st, _r = await c.call("POST", route, token=tok, body={cf: code})
    return st == 200 and await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
