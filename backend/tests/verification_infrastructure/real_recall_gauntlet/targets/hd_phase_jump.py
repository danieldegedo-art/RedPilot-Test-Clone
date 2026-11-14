"""HOLDOUT reconstruction: a client-supplied phase jumps the order straight to entitled.

Real source (independent, public fix):
  Solidus GHSA-qwqm-3jx5-rr8m -- "checkout state skip via unvalidated state parameter": a user
  could pass a later valid state to skip over the callbacks tied to intermediate transitions. The
  fix only accepts a requested state the order has already reached or passed (else 422).

Hardened context: a fulfilled order is legitimately entitled, and the legitimate path to
"fulfilled" is a real capture (server-side settle). flaw_on flips exactly one check: the phase
update endpoint trusts a client-supplied target phase and lets the order jump to the terminal
phase without a captured payment -> entitlement without payment.

Author-blind HOLDOUT instance: own glue-route shape, own phase vocabulary, own seed.
"""
from __future__ import annotations

from _hardened import HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "hd_phase_jump"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ADVANCE_ROUTES = ["fulfilment/advance", "basket/transition", "order/progress", "checkout/move", "purchase/set-phase"]
_PHASE_FIELDS = ["phase", "stage", "milestone", "lifecycle", "checkpoint"]
_PHASE_SEQ = ("opened", "reviewing", "charging", "fulfilled")


class Target(HardenedCommerce):
    def _glue_catalog(self):
        return [{"method": "POST", "path": self.s.custom(_ADVANCE_ROUTES, "hd_phase"),
                 "fields": [self.s.field("payment_id"), self.s.one(_PHASE_FIELDS, "hd_phase_field")]}]

    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ADVANCE_ROUTES, "hd_phase")
        if method == "POST" and path == route:
            tid = ident["tenant"]
            tenant = self.tenants[tid]
            pid = body.get(self.s.field("payment_id")) or body.get("payment_id")
            p = self.payments.get(pid or "")
            if p is None or p["tenant"] != tid:
                return 404, {"error": "unknown_order"}
            requested = body.get(self.s.one(_PHASE_FIELDS, "hd_phase_field"))
            if requested not in _PHASE_SEQ:
                return 400, {"error": "unknown_phase"}
            cur = _PHASE_SEQ.index(p.get("order_phase", "opened"))
            tgt = _PHASE_SEQ.index(requested)
            if not self.flaw_on and tgt > cur:
                return 422, {"error": "illegal_phase_transition"}  # FIX: no forward jump (Solidus)
            p["order_phase"] = requested  # flaw: trusts the client-supplied target phase
            if requested == _PHASE_SEQ[-1]:
                self._grant_plan(tenant, p["plan"])  # a fulfilled order is entitled
            return 200, {self.s.one(_PHASE_FIELDS, "hd_phase_field"): p["order_phase"]}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    return {"phase_advance": {"method": "POST", "path": scheme.custom(_ADVANCE_ROUTES, "hd_phase"),
                              "observed_via": "public_api_reference",
                              "request_fields": {"payment_id": scheme.field("payment_id"),
                                                 "phase": scheme.one(_PHASE_FIELDS, "hd_phase_field")}}}


def brief(base_url, scheme, declare_glue=True):
    return hardened_brief(base_url, scheme, plan_names=PLANS, prices=PRICES,
                          extra_ops=glue_ops(scheme) if declare_glue else None)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_basic", "export_id"):
        return False
    _st, co = await c.call("POST", S.route("checkout"), token=tok, body={F("plan"): "basic", F("currency"): "USD"})
    pid = co.get(F("payment_id"))
    route = S.custom(_ADVANCE_ROUTES, "hd_phase")
    await c.call("POST", route, token=tok,
                 body={F("payment_id"): pid, S.one(_PHASE_FIELDS, "hd_phase_field"): _PHASE_SEQ[-1]})
    return await c.feature_allowed(tok, "feature_basic", "export_id")
