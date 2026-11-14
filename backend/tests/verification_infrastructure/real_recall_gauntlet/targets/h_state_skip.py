"""HARDENED reconstruction: state-machine SKIP straight to a completed/entitled order.

Real source (independent, public fix):
  Solidus GHSA-qwqm-3jx5-rr8m -- "checkout state skip via unvalidated state parameter": a user
  could pass a later valid state to skip over the callbacks tied to intermediate transitions. The
  fix only accepts a requested state the order has already reached or passed (else 422).

Hardened context: a completed order is legitimately entitled, and the legitimate path to
"complete" is a real capture (server-side settle). flaw_on flips exactly one check: the order
update endpoint trusts a client-supplied target state and lets the order jump to "complete" without
a captured payment -> entitlement without payment.

Generalized critical class: access-without-payment (state-machine skip to entitled).
Pre-registered under today's engine: MISS (likely); fabric `_amend` is the uncertainty.
"""
from __future__ import annotations

from _hardened import HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "h_state_skip"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ORDER_ROUTES = ["orders/transition", "order/advance", "cart/state", "checkout/step", "order/update-state"]
_STATE_FIELDS = ["state", "status", "phase", "step", "stage"]
_ORDER_SEQ = ("created", "in_progress", "payment", "complete")


class Target(HardenedCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ORDER_ROUTES, "h_state")
        if method == "POST" and path == route:
            tid = ident["tenant"]
            tenant = self.tenants[tid]
            pid = body.get(self.s.field("payment_id")) or body.get("payment_id")
            p = self.payments.get(pid or "")
            if p is None or p["tenant"] != tid:
                return 404, {"error": "unknown_order"}
            requested = body.get(self.s.one(_STATE_FIELDS, "h_state_field"))
            if requested not in _ORDER_SEQ:
                return 400, {"error": "unknown_state"}
            cur = _ORDER_SEQ.index(p.get("order_state", "created"))
            tgt = _ORDER_SEQ.index(requested)
            if not self.flaw_on and tgt > cur:
                return 422, {"error": "illegal_state_transition"}  # FIX: no forward jump (Solidus)
            p["order_state"] = requested  # flaw: trusts the client-supplied target state
            if requested == "complete":
                self._grant_plan(tenant, p["plan"])  # a completed order is entitled
            return 200, {self.s.one(_STATE_FIELDS, "h_state_field"): p["order_state"]}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    return {"order_transition": {"method": "POST", "path": scheme.custom(_ORDER_ROUTES, "h_state"),
                                 "observed_via": "public_api_reference",
                                 "request_fields": {"payment_id": scheme.field("payment_id"),
                                                    "state": scheme.one(_STATE_FIELDS, "h_state_field")}}}


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
    route = S.custom(_ORDER_ROUTES, "h_state")
    await c.call("POST", route, token=tok, body={F("payment_id"): pid, S.one(_STATE_FIELDS, "h_state_field"): "complete"})
    return await c.feature_allowed(tok, "feature_basic", "export_id")
