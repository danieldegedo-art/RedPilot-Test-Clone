"""HARDENED reconstruction: multi-service / federated confirm SKIPPED (reference trusted unverified).

Real source (independent, public fix):
  OwnPay GHSA-7wwh-c3v9-fc55 (PR #623) -- "TrustlyGateway::verify() previously accepted any
  non-empty gateway_trx_id as completed; it now fails closed." Corroborating: FOSSBilling
  GHSA-7v47-rh46-w923 (entitlement reachable without verification).

Hardened context: the entitlement side and the gateway are separate concerns. The correct grant
op verifies the presented payment reference against the gateway record (it must be a SETTLED
payment) and binds it to the caller (defense 6). flaw_on flips exactly one check: it accepts the
caller's reference without verifying it settled -- so a reference from the caller's OWN unpaid
order (no forgery, no id guessing) is enough to be granted.

Generalized critical class: access-without-payment (federated/cross-service confirm skipped).
Pre-registered under today's engine: UNCERTAIN (the shipped federation probe may reach it).
"""
from __future__ import annotations

from _hardened import HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "h_federated_skip"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_FED_ROUTES = ["entitlement/confirm", "activate-by-receipt", "grant-from-payment", "link-purchase", "claim-receipt"]
_FEDREF_FIELDS = ["receipt", "payment_ref", "settlement_id", "gateway_ref", "order_token"]


class Target(HardenedCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_FED_ROUTES, "h_fed")
        if method == "POST" and path == route:
            tid = ident["tenant"]
            tenant = self.tenants[tid]
            ref = body.get(self.s.one(_FEDREF_FIELDS, "h_fedref"))
            p = self.payments.get(ref or "")
            if self.flaw_on:
                # BUG: trusts the caller's reference as "completed" without verifying it settled.
                if p is not None and p["tenant"] == tid:
                    self._grant_plan(tenant, p["plan"])
                    return 200, {"granted": p["plan"]}
                return 400, {"error": "missing_reference"}
            # FIX: the gateway must confirm the payment really settled (fail closed).
            if p is not None and p["tenant"] == tid and p.get("captured"):
                self._grant_plan(tenant, p["plan"])
                return 200, {"granted": p["plan"]}
            return 402, {"error": "payment_not_verified"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    return {"entitlement_confirm": {"method": "POST", "path": scheme.custom(_FED_ROUTES, "h_fed"),
                                    "observed_via": "public_api_reference",
                                    "request_fields": {"payment_ref": scheme.one(_FEDREF_FIELDS, "h_fedref")}}}


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
    pid = co.get(F("payment_id"))  # the caller's OWN reference for an order it never paid
    route = S.custom(_FED_ROUTES, "h_fed")
    await c.call("POST", route, token=tok, body={S.one(_FEDREF_FIELDS, "h_fedref"): pid})
    return await c.feature_allowed(tok, "feature_basic", "export_id")
