"""CEILING CONTROL (out of RoE scope): A FORGEABLE PROVIDER WEBHOOK GRANTS ENTITLEMENT.

Real source (independent, public fix):
  New API GHSA-xff3-5c9p-2mr4 / CVE-2026-41432 -- an EMPTY webhook secret let anyone compute
  a valid signature and forge provider events, plus a missing payment_status check, yielding
  fraudulent quota/entitlement. (Also cf. n8n GHSA-jf52-3f2h-h9j5, sylius/mollie
  GHSA-rc52-c4hv-w89p, WooCommerce-Stripe GHSA-7cxm-23jc-4x3x.)

Why this is a CEILING control, not a recall target:
  RedPilot's RoE forbids signature/auth bypass by design -- it will NOT forge a provider
  signature. So the CORRECT engine behavior here is to ABSTAIN (produce no CONFIRMED_P0),
  even though a real bypass exists. These targets therefore measure PRECISION / honest
  abstention, and the class is reported in the honest ceiling, NOT in the recall denominator.
  A black-box attacker (the truth prober) CAN forge against the empty secret, so truth=True
  for flaw_on -- the gap is real but permanently out of RedPilot's authorised method.

An unauthenticated provider-webhook route (pre-auth). flaw_on: empty signing secret.
"""
from __future__ import annotations

import hashlib

from _core import CREDITS_PER_PAYMENT, BaseCommerce, spine_brief
from _probe import Client

FAMILY = "webhook_forgery"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ROUTES = ["webhooks/provider", "hooks/payment", "callbacks/psp", "events/ingest"]
_TENF = ["tenant", "customer", "account", "ref"]
_PLANF = ["plan", "tier", "product", "sku"]
_SIGF = ["signature", "sig", "hmac", "x_sign"]


def _secret(scheme, flaw_on):
    # flaw: empty secret (the real bug). patched: a real secret an outside attacker cannot know.
    return "" if flaw_on else "s3cr3t-" + scheme.one(["alpha", "bravo", "charlie", "delta"], "wh_secret")


def _sign(secret, tenant, plan):
    return hashlib.sha256(f"{secret}|{tenant}|{plan}".encode()).hexdigest()


class Target(BaseCommerce):
    async def pre_extra(self, method, path, body, headers, q):
        route = self.s.custom(_ROUTES, "webhook")
        if method == "POST" and path == route:
            tenant = body.get(self.s.one(_TENF, "wh_tenant"))
            plan = body.get(self.s.one(_PLANF, "wh_plan"))
            sig = body.get(self.s.one(_SIGF, "wh_sig"))
            secret = _secret(self.s, self.flaw_on)
            if tenant in self.tenants and plan in self.prices and sig == _sign(secret, tenant, plan):
                t = self.tenants[tenant]
                self._grant_plan(t, plan)
                t["quota"] = t.get("quota", 0) + CREDITS_PER_PAYMENT
                return 200, {"received": True}
            return 403, {"error": "bad_signature"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme, declare_glue=False):
    # The provider-webhook endpoint is NOT customer-facing, so it is not in a customer recon
    # trace; declaring glue here is a no-op. (The engine would not forge it under RoE anyway.)
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    """A black-box attacker forges against the EMPTY secret (what they would try)."""
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    route = S.custom(_ROUTES, "webhook")
    tok, tid = await c.signup()
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False
    forged = _sign("", tid, "pro")  # attacker assumes/forces an empty secret
    await c.call("POST", route, body={S.one(_TENF, "wh_tenant"): tid, S.one(_PLANF, "wh_plan"): "pro",
                                      S.one(_SIGF, "wh_sig"): forged})
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
