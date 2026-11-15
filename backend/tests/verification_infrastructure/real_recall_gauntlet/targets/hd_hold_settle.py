"""HOLDOUT reconstruction: a HELD (authorized, not-yet-settled) payment is treated as paid.

Real source (independent, public fix):
  Aimeos ai-client-html GHSA-v4g2-cm5v-cxv7 -- digital goods were downloadable "without valid
  payment, e.g. if the payment didn't succeed". Corroborating real-world pattern: Medusa #13849
  (a Stripe `processing` intent treated as authorized) and Paddle's guidance to provision only on
  the terminal `completed`/`succeeded` event.

Hardened context: the grant is server-authoritative on a REAL capture (defense 1). An authorize
HOLD is a legitimate transient state but must NOT entitle. flaw_on flips exactly one check: a held
(non-settled) payment is accepted as entitling, so a caller who only places the hold (never lets it
capture) gets access with no qualifying payment.

Author-blind HOLDOUT instance: own module, own seed; the single flipped check lives in `_entitling`.
"""
from __future__ import annotations

from _hardened import _AUTHORIZE_ROUTES, HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "hd_hold_settle"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}


class Target(HardenedCommerce):
    def _entitling(self, p):
        if self.flaw_on:
            # BUG: a hold / non-settled state is accepted as a completed payment.
            return bool(p.get("captured")) or p.get("state") == "authorized"
        return super()._entitling(p)


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme, declare_glue=True):
    return hardened_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_basic", "export_id"):
        return False  # fixture sanity: a fresh identity must be denied first
    _st, co = await c.call("POST", S.route("checkout"), token=tok, body={F("plan"): "basic", F("currency"): "USD"})
    pid = co.get(F("payment_id"))
    auth = S.custom(_AUTHORIZE_ROUTES, "h_authorize")
    await c.call("POST", auth + f"/{pid}", token=tok)  # HOLD ONLY -- payment never captured/settled
    return await c.feature_allowed(tok, "feature_basic", "export_id")
