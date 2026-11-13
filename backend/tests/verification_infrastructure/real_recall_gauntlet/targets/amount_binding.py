"""AnonVul-anonymised reconstruction of: SERVER TRUSTS A CLIENT-SUPPLIED PAYMENT AMOUNT.

Real source (independent, public fix):
  Solidus GHSA-c2fq-w6qj-3hj4 -- "arbitrary payment amounts enabling underpayment".
  A customer could submit the payment amount for an order; the server used it instead of
  the authoritative order total, so a top-tier entitlement could be bought for a few cents.
  Fixed in Solidus 4.7.1 / 4.6.3 by making the server authoritative for the charged amount.

Faithful logic: the ONLY change from the correct backbone is that ``resolve_billed_amount``
trusts the client's amount field when present. The amount field is part of the authorised
checkout request (observable in a recorded paid session), so the brief declares it -- this
is an IN-VOCABULARY case the engine's price-binding experiment (PBB-F) should find.

Engine class: PBB-F (plan_or_price_binding). Expected a-priori: FIND.
"""
from __future__ import annotations

from _core import BaseCommerce, spine_brief
from _probe import Client

FAMILY = "amount_binding"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0, "JPY": 1350.0}, "pro": {"USD": 99.0, "JPY": 14850.0}}


def brief(base_url, scheme):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


class Target(BaseCommerce):
    def resolve_billed_amount(self, plan: str, currency: str, body: dict) -> float:
        if self.flaw_on:
            client_amt = body.get(self.s.field("amount"))
            if isinstance(client_amt, (int, float)) and not isinstance(client_amt, bool):
                return float(client_amt)  # BUG: trusts the client-submitted amount
        return self.prices[plan][currency]


def make(scheme, flaw_on: bool, path_log=None) -> Target:
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


async def probe_truth(scheme, flaw_on: bool) -> bool:
    """A top-tier entitlement is obtained for a token amount far below the real price."""
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    # baseline: unpaid identity is denied the tier feature
    unpaid, _ = await c.signup()
    if await c.feature_allowed(unpaid, "feature_tier", "report_id", method="GET"):
        return False  # feature open to everyone -> not this flaw
    # attack: buy 'pro' for 1 cent
    tok, _ = await c.signup()
    st, co = await c.call("POST", S.route("checkout"), token=tok,
                          body={F("plan"): "pro", F("currency"): "USD", F("amount"): 0.01})
    if st != 201:
        return False
    billed = co.get(F("amount"))
    pid = co.get(F("payment_id"))
    underpaid = isinstance(billed, (int, float)) and billed < PRICES["pro"]["USD"]
    await c.call("POST", S.route("pay") + f"/{pid}", token=tok, body={"outcome": "success"})
    await c.call("GET", S.route("return"), token=tok, query={F("payment_id"): pid, F("status"): "success"})
    got_tier = await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
    return bool(underpaid and got_tier)
