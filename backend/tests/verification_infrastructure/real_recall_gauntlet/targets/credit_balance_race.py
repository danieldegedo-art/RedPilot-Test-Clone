"""Anonymised reconstruction of: A CREDIT BALANCE CAN BE DOUBLE-SPENT UNDER CONCURRENCY.

Real source (independent, public fix):
  paymenter GHSA-pgcq-8grm-5rx9 / CVE-2026-55219 ("payWithCredit race", lockForUpdate outside
  a transaction) and GHSA-5gmm-hjfj-8ff7 (credit refund double-spend on downgrade). Root
  cause family: a check-then-write on a credit balance that is not atomic, so concurrent
  requests each see the same balance and all succeed.

Faithful logic: spending 1 credit advances one paid cycle; 2 paid cycles unlock the top
tier. A legit balance of 1 credit buys exactly 1 cycle. flaw_on introduces the real
non-atomic window (a yield between the balance check and the decrement), so two concurrent
spends off a balance of 1 both succeed -> 2 cycles -> top tier for the price of one. The
spend route is glue-specific and undeclared.

Engine class: nearest is PBB-C (duplicate value) but the mechanism is a CONCURRENCY race on
an undeclared credit route, not return-flow repetition. Expected a-priori: MISS.
"""
from __future__ import annotations

import asyncio

from _core import BaseCommerce, spine_brief
from _probe import Client

FAMILY = "credit_balance_race"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ROUTES = ["credit/spend", "wallet/debit", "balance/apply", "ledger/charge"]


class Target(BaseCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ROUTES, "spend")
        if method == "POST" and path == route:
            tenant = self.tenants[ident["tenant"]]
            cost = 1
            if tenant.get("credit", 0) >= cost:
                if self.flaw_on:
                    await asyncio.sleep(0.01)  # BUG: non-atomic window between check and write
                tenant["credit"] = tenant.get("credit", 0) - cost
                tenant["cycles"] = tenant.get("cycles", 0) + 1
                if tenant["cycles"] >= 2:
                    self._grant_plan(tenant, "pro")
                return 200, {"cycles": tenant["cycles"], "credit": tenant["credit"]}
            return 402, {"error": "insufficient_credit"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    route = S.custom(_ROUTES, "spend")
    tok, tid = await c.signup()
    t.tenants[tid]["credit"] = 1  # the identity legitimately holds one credit's worth
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False
    await asyncio.gather(*[c.call("POST", route, token=tok, body={}) for _ in range(3)])
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
