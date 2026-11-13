"""Anonymised reconstruction of: ENTITLEMENT FROM A CLAIM OF OWNERSHIP WITH NO PROOF.

Real source (independent, public fix):
  GHSA-jg6q-3qfh-r9f8 (@insumermodel/mppx-condition-gate) -- grants free access based on a
  wallet the user only CLAIMS to own, without verifying control of it.

Faithful logic: an 'entitlement/claim' route grants the top tier to anyone who asserts
ownership of a license/wallet id. flaw_on trusts the assertion; the patched version requires
a proof the claimant cannot fabricate from outside (a server-issued ownership token tied to a
real purchase). The claim route is glue-specific and undeclared.

Engine class: nearest is PBB-OPEN/PBB-U, but the grant is via an undeclared claim route, not
the modelled payment flow. Expected a-priori: MISS (possibly PARTIAL if OPEN heuristics fire).
"""
from __future__ import annotations

from _core import BaseCommerce, spine_brief
from _probe import Client

FAMILY = "proof_of_control"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_ROUTES = ["entitlement/claim", "license/activate", "ownership/assert", "unlock"]
_OWNF = ["owns", "wallet", "license_id", "holder"]


class Target(BaseCommerce):
    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_ROUTES, "claim")
        if method == "POST" and path == route:
            tenant = self.tenants[ident["tenant"]]
            claim = body.get(self.s.one(_OWNF, "claim_field"))
            if self.flaw_on:
                if claim:  # BUG: trusts an unproven ownership claim
                    self._grant_plan(tenant, "pro")
                    return 200, {"granted": "pro"}
                return 400, {"error": "missing_claim"}
            # correct: a bare claim is never enough; a server-issued proof-of-purchase is required
            return 403, {"error": "ownership_proof_required"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def brief(base_url, scheme):
    return spine_brief(base_url, scheme, plan_names=PLANS, prices=PRICES)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    route, of = S.custom(_ROUTES, "claim"), S.one(_OWNF, "claim_field")
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False
    await c.call("POST", route, token=tok, body={of: "wallet-anything"})
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
