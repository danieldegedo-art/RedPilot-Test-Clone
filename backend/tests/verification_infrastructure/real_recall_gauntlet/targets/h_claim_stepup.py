"""HARDENED reconstruction: alternate-flow / claim grant behind a REAL step-up challenge.

Real source (independent, public fix):
  mppx-condition-gate GHSA-jg6q-3qfh-r9f8 -- grants access from a CLAIMED wallet/ownership with no
  proof of control. Corroborating alternate-flow grant: Ghost GHSA-xm43-3m56-w3wf (a cheap
  alternate/donation flow granted a paid membership). Fix: require a server-issued proof tied to a
  real purchase; a bare claim is never enough.

Hardened context: the claim/redeem route is correctly guarded by a one-time step-up challenge
(defense 3) and rate limiting (defense 5) -- enforced in BOTH flaw_on and patched. flaw_on flips
exactly one check: with a valid step-up solved, a bare ownership claim grants the top tier. The
step-up is anti-automation, not an entitlement check.

Generalized critical class: access-without-payment (alternate-flow / claim grant).
Pre-registered under today's engine: MISS (likely); needs claim-route discovery + behaviour probe.
"""
from __future__ import annotations

from _hardened import _CHALLENGE_ROUTES, _CHAL_FIELDS, HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "h_claim_stepup"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_CLAIM_ROUTES = ["entitlement/claim", "license/activate", "ownership/assert", "unlock-pro", "redeem-claim"]
_CLAIMF = ["owns", "license_id", "wallet", "holder", "serial"]


class Target(HardenedCommerce):
    def _glue_catalog(self):
        return [{"method": "POST", "path": self.s.custom(_CLAIM_ROUTES, "h_claim"),
                 "fields": [self.s.one(_CHAL_FIELDS, "h_chal_field"), self.s.one(_CLAIMF, "h_claim_field")]}]

    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_CLAIM_ROUTES, "h_claim")
        if method == "POST" and path == route:
            tid = ident["tenant"]
            tenant = self.tenants[tid]
            if not self._rate_ok(tid):
                return 429, {"error": "rate_limited"}
            token = body.get(self.s.one(_CHAL_FIELDS, "h_chal_field"))
            if not self._consume_challenge(token, tid):  # defense 3, enforced in BOTH
                return 401, {"error": "step_up_required"}
            claim = body.get(self.s.one(_CLAIMF, "h_claim_field"))
            if self.flaw_on:
                if claim:  # BUG: a bare, unproven ownership claim is trusted
                    self._grant_plan(tenant, self.top)
                    return 200, {"granted": self.top}
                return 400, {"error": "missing_claim"}
            return 403, {"error": "ownership_proof_required"}  # FIX: a server-issued proof is required
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    return {"claim_ownership": {"method": "POST", "path": scheme.custom(_CLAIM_ROUTES, "h_claim"),
                                "observed_via": "public_api_reference",
                                "request_fields": {"challenge": scheme.one(_CHAL_FIELDS, "h_chal_field"),
                                                   "owns": scheme.one(_CLAIMF, "h_claim_field")}}}


def brief(base_url, scheme, declare_glue=True):
    return hardened_brief(base_url, scheme, plan_names=PLANS, prices=PRICES,
                          extra_ops=glue_ops(scheme) if declare_glue else None)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False
    chal = S.custom(_CHALLENGE_ROUTES, "h_challenge")
    _st, cr = await c.call("POST", chal, token=tok)  # solve the step-up LEGITIMATELY
    token = cr.get(S.one(_CHAL_FIELDS, "h_chal_field"))
    route = S.custom(_CLAIM_ROUTES, "h_claim")
    await c.call("POST", route, token=tok, body={S.one(_CHAL_FIELDS, "h_chal_field"): token,
                                                 S.one(_CLAIMF, "h_claim_field"): "any-wallet"})
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
