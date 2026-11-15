"""HOLDOUT reconstruction: a bare ownership claim grants the top tier behind a real step-up.

Real source (independent, public fix):
  mppx-condition-gate GHSA-jg6q-3qfh-r9f8 -- grants access from a CLAIMED wallet/ownership with no
  proof of control. Corroborating alternate-flow grant: Ghost GHSA-xm43-3m56-w3wf (a cheap
  alternate/donation flow granted a paid membership). Fix: require a server-issued proof tied to a
  real purchase; a bare claim is never enough.

Hardened context: the claim/activate route is correctly guarded by a one-time step-up challenge
(defense 3) and rate limiting (defense 5) -- enforced in BOTH flaw_on and patched. flaw_on flips
exactly one check: with a valid step-up solved, a bare ownership assertion grants the top tier. The
step-up is anti-automation, not an entitlement check.

Author-blind HOLDOUT instance: own glue-route shape, own claim-field vocabulary, own seed.
"""
from __future__ import annotations

from _hardened import _CHALLENGE_ROUTES, _CHAL_FIELDS, HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "hd_claim_unlock"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_UNLOCK_ROUTES = ["membership/assert", "pro/activate", "tier/claim", "benefit/unlock", "ownership/declare"]
_OWNF = ["holder_id", "membership_no", "owns_token", "serial_no", "wallet_ref"]


class Target(HardenedCommerce):
    def _glue_catalog(self):
        return [{"method": "POST", "path": self.s.custom(_UNLOCK_ROUTES, "hd_unlock"),
                 "fields": [self.s.one(_CHAL_FIELDS, "h_chal_field"), self.s.one(_OWNF, "hd_own")]}]

    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_UNLOCK_ROUTES, "hd_unlock")
        if method == "POST" and path == route:
            tid = ident["tenant"]
            tenant = self.tenants[tid]
            if not self._rate_ok(tid):
                return 429, {"error": "rate_limited"}
            token = body.get(self.s.one(_CHAL_FIELDS, "h_chal_field"))
            if not self._consume_challenge(token, tid):  # defense 3, enforced in BOTH
                return 401, {"error": "step_up_required"}
            claim = body.get(self.s.one(_OWNF, "hd_own"))
            if self.flaw_on:
                if claim:  # BUG: a bare, unproven ownership assertion is trusted
                    self._grant_plan(tenant, self.top)
                    return 200, {"granted": self.top}
                return 400, {"error": "missing_claim"}
            return 403, {"error": "ownership_proof_required"}  # FIX: a server-issued proof is required
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    return {"assert_ownership": {"method": "POST", "path": scheme.custom(_UNLOCK_ROUTES, "hd_unlock"),
                                 "observed_via": "public_api_reference",
                                 "request_fields": {"challenge": scheme.one(_CHAL_FIELDS, "h_chal_field"),
                                                    "owns": scheme.one(_OWNF, "hd_own")}}}


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
    route = S.custom(_UNLOCK_ROUTES, "hd_unlock")
    await c.call("POST", route, token=tok, body={S.one(_CHAL_FIELDS, "h_chal_field"): token,
                                                 S.one(_OWNF, "hd_own"): "any-holder"})
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
