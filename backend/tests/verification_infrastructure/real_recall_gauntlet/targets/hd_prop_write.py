"""HOLDOUT reconstruction: property-level / mass-assignment privilege escalation.

Real source (independent, public fix):
  Snipe-IT GHSA-5448-v74m-7mv7 -- "sensitive user attributes related to account privileges are
  insufficiently protected against mass assignment." Corroborating: Netmaker CVE-2023-32079
  (non-admin -> admin via mass assignment), Spree CVE-2013-2506 (mass role assignment on update).
  Fix: allow-list writable fields; reject privileged fields from the caller.

Grey-box confirmation (in RoE): an ordinary identity sends a settings update including a privileged
field (the plan) it must not be able to set. flaw_on flips exactly one check: the update applies all
fields (mass assignment), so the caller sets its own plan to the top tier -> a forbidden state
(access without payment). The published spec documents only the safe field (display name); the
privileged field is discovered by a grey-box response-diff, never guessed destructively.

Author-blind HOLDOUT instance: own glue-route shape, own safe-field vocabulary, own seed.
"""
from __future__ import annotations

from _hardened import HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "hd_prop_write"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_SETTINGS_ROUTES = ["me/profile", "settings/update", "account/edit", "user/patch", "profile/save"]
_SAFEF = ["display_name", "nickname", "avatar_label", "handle", "bio"]


class Target(HardenedCommerce):
    def _glue_catalog(self):
        # Only the documented safe field is advertised; the privileged 'plan' field is NOT in the
        # catalog -- the engine must discover it by harvesting it from a legit response (never a hint).
        return [{"method": "POST", "path": self.s.custom(_SETTINGS_ROUTES, "hd_settings"),
                 "fields": [self.s.one(_SAFEF, "hd_safe")]}]

    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_SETTINGS_ROUTES, "hd_settings")
        if method == "POST" and path == route:
            tid = ident["tenant"]
            tenant = self.tenants[tid]
            safe = self.s.one(_SAFEF, "hd_safe")
            if safe in body:
                tenant["display"] = body[safe]          # the documented, writable field
            planf = self.s.field("plan")
            if self.flaw_on:
                # BUG: mass assignment -> privileged fields from the caller are applied.
                if body.get(planf) in self.prices:
                    self._grant_plan(tenant, body[planf])
                if body.get("role"):
                    tenant["role"] = body["role"]
            return 200, {"display": tenant.get("display"),
                         self.s.field("plan"): tenant["plan"] or "free", "role": tenant.get("role", "member")}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    # Published spec documents ONLY the safe field; the privileged field is NOT advertised as writable.
    return {"settings_update": {"method": "POST", "path": scheme.custom(_SETTINGS_ROUTES, "hd_settings"),
                                "observed_via": "public_api_reference",
                                "request_fields": {"display_name": scheme.one(_SAFEF, "hd_safe")}}}


def brief(base_url, scheme, declare_glue=True):
    return hardened_brief(base_url, scheme, plan_names=PLANS, prices=PRICES,
                          extra_ops=glue_ops(scheme) if declare_glue else None)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S, F = scheme, scheme.field
    tok, _ = await c.signup()
    if await c.feature_allowed(tok, "feature_tier", "report_id", method="GET"):
        return False
    await c.call("POST", S.custom(_SETTINGS_ROUTES, "hd_settings"), token=tok,
                 body={S.one(_SAFEF, "hd_safe"): "qa", F("plan"): "pro"})  # mass-assign the plan
    return await c.feature_allowed(tok, "feature_tier", "report_id", method="GET")
