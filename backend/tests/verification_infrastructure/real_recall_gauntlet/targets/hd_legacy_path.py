"""HOLDOUT reconstruction: a deprecated/shadow route to a resource skips the access control.

Real source (independent, public fix):
  DefectDojo GHSA-9jr7-2hgp-vhp8 -- "API v1 and v2 lacking appropriate access controls; APIv1 is
  deprecated and will not be fixed." Corroborating: the Gitea incomplete-fix parallel-path pattern
  (the authorization check was added on one route but not on a parallel route to the same
  resource). Fix: apply the same authorization check on every route; retire the uncontrolled path.

Grey-box confirmation (in RoE): the published spec lists a current tier-report route (plan-gated)
AND a legacy route to the same report. flaw_on flips exactly one check: the legacy route omits the
plan check, so an unpaid identity gets the top-tier report through it -- access the current route
correctly denies.

Author-blind HOLDOUT instance: own glue-route shape, own legacy-path vocabulary, own seed. The
legacy route is advertised WITHOUT a 'deprecated' flag -- the engine must infer it by behaviour.
"""
from __future__ import annotations

from _core import _id
from _hardened import HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "hd_legacy_path"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_OLD_ROUTES = ["v0/report", "classic/export", "legacy/analytics", "retired/full-report", "compat/dump"]


class Target(HardenedCommerce):
    def _glue_catalog(self):
        # The legacy route IS advertised (improper inventory is the point), but WITHOUT a
        # 'deprecated' flag -- the engine must infer it is an alternate path by behaviour.
        return [{"method": "GET", "path": self.s.custom(_OLD_ROUTES, "hd_old"), "fields": []}]

    async def extra(self, method, path, body, ident, q):
        route = self.s.custom(_OLD_ROUTES, "hd_old")
        if method == "GET" and path == route:
            tenant = self.tenants[ident["tenant"]]
            if self.flaw_on or tenant["plan"] == self.top:  # BUG(flaw): legacy route skips the plan check
                return 200, {"report_id": _id("rep"), "legacy": True}
            return 403, {"error": "upgrade_required"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    # Improper inventory: the legacy route IS in the published spec (that is the point).
    return {"legacy_report": {"method": "GET", "path": scheme.custom(_OLD_ROUTES, "hd_old"),
                              "observed_via": "public_api_reference", "deprecated": True}}


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
    st, r = await c.call("GET", S.custom(_OLD_ROUTES, "hd_old"), token=tok)  # unpaid via the legacy route
    return st == 200 and "report_id" in r
