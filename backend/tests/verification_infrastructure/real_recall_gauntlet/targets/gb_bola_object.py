"""GREY-BOX reconstruction: broken object-level authorization (cross-tenant object read).

Real source (independent, public fix):
  OpenWISP IPAM GHSA-x287-5c68-36wp -- "a member of one organization can export another
  organization's subnet and all its IP addresses." Corroborating: InvoiceShelf CVE-2026-55610
  (cross-tenant IDOR), stigmem-node GHSA-6gqw-jqv7-v88m (multi-tenant isolation bypass). Fix: add
  org/ownership validation at the data-access layer.

Grey-box confirmation (in RoE, no id guessing): the engine owns TWO of its own synthetic tenants.
Tenant B creates its own object and holds the reference. Tenant A then reads it with B's reference
(which the engine legitimately holds, because B is its own account). A differential -- A denied on
a control vs A allowed on B's object -- confirms forbidden cross-tenant access. flaw_on flips
exactly one check: the object read omits the ownership check.

Generalized critical class: forbidden cross-tenant object access (BOLA).
Pre-registered under today's engine: MISS (no cross-tenant object-read differential today).
"""
from __future__ import annotations

from _core import _id
from _hardened import HardenedCommerce, hardened_brief
from _probe import Client

FAMILY = "gb_bola_object"
PLANS = ("basic", "pro")
PRICES = {"basic": {"USD": 9.0}, "pro": {"USD": 99.0}}
_OBJ_ROUTES = ["objects", "resources", "records", "documents", "datasets"]


class Target(HardenedCommerce):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._objects: dict[str, dict] = {}

    def _glue_catalog(self):
        base = self.s.custom(_OBJ_ROUTES, "h_obj")
        return [{"method": "POST", "path": base, "fields": []},
                {"method": "GET", "path": base + "/{id}", "fields": []}]

    async def extra(self, method, path, body, ident, q):
        base = self.s.custom(_OBJ_ROUTES, "h_obj")
        tid = ident["tenant"]
        if method == "POST" and path == base:
            oid = _id("obj")
            self._objects[oid] = {"owner": tid, "data": _id("secret")}
            return 201, {"object_id": oid}
        if method == "GET" and path.startswith(base + "/"):
            oid = path[len(base) + 1:]
            o = self._objects.get(oid)
            if o is None:
                return 404, {"error": "not_found"}
            if self.flaw_on or o["owner"] == tid:  # BUG(flaw): no ownership check -> any tenant reads any object
                return 200, {"object_id": oid, "owner": o["owner"], "data": o["data"]}
            return 403, {"error": "forbidden"}
        return None


def make(scheme, flaw_on, path_log=None):
    return Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES, path_log=path_log)


def glue_ops(scheme):
    base = scheme.custom(_OBJ_ROUTES, "h_obj")
    return {"object_create": {"method": "POST", "path": base, "observed_via": "public_api_reference"},
            "object_read": {"method": "GET", "path": base + "/{object_id}", "observed_via": "public_api_reference"}}


def brief(base_url, scheme, declare_glue=True):
    return hardened_brief(base_url, scheme, plan_names=PLANS, prices=PRICES,
                          extra_ops=glue_ops(scheme) if declare_glue else None)


async def probe_truth(scheme, flaw_on):
    t = Target(scheme, flaw_on=flaw_on, plan_names=PLANS, prices=PRICES)
    c = Client(t)
    S = scheme
    base = S.custom(_OBJ_ROUTES, "h_obj")
    tok_a, _ = await c.signup()
    tok_b, _ = await c.signup()
    _s, rb = await c.call("POST", base, token=tok_b)        # B creates its OWN object
    b_oid = rb.get("object_id")
    _s2, ra = await c.call("POST", base, token=tok_a)        # A's own object (control baseline)
    a_oid = ra.get("object_id")
    st_own, _ = await c.call("GET", base + f"/{a_oid}", token=tok_a)   # A reads its own -> allowed
    st_x, _ = await c.call("GET", base + f"/{b_oid}", token=tok_a)     # A reads B's -> forbidden unless flaw
    return st_own == 200 and st_x == 200
