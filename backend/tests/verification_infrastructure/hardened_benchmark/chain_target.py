"""A realistic enterprise billing target whose paywall bypass is CHAIN-ONLY.

The flaw is a real class: a checkout 'draft entitlement' can become ``bound`` two ways
-- by a captured payment (legitimate) or by associating it with a billing profile you
own (an invoicing convenience) -- and the provisioning endpoint trusts ``bound`` as
proof of payment without distinguishing the two. Every individual step is harmless:

  * GET  /api/v1/orgs/current                      -> your own org + opaque billing_profile_id   (recon)
  * POST /api/v1/checkout/intent                   -> an UNBOUND draft (provisioner ignores it)   (step 1)
  * POST /api/v1/checkout/intent/{id}/bind         -> binds the draft to a profile YOU own        (step 2)
  * POST/GET /api/v1/checkout/return               -> provisions IF draft.bound  (BUG: ignores bound_by/captured)

Only the sequence intent(enterprise) -> bind(own profile) -> return, with NO payment,
provisions free enterprise ("the system thinks it's paid"). Alone, each step grants
nothing. Legit flow (intent -> pay -> return) and the 1-step tricks the base engine
already tests (declined-then-return) are correctly gated, so the ONLY flaw here is the
chain -- which isolates the chaining capability under test.

Reuses CustomerLevelTarget for signup / subscription / features / refund so the
Protected-Feature Oracle works unchanged; overrides checkout/pay/return and adds the
recon + bind primitives.
"""
from __future__ import annotations

import asyncio
import copy
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from purity_benchmark.customer_target import PLAN_RANK, PRICES, CustomerLevelTarget, TargetFlags, _serve_connection
from purity_benchmark.lab import BASE_BRIEF
from reference_target import _TrackedServer


@dataclass
class _Draft:
    draft_id: str
    plan: str
    bound: bool = False
    bound_by: str | None = None  # "payment" | "profile"


@dataclass
class _Intent:
    intent_id: str
    tenant_id: str
    plan: str
    currency: str
    amount: float
    captured: bool = False
    draft: _Draft = field(default=None)  # type: ignore[assignment]


class ChainTarget(CustomerLevelTarget):
    def __init__(self) -> None:
        super().__init__(TargetFlags())
        self.orgs: dict[str, dict[str, Any]] = {}       # tenant_id -> {plan, billing_profile_id}
        self.bp_to_tenant: dict[str, str] = {}
        self.intents: dict[str, _Intent] = {}

    def _org(self, tenant_id: str) -> dict[str, Any]:
        if tenant_id not in self.orgs:
            bp = f"bp_{uuid.uuid4().hex[:12]}"
            self.orgs[tenant_id] = {"plan": None, "billing_profile_id": bp}
            self.bp_to_tenant[bp] = tenant_id
        return self.orgs[tenant_id]

    async def handle(self, method, raw_path, body, headers):
        parsed = urlparse(raw_path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        auth = headers.get("authorization", "")
        ident = self._by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None

        # signup: let the base create the identity, then make sure its org/billing profile exists
        if method == "POST" and path == "/api/v1/account/signup":
            status, resp, extra = await super().handle(method, raw_path, body, headers)
            if status == 201 and isinstance(resp, dict):
                self._org(resp["tenant_id"])  # billing_profile_id is NOT revealed here; recon must fetch /orgs/current
            return status, resp, extra

        if ident is not None:
            if method == "GET" and path == "/api/v1/orgs/current":
                self.request_log.append((method, path))
                org = self._org(ident.tenant_id)
                return 200, {"org_id": ident.tenant_id, "plan": org["plan"] or "free", "billing_profile_id": org["billing_profile_id"]}, {}

            if method == "POST" and path == "/api/v1/checkout":
                self.request_log.append((method, path))
                plan = (body or {}).get("plan")
                currency = (body or {}).get("currency") or "USD"
                if plan not in PRICES or currency not in PRICES[plan]:
                    return 400, {"error": "unknown_plan_or_currency"}, {}
                iid = f"pay_{uuid.uuid4().hex[:10]}"
                self.intents[iid] = _Intent(iid, ident.tenant_id, plan, currency, PRICES[plan][currency],
                                            draft=_Draft(f"draft_{uuid.uuid4().hex[:8]}", plan))
                return 201, {"payment_id": iid, "amount": PRICES[plan][currency], "currency": currency,
                             "status": "pending", "draft": {"draft_id": self.intents[iid].draft.draft_id, "plan": plan, "bound": False}}, {}

            if method == "POST" and path.startswith("/api/v1/checkout/") and path.endswith("/sandbox-pay"):
                self.request_log.append((method, path))
                iid = path.split("/")[4]
                it = self.intents.get(iid)
                if it is None or it.tenant_id != ident.tenant_id:
                    return 404, {"error": "unknown_payment"}, {}
                if (body or {}).get("outcome") == "success":
                    it.captured = True
                    it.draft.bound, it.draft.bound_by = True, "payment"
                    return 200, {"status": "captured"}, {}
                return 402, {"error": "card_declined"}, {}

            if method == "POST" and path.startswith("/api/v1/checkout/") and path.endswith("/bind"):
                self.request_log.append((method, path))
                iid = path.split("/")[4]
                it = self.intents.get(iid)
                if it is None or it.tenant_id != ident.tenant_id:
                    return 404, {"error": "unknown_intent"}, {}
                bp = (body or {}).get("billing_profile_id")
                if not bp or self.bp_to_tenant.get(bp) != ident.tenant_id:
                    return 403, {"error": "profile_not_yours"}, {}  # ownership IS checked -- harmless alone
                it.draft.bound, it.draft.bound_by = True, "profile"
                return 200, {"draft_id": it.draft.draft_id, "bound": True, "note": "associated with billing profile"}, {}

            if method == "GET" and path == "/api/v1/checkout/return":
                self.request_log.append((method, path))
                it = self.intents.get(query.get("payment_id", ""))
                if it is None or it.tenant_id != ident.tenant_id:
                    return 404, {"error": "unknown_payment"}, {}
                if it.draft.bound:  # BUG: 'bound' is trusted as proof of payment; bound_by/captured are never checked
                    org = self._org(ident.tenant_id)
                    if PLAN_RANK[it.draft.plan] >= PLAN_RANK.get(org["plan"], 0):
                        org["plan"] = it.draft.plan
                    self.entitlements[ident.tenant_id] = {"plan": org["plan"], "credits": 3}
                    return 200, {"status": "ok", "message": "Subscription active."}, {}
                return 200, {"status": "payment_not_completed"}, {}

        return await super().handle(method, raw_path, body, headers)


def chain_brief(base_url: str) -> dict[str, Any]:
    """BASE_BRIEF surface (same op vocabulary the engine uses) PLUS the two primitives a
    browser trace of checkout would reveal -- orgs_current and the bind step. The engine's
    fixed experiments never call these, which is exactly the chaining gap."""
    brief = copy.deepcopy(BASE_BRIEF)
    brief["allowed_hosts"] = [base_url.split("//", 1)[1]]
    brief["surface"]["orgs_current"] = {"method": "GET", "path": "/api/v1/orgs/current", "observed_via": "authorized_browser_trace"}
    brief["surface"]["bind_intent"] = {"method": "POST", "path": "/api/v1/checkout/{payment_id}/bind", "observed_via": "authorized_browser_trace"}
    return brief


async def start_chain_target():
    target = ChainTarget()
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


# ------------------------- independent truth: execute the chain in-process -------------------------
async def _call(t: ChainTarget, method, path, *, token=None, body=None):
    headers = {"authorization": f"Bearer {token}"} if token else {}
    s, r, _ = await t.handle(method, path, body or {}, headers)
    return s, r


async def probe_chain_truth() -> dict[str, Any]:
    """Returns the ground truth for the chain target, established purely by driving the
    public API: does the recon+chain bypass grant free enterprise, is each step harmless
    alone, and is the feature correctly gated for a normal unpaid identity?"""
    out: dict[str, Any] = {}

    # (a) legit gating: a fresh unpaid identity must be denied the feature
    t = ChainTarget()
    _s, who = await _call(t, "POST", "/api/v1/account/signup")
    tok = who["token"]
    s_exp, _ = await _call(t, "POST", "/api/v1/premium/export", token=tok)
    out["unpaid_denied"] = s_exp in (402, 403)

    # (b) each step alone is harmless
    t = ChainTarget()
    _s, who = await _call(t, "POST", "/api/v1/account/signup"); tok = who["token"]
    _s, intent = await _call(t, "POST", "/api/v1/checkout", token=tok, body={"plan": "enterprise", "currency": "USD"})
    _s, _ = await _call(t, "GET", "/api/v1/checkout/return?payment_id=" + intent["payment_id"], token=tok)  # intent+return, no bind/pay
    s1, _ = await _call(t, "GET", "/api/v1/premium/enterprise-report", token=tok)
    out["intent_then_return_harmless"] = s1 in (402, 403)

    # (c) the full chain: recon -> intent(enterprise) -> bind(own profile) -> return, NO payment
    t = ChainTarget()
    _s, who = await _call(t, "POST", "/api/v1/account/signup"); tok = who["token"]
    _s, org = await _call(t, "GET", "/api/v1/orgs/current", token=tok)
    bp = org["billing_profile_id"]
    _s, intent = await _call(t, "POST", "/api/v1/checkout", token=tok, body={"plan": "enterprise", "currency": "USD"})
    iid = intent["payment_id"]
    _s, _ = await _call(t, "POST", f"/api/v1/checkout/{iid}/bind", token=tok, body={"billing_profile_id": bp})
    _s, _ = await _call(t, "GET", "/api/v1/checkout/return?payment_id=" + iid, token=tok)
    s_ent, r_ent = await _call(t, "GET", "/api/v1/premium/enterprise-report", token=tok)
    out["chain_bypass_grants_enterprise"] = s_ent == 200 and "report_id" in r_ent

    out["bypass_present"] = bool(out["unpaid_denied"] and out["chain_bypass_grants_enterprise"])
    return out
