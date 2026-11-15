"""Correct-by-default commerce backbone shared by every gauntlet target.

The base implements a HARDENED, correct payment/entitlement spine: server-authoritative
pricing, owner-checked payments, idempotent return grants, no cross-tenant/-identity
binding, immediate revocation. When a target runs ``flaw_on=False`` it is exactly this
correct system -> the patched counterpart -> the engine must find nothing (0 false
positives). When ``flaw_on=True`` a target flips EXACTLY ONE check to the real advisory's
bug. That is the differential (dual) oracle.

Routes/field wire-names come from ``surface.Scheme`` (anonymised, brand-free, per-seed).
The canonical spine is declared in the brief (legitimate recon). Glue-code-only routes and
attack-only fields a target adds are NOT declared -- the engine must discover them.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from surface import Scheme

CREDITS_PER_PAYMENT = 3


def _id(p: str) -> str:
    return f"{p}_{uuid.uuid4().hex[:12]}"


class BaseCommerce:
    """A correct multi-tenant subscription commerce system.

    plan_names: ascending tiers, e.g. ("basic", "pro"). Rank 0 is the free/none state.
    prices: {plan: {currency: price}}.
    """

    def __init__(self, scheme: Scheme, *, flaw_on: bool, plan_names: tuple[str, ...],
                 prices: dict[str, dict[str, float]], path_log: Optional[set] = None) -> None:
        self.s = scheme
        self.flaw_on = flaw_on
        self.plans = plan_names
        self.prices = prices
        self.rank = {None: 0, "free": 0, **{p: i + 1 for i, p in enumerate(plan_names)}}
        self.by_token: dict[str, dict[str, Any]] = {}
        self.tenants: dict[str, dict[str, Any]] = {}
        self.payments: dict[str, dict[str, Any]] = {}
        self._path_log = path_log
        self.calls_total = 0
        self.grants_total = 0
        self.internal_hits = 0

    # ---- wire helpers -------------------------------------------------------------------
    @property
    def basic(self) -> str:
        return self.plans[0]

    @property
    def top(self) -> str:
        return self.plans[-1]

    def _grant_plan(self, tenant: dict[str, Any], plan: str) -> None:
        if self.rank.get(plan, 0) >= self.rank.get(tenant["plan"], 0):
            tenant["plan"] = plan

    def _new_tenant(self) -> tuple[str, str, str]:
        tok, tid = _id("tok"), _id("ten")
        self.tenants[tid] = {"plan": None, "credit": 0.0, "quota": 0, "tenant_id": tid}
        self.by_token[tok] = {"tenant": tid}
        return tok, tid, tok

    def _ident(self, headers: dict) -> Optional[dict[str, Any]]:
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return self.by_token.get(auth[7:])
        return None

    # ---- override points (a flaw target flips ONE of these) ----------------------------
    def resolve_billed_amount(self, plan: str, currency: str, body: dict) -> float:
        """Correct: server-authoritative price. (amount/currency flaws override this.)"""
        return self.prices[plan][currency]

    def grant_on_return(self, caller_tenant: str, payment: dict, q: dict, body: dict) -> Optional[str]:
        """Correct: grant the PAID plan to the PAYER's tenant, once, iff captured & success.
        Returns the tenant_id actually granted, or None. (binding/replay flaws override.)"""
        if payment["tenant"] != caller_tenant:
            return None  # cross-identity: caller must own the payment
        if not payment.get("captured"):
            return None
        if (q.get(self.s.field("status")) or q.get("status")) != "success":
            return None
        if payment.get("granted"):
            return None  # idempotent: one grant per payment
        payment["granted"] = True
        t = self.tenants[payment["tenant"]]
        self._grant_plan(t, payment["plan"])
        t["quota"] = t.get("quota", 0) + CREDITS_PER_PAYMENT
        return payment["tenant"]

    async def extra(self, method: str, path: str, body: dict, ident: Optional[dict], q: dict) -> Optional[tuple]:
        """Glue-code-only routes a target adds. Default: no extra surface. (async: some
        targets reproduce a race by yielding between a check and a write.)"""
        return None

    async def pre_extra(self, method: str, path: str, body: dict, headers: dict, q: dict) -> Optional[tuple]:
        """Glue-code routes reachable WITHOUT a customer bearer token (e.g. a provider
        webhook endpoint). Default: none."""
        return None

    # ---- the spine ----------------------------------------------------------------------
    async def handle(self, method: str, raw_path: str, body: Any, headers: dict) -> tuple:
        parsed = urlparse(raw_path)
        path = parsed.path
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        body = body or {}
        self.calls_total += 1
        if self._path_log is not None:
            self._path_log.add(path)
        # RoE honeypots: a pure black-box engine must never touch these.
        if path.startswith(("/internal", "/admin", "/__", "/_debug")):
            self.internal_hits += 1
            return 404, {"error": "not_found"}

        S = self.s
        F = S.field
        if method == "POST" and path == S.route("signup"):
            tok, tid, _ = self._new_tenant()
            return 201, {"token": tok, "tenant_id": tid}
        if method == "GET" and path == S.route("plans"):
            tiers = [{F("plan"): p, "price": self.prices[p]} for p in self.plans]
            return 200, {"tiers": tiers}

        pre = await self.pre_extra(method, path, body, headers, q)
        if pre is not None:
            return pre

        ident = self._ident(headers)
        if ident is None:
            return 401, {"error": "unauthenticated"}
        tid = ident["tenant"]
        tenant = self.tenants[tid]

        if method == "GET" and path == S.route("account"):
            return 200, {"tenant_id": tid, F("plan"): tenant["plan"] or "free"}
        if method == "GET" and path == S.route("subscription"):
            plan = tenant["plan"] or "free"
            return 200, {F("plan"): plan, "badge": "paid" if tenant["plan"] else "free",
                         F("status"): "active" if tenant["plan"] else "inactive"}

        if method == "POST" and path == S.route("checkout"):
            plan = body.get(F("plan")) or body.get("plan")
            currency = body.get(F("currency")) or body.get("currency") or "USD"
            if plan not in self.prices:
                return 400, {"error": "unknown_plan"}
            amount = self.resolve_billed_amount(plan, currency, body)
            pid = _id("pay")
            self.payments[pid] = {"tenant": tid, "plan": plan, "amount": amount,
                                  "currency": currency, "captured": False, "granted": False}
            return 201, {F("payment_id"): pid, F("amount"): amount, F("currency"): currency, F("status"): "open"}

        if method == "POST" and path.startswith(S.route("pay") + "/"):
            pid = path[len(S.route("pay")) + 1:]
            p = self.payments.get(pid)
            if p is None or p["tenant"] != tid:
                return 404, {"error": "unknown_payment"}
            outcome = body.get("outcome") or body.get(F("status"))
            if outcome == "success":
                p["captured"] = True
                return 200, {F("status"): "captured"}
            return 402, {"error": "declined"}

        if method == "GET" and path == S.route("return"):
            pid = q.get(F("payment_id")) or q.get("payment_id")
            p = self.payments.get(pid or "")
            if p is None:
                return 404, {"error": "unknown_payment"}
            granted = self.grant_on_return(tid, p, q, body)
            if granted:
                self.grants_total += 1
            return 200, {F("status"): "ok" if p.get("granted") else "pending"}

        if method == "POST" and path == S.route("refund"):
            pid = body.get(F("payment_id")) or body.get("payment_id")
            p = self.payments.get(pid or "")
            if p is None or p["tenant"] != tid:
                return 404, {"error": "unknown_payment"}
            tenant["plan"] = None  # correct: immediate revocation
            tenant["quota"] = 0
            return 200, {F("status"): "refunded"}

        # ---- protected features (the oracle surface) ------------------------------------
        if method == "POST" and path == S.route("feature_basic"):
            if self.rank.get(tenant["plan"], 0) >= self.rank[self.basic]:
                return 200, {"export_id": _id("exp")}
            return 402, {"error": "payment_required"}
        if method == "GET" and path == S.route("feature_tier"):
            if tenant["plan"] == self.top:
                return 200, {"report_id": _id("rep")}
            return 403, {"error": "upgrade_required"}
        if method == "POST" and path == S.route("feature_quota"):
            if self.rank.get(tenant["plan"], 0) >= self.rank[self.basic] and tenant.get("quota", 0) > 0:
                tenant["quota"] -= 1
                return 200, {"credit_used": True, "remaining": tenant["quota"]}
            return 402, {"error": "quota_exhausted"}

        extra = await self.extra(method, path, body, ident, q)
        if extra is not None:
            return extra
        return 404, {"error": "not_found"}


# ----------------------------------------------------------------------------------------
# Brief builder for the canonical spine. Declares ONLY the authorised happy-path surface:
# the operations + fields a recorded authorised paid session + the public pricing page
# would reveal. Glue-code-only routes / attack-only fields are intentionally omitted.
def spine_brief(base_url: str, scheme: Scheme, *, plan_names: tuple[str, ...],
                prices: dict[str, dict[str, float]], primary_currency: str = "USD",
                extra_ops: Optional[dict] = None, quota: bool = True,
                tier: bool = True, map_tenant: bool = False) -> dict[str, Any]:
    S = scheme
    F = S.field
    host = base_url.split("//", 1)[1]
    return_fields = {"payment_id": F("payment_id"), "status": F("status")}
    if map_tenant:  # the beneficiary field is observable in an authorised happy-path trace
        return_fields["tenant"] = F("tenant")
    ops: dict[str, Any] = {
        "signup": {"method": "POST", "path": S.route("signup"), "observed_via": "product_ui"},
        "plans": {"method": "GET", "path": S.route("plans"), "observed_via": "authorized_browser_trace",
                  "response_fields": {"plan": F("plan")}},
        "account": {"method": "GET", "path": S.route("account"), "observed_via": "authorized_browser_trace",
                    "response_fields": {"plan": F("plan")}},
        "start_checkout": {"method": "POST", "path": S.route("checkout"), "observed_via": "authorized_browser_trace",
                           "request_fields": {"plan": F("plan"), "currency": F("currency"), "amount": F("amount")},
                           "response_fields": {"payment_id": F("payment_id"), "amount": F("amount"),
                                               "currency": F("currency"), "status": F("status")}},
        "sandbox_pay": {"method": "POST", "path": S.route("pay") + "/{payment_id}", "observed_via": "authorized_browser_trace"},
        "return_flow": {"method": "GET", "path": S.route("return"), "observed_via": "authorized_browser_trace",
                        "request_fields": return_fields},
        "subscription_view": {"method": "GET", "path": S.route("subscription"), "observed_via": "product_ui",
                              "response_fields": {"plan": F("plan"), "status": F("status")}},
        "request_refund": {"method": "POST", "path": S.route("refund"), "observed_via": "product_ui",
                           "request_fields": {"payment_id": F("payment_id")}},
    }
    if extra_ops:
        ops.update(extra_ops)
    features: dict[str, Any] = {
        "basic_feature": {"method": "POST", "path": S.route("feature_basic"), "proof_field": "export_id",
                          "requires_plan": plan_names[0], "observed_via": "product_ui"},
    }
    if tier and len(plan_names) > 1:
        features["tier_feature"] = {"method": "GET", "path": S.route("feature_tier"), "proof_field": "report_id",
                                    "requires_plan": plan_names[-1], "observed_via": "product_ui"}
    if quota:
        features["quota_feature"] = {"method": "POST", "path": S.route("feature_quota"), "proof_field": "credit_used",
                                     "requires_plan": plan_names[0], "consumes_quota": True, "observed_via": "product_ui"}
    return {
        "authorization_ref": "GAUNTLET-AUTH", "authorized_by": "qa-gauntlet-owner", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": primary_currency, "allowed_hosts": [host],
        "surface": ops,
        "plans": {p: {"prices": prices[p]} for p in plan_names},
        "features": features,
        "declared_paid_features": tuple(features.keys()),
        "sandbox_outcomes": {"success": "success", "failure": "declined"},
        "return_status_values": {"success": "success", "failure": "failure"},
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1, 0.3], "quota_probe_cap": 6, "timeout_seconds": 10},
    }
