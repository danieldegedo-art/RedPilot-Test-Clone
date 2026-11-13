"""Meridian (fictional) -- an extreme, architecturally-realistic enterprise billing target.

Realistic stack: payment-intents + confirm + return for ordinary purchase; a separate
subscription-SCHEDULE + SETTLE path used by the self-serve plan-change flow; promotional
CREDITS; an async entitlement activate endpoint gated by a webhook signature; estimate /
preview read-only forecasts. Ownership, eligibility and signatures are all genuinely
enforced. Legit purchase works; every 1- and 2-step trick a tester usually tries is gated.

The ONLY paywall bypass is a depth-3 chain with an ESSENTIAL, NON-OBVIOUS ordering:

  recon : GET /v3/catalog       -> learn the enterprise price_id (pro is the decoy "recommended")
          GET /v3/orgs/current  -> learn your billing_account_id
  P2    : POST /v3/subscription/schedule {price_id=enterprise}      -> a pending change (seq = s), no entitlement
  P1    : POST /v3/billing/credits/grant                            -> a tiny promo credit (seq = c)
  P3    : POST /v3/subscription/schedule/{id}/settle {credit_id, billing_account_id}
          -> BUG: settle activates the schedule if an owned credit is attached AND credit.seq > schedule.seq
             (a freshness/anti-replay check the devs added) -- but it NEVER checks the credit covers the price.

Ordering is essential and non-obvious: a credit minted BEFORE the schedule (the natural
"mint-then-spend" order) is rejected `stale_credit`; you must schedule FIRST, then mint the
credit, then settle. A tester has to LEARN that freshness rule from the rejection and reverse
the order. Each primitive alone is harmless; the obvious orders all fail.

Decoys that mimic the real chain: estimate/preview (read-only), the signature-gated activate
endpoint (looks like the sink; black-box can't forge the signature -> genuinely BLOCKED, not
the bug), trial-on-enterprise (rejected, ineligible), settle without a credit (402), settle
with a stale credit (409).
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from reference_target import _read_http_request, _TrackedServer

CATALOG = [
    {"code": "basic", "price_id": "price_basic", "amount": 9.0},
    {"code": "pro", "price_id": "price_pro", "amount": 49.0, "recommended": True},
    {"code": "enterprise", "price_id": "price_ent", "amount": 999.0},
]
PRICE_TO_PLAN = {p["price_id"]: p["code"] for p in CATALOG}
PLAN_AMOUNT = {p["code"]: p["amount"] for p in CATALOG}
PLAN_RANK = {None: 0, "free": 0, "basic": 1, "pro": 2, "enterprise": 3}


class ExtremeTarget:
    INTERNAL_PREFIXES = ("/internal", "/admin", "/__benchmark__")

    def __init__(self) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.ba_to_org: dict[str, str] = {}
        self.payments: dict[str, dict[str, Any]] = {}
        self.credits: dict[str, dict[str, Any]] = {}
        self.schedules: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    async def handle(self, method, raw_path, body, headers):
        parsed = urlparse(raw_path)
        path = parsed.path
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        body = body or {}
        self.request_log.append((method, path))
        self.request_headers_seen.append(dict(headers))
        if any(path == p or path.startswith(p + "/") for p in self.INTERNAL_PREFIXES):
            self.internal_hits += 1
            return 404, {"error": "not_found"}, {}

        if method == "POST" and path == "/v3/accounts":
            oid, ba, tok = f"org_{uuid.uuid4().hex[:8]}", f"ba_{uuid.uuid4().hex[:10]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"plan": None, "billing_account_id": ba}
            self.ba_to_org[ba] = oid
            self.by_token[tok] = {"identity_id": f"usr_{uuid.uuid4().hex[:8]}", "org_id": oid}
            return 201, {"token": tok, "tenant_id": oid, "identity_id": self.by_token[tok]["identity_id"]}, {}
        if method == "GET" and path == "/v3/catalog":
            return 200, {"currency": "USD", "plans": CATALOG}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        org_id = ident["org_id"]
        org = self.orgs[org_id]

        if method == "GET" and path == "/v3/orgs/current":
            return 200, {"org_id": org_id, "billing_account_id": org["billing_account_id"], "seat_role": "owner", "region": "eu-1"}, {}
        if method == "GET" and path == "/v3/entitlements":
            return 200, {"grants": [{"plan": org["plan"] or "free", "source": "paid" if org["plan"] else "none", "state": "active" if org["plan"] else "none"}]}, {}

        if method == "POST" and path == "/v3/billing/checkout":
            code = body.get("plan") or PRICE_TO_PLAN.get(body.get("price_id", ""))
            if code not in PLAN_AMOUNT:
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pi_{uuid.uuid4().hex[:10]}"
            self.payments[pid] = {"org_id": org_id, "plan": code, "captured": False}
            return 201, {"payment_id": pid, "amount": PLAN_AMOUNT[code], "status": "requires_confirmation"}, {}
        if method == "POST" and path.startswith("/v3/billing/checkout/") and path.endswith("/confirm"):
            p = self.payments.get(path.split("/")[4])
            if p is None or p["org_id"] != org_id:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                p["captured"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and path == "/v3/billing/checkout/return":
            p = self.payments.get(q.get("payment_id", ""))
            if p is None or p["org_id"] != org_id:
                return 404, {"error": "unknown_payment"}, {}
            if p["captured"]:
                if PLAN_RANK[p["plan"]] >= PLAN_RANK[org["plan"]]:
                    org["plan"] = p["plan"]
                return 200, {"status": "ok"}, {}
            return 200, {"status": "payment_not_completed"}, {}

        if method == "POST" and path == "/v3/billing/credits/grant":
            cid = f"cr_{uuid.uuid4().hex[:10]}"
            self.credits[cid] = {"org_id": org_id, "amount": 5.0, "seq": self._next_seq()}
            return 201, {"credit_id": cid, "amount": 5.0, "kind": "promo"}, {}

        if method == "POST" and path == "/v3/subscription/schedule":
            code = PRICE_TO_PLAN.get(body.get("price_id", "")) or body.get("plan")
            if code not in PLAN_AMOUNT:
                return 400, {"error": "unknown_plan"}, {}
            if body.get("trial") and code != "basic":
                return 400, {"error": "plan_not_trial_eligible"}, {}
            sid = f"sch_{uuid.uuid4().hex[:10]}"
            self.schedules[sid] = {"org_id": org_id, "plan": code, "state": "awaiting_settlement", "seq": self._next_seq()}
            return 201, {"schedule_id": sid, "plan": code, "state": "awaiting_settlement"}, {}

        if method == "POST" and path.startswith("/v3/subscription/schedule/") and path.endswith("/settle"):
            sid = path.split("/")[4]
            sch = self.schedules.get(sid)
            if sch is None or sch["org_id"] != org_id:
                return 404, {"error": "unknown_schedule"}, {}
            ba = body.get("billing_account_id")
            if ba is not None and self.ba_to_org.get(ba) != org_id:
                return 403, {"error": "billing_account_not_yours"}, {}
            cid = body.get("credit_id")
            if cid is None:
                return 402, {"error": "payment_required"}, {}
            cr = self.credits.get(cid)
            if cr is None or cr["org_id"] != org_id:
                return 403, {"error": "credit_not_yours"}, {}
            if cr["seq"] <= sch["seq"]:
                return 409, {"error": "stale_credit", "hint": "the credit must be newer than the schedule it settles"}, {}
            # BUG: a fresher owned credit is accepted as settlement; the credit amount vs price is never checked.
            sch["state"] = "active"
            if PLAN_RANK[sch["plan"]] >= PLAN_RANK[org["plan"]]:
                org["plan"] = sch["plan"]
            return 200, {"status": "active", "plan": sch["plan"]}, {}

        if method == "POST" and path == "/v3/billing/estimate":
            return 200, {"estimate": PLAN_AMOUNT.get(PRICE_TO_PLAN.get(body.get("price_id", "")), 0.0)}, {}
        if method == "GET" and path == "/v3/subscription/preview":
            return 200, {"current": org["plan"] or "free", "note": "forecast only"}, {}
        if method == "POST" and path.startswith("/v3/entitlements/") and path.endswith("/activate"):
            if not body.get("webhook_signature"):   # genuinely gated: black-box cannot forge -> dead end, not the bug
                return 403, {"error": "signature_required"}, {}
            return 403, {"error": "invalid_signature"}, {}

        if method == "GET" and path == "/v3/account/subscription":
            return 200, {"plan": org["plan"] or "free", "status": "active" if org["plan"] else "inactive"}, {}
        if method == "POST" and path == "/v3/data/export":
            return (200, {"export_id": f"exp_{uuid.uuid4().hex[:8]}", "rows": 3}, {}) if PLAN_RANK[org["plan"]] >= 1 else (402, {"error": "payment_required"}, {})
        if method == "GET" and path == "/v3/data/enterprise-report":
            return (200, {"report_id": f"rep_{uuid.uuid4().hex[:8]}"}, {}) if org["plan"] == "enterprise" else (403, {"error": "upgrade_required"}, {})
        if method == "POST" and path == "/v3/account/refund":
            org["plan"] = None
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


async def _serve(target: ExtremeTarget, reader, writer) -> None:
    try:
        method, path, body, headers = await _read_http_request(reader)
        status, payload_obj, extra = await target.handle(method, path, body, headers)
    except Exception as exc:  # noqa: BLE001
        status, payload_obj, extra = 400, {"error": "bad_request", "detail": str(exc)}, {}
    payload = json.dumps(payload_obj).encode("utf-8")
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def start_extreme_target():
    target = ExtremeTarget()
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


def extreme_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-AUTH-EXTREME", "authorized_by": "qa-benchmark-owner", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": "/v3/accounts", "observed_via": "product_ui"},
            "orgs_self": {"method": "GET", "path": "/v3/orgs/current", "observed_via": "authorized_browser_trace"},
            "catalog": {"method": "GET", "path": "/v3/catalog", "observed_via": "authorized_browser_trace"},
            "entitlements": {"method": "GET", "path": "/v3/entitlements", "observed_via": "authorized_browser_trace"},
            "start_checkout": {"method": "POST", "path": "/v3/billing/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": "/v3/billing/checkout/{payment_id}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": "/v3/billing/checkout/return", "observed_via": "authorized_browser_trace"},
            "credits_grant": {"method": "POST", "path": "/v3/billing/credits/grant", "observed_via": "authorized_browser_trace"},
            "schedule_change": {"method": "POST", "path": "/v3/subscription/schedule", "observed_via": "authorized_browser_trace"},
            "settle_schedule": {"method": "POST", "path": "/v3/subscription/schedule/{schedule_id}/settle", "observed_via": "authorized_browser_trace"},
            "estimate": {"method": "POST", "path": "/v3/billing/estimate", "observed_via": "authorized_browser_trace"},
            "subscription_view": {"method": "GET", "path": "/v3/account/subscription", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": "/v3/account/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0}}, "pro": {"prices": {"USD": 49.0}}, "enterprise": {"prices": {"USD": 999.0}}},
        "features": {
            "data_export": {"method": "POST", "path": "/v3/data/export", "proof_field": "export_id", "requires_plan": "basic", "observed_via": "product_ui"},
            "enterprise_report": {"method": "GET", "path": "/v3/data/enterprise-report", "proof_field": "report_id", "requires_plan": "enterprise", "observed_via": "product_ui"},
        },
        "declared_paid_features": ["data_export", "enterprise_report"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 4, "timeout_seconds": 10},
    }


async def _c(t: ExtremeTarget, method, path, *, token=None, body=None):
    h = {"authorization": f"Bearer {token}"} if token else {}
    s, r, _ = await t.handle(method, path, body or {}, h)
    return s, r


async def probe_extreme_truth() -> dict[str, Any]:
    out: dict[str, Any] = {}
    t = ExtremeTarget()
    _s, who = await _c(t, "POST", "/v3/accounts"); tok = who["token"]
    s_e, _ = await _c(t, "GET", "/v3/data/enterprise-report", token=tok)
    out["unpaid_denied"] = s_e in (402, 403)

    # obvious order (credit BEFORE schedule) is rejected -> ordering is essential
    t = ExtremeTarget()
    _s, who = await _c(t, "POST", "/v3/accounts"); tok = who["token"]
    _s, cr = await _c(t, "POST", "/v3/billing/credits/grant", token=tok)
    _s, sch = await _c(t, "POST", "/v3/subscription/schedule", token=tok, body={"price_id": "price_ent"})
    s_settle, r_settle = await _c(t, "POST", f"/v3/subscription/schedule/{sch['schedule_id']}/settle", token=tok, body={"credit_id": cr["credit_id"]})
    out["obvious_order_rejected"] = s_settle == 409 and r_settle.get("error") == "stale_credit"

    # correct order: schedule FIRST, then credit (newer), then settle -> free enterprise
    t = ExtremeTarget()
    _s, who = await _c(t, "POST", "/v3/accounts"); tok = who["token"]
    _s, org = await _c(t, "GET", "/v3/orgs/current", token=tok)
    _s, cat = await _c(t, "GET", "/v3/catalog", token=tok)
    ent_price = next(p["price_id"] for p in cat["plans"] if p["code"] == "enterprise")
    _s, sch = await _c(t, "POST", "/v3/subscription/schedule", token=tok, body={"price_id": ent_price})
    _s, cr = await _c(t, "POST", "/v3/billing/credits/grant", token=tok)
    await _c(t, "POST", f"/v3/subscription/schedule/{sch['schedule_id']}/settle", token=tok,
             body={"credit_id": cr["credit_id"], "billing_account_id": org["billing_account_id"]})
    s_e, r_e = await _c(t, "GET", "/v3/data/enterprise-report", token=tok)
    out["correct_order_grants_enterprise"] = s_e == 200 and "report_id" in r_e

    out["bypass_present"] = bool(out["unpaid_denied"] and out["correct_order_grants_enterprise"])
    return out
