"""Northwind Cloud -- an ultra-realistic enterprise billing target.

No flag screams "flaw here". The surface looks like a real v2 billing API (catalog,
orgs, checkout+confirm+return, vouchers, subscription activate, estimate, refund,
features). Legitimate purchase works; the 1-step tricks a tester usually tries are all
correctly gated. The ONLY paywall bypass needs:

  recon  : GET /billing/catalog      -> learn the ENTERPRISE price_id (top of several plans; pro is a decoy "recommended")
           GET /orgs/self            -> learn your billing_account_id
  step 1 : POST /billing/vouchers/claim        -> a tiny loyalty voucher (credit_value 5.00)      [harmless: small credit]
  step 2 : POST /billing/subscription/activate {price_id, billing_account_id, voucher_id}
           -> BUG: treats ANY owned voucher as settled payment; never checks credit_value >= price.

Only claim->activate (two composed primitives) with the learned enterprise price_id grants
free enterprise. Alone each is harmless; partial chains are harmless (voucher alone = a
credit; activate without a voucher/payment = 402). Decoys that mimic a chain:
  * /billing/estimate looks like it could zero the price -> read-only dead end
  * activate with trial:true on enterprise -> rejected (enterprise is not trial-eligible)
  * activate with a voucher you do not own -> 403 (ownership IS checked)
  * a cosmetic 'preview_badge' in the subscription view
Ownership is genuinely enforced; the single real defect is the missing coverage check.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from reference_target import _read_http_request, _TrackedServer

CATALOG = [
    {"code": "basic", "price_id": "price_basic_9", "amount": 9.0},
    {"code": "pro", "price_id": "price_pro_49", "amount": 49.0, "recommended": True},   # decoy "recommended"
    {"code": "enterprise", "price_id": "price_ent_999", "amount": 999.0},
]
PRICE_TO_PLAN = {p["price_id"]: p["code"] for p in CATALOG}
PLAN_AMOUNT = {p["code"]: p["amount"] for p in CATALOG}
PLAN_RANK = {None: 0, "free": 0, "basic": 1, "pro": 2, "enterprise": 3}
TRIAL_ELIGIBLE = {"basic": True, "pro": False, "enterprise": False}


class UltraTarget:
    INTERNAL_PREFIXES = ("/internal", "/admin", "/__benchmark__")

    def __init__(self) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.ba_to_org: dict[str, str] = {}
        self.vouchers: dict[str, dict[str, Any]] = {}
        self.payments: dict[str, dict[str, Any]] = {}
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

    def _org(self, org_id: str) -> dict[str, Any]:
        return self.orgs[org_id]

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

        if method == "POST" and path == "/api/v2/account/signup":
            oid = f"org_{uuid.uuid4().hex[:8]}"
            ba = f"ba_{uuid.uuid4().hex[:10]}"
            tok = f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"plan": None, "billing_account_id": ba}
            self.ba_to_org[ba] = oid
            self.by_token[tok] = {"identity_id": f"usr_{uuid.uuid4().hex[:8]}", "org_id": oid}
            return 201, {"token": tok, "tenant_id": oid, "identity_id": self.by_token[tok]["identity_id"]}, {}

        if method == "GET" and path == "/api/v2/billing/catalog":
            return 200, {"currency": "USD", "plans": CATALOG}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        org_id = ident["org_id"]
        org = self._org(org_id)

        if method == "GET" and path == "/api/v2/orgs/self":
            return 200, {"org_id": org_id, "billing_account_id": org["billing_account_id"], "plan": org["plan"] or "free"}, {}

        if method == "POST" and path == "/api/v2/billing/checkout":
            code = body.get("plan") or PRICE_TO_PLAN.get(body.get("price_id", ""))
            if code not in PLAN_AMOUNT:
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:10]}"
            self.payments[pid] = {"org_id": org_id, "plan": code, "captured": False}
            return 201, {"payment_id": pid, "amount": PLAN_AMOUNT[code], "currency": body.get("currency") or "USD", "status": "pending"}, {}

        if method == "POST" and path.startswith("/api/v2/billing/checkout/") and path.endswith("/confirm"):
            pid = path.split("/")[5]
            p = self.payments.get(pid)
            if p is None or p["org_id"] != org_id:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                p["captured"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}

        if method == "GET" and path == "/api/v2/billing/checkout/return":
            p = self.payments.get(q.get("payment_id", ""))
            if p is None or p["org_id"] != org_id:
                return 404, {"error": "unknown_payment"}, {}
            if p["captured"]:  # legitimate: only a captured payment provisions here (status claim is ignored)
                if PLAN_RANK[p["plan"]] >= PLAN_RANK[org["plan"]]:
                    org["plan"] = p["plan"]
                return 200, {"status": "ok"}, {}
            return 200, {"status": "payment_not_completed"}, {}

        if method == "POST" and path == "/api/v2/billing/vouchers/claim":
            vid = f"vch_{uuid.uuid4().hex[:10]}"
            self.vouchers[vid] = {"org_id": org_id, "credit_value": 5.0}
            return 201, {"voucher_id": vid, "credit_value": 5.0, "kind": "loyalty"}, {}

        if method == "POST" and path == "/api/v2/billing/estimate":  # decoy: read-only
            code = PRICE_TO_PLAN.get(body.get("price_id", ""))
            return 200, {"estimate": PLAN_AMOUNT.get(code, 0.0), "discounted": False}, {}

        if method == "POST" and path == "/api/v2/billing/subscription/activate":
            code = PRICE_TO_PLAN.get(body.get("price_id", ""))
            if code is None:
                return 400, {"error": "unknown_price_id"}, {}
            if body.get("trial"):
                if not TRIAL_ELIGIBLE.get(code):
                    return 400, {"error": "plan_not_trial_eligible"}, {}
            ba = body.get("billing_account_id")
            if ba is not None and self.ba_to_org.get(ba) != org_id:
                return 403, {"error": "billing_account_not_yours"}, {}
            vid = body.get("voucher_id")
            voucher_ok = False
            if vid is not None:
                v = self.vouchers.get(vid)
                if v is None or v["org_id"] != org_id:
                    return 403, {"error": "voucher_not_yours"}, {}
                voucher_ok = True  # BUG: any owned voucher counts as settled; credit_value vs price is never checked
            paid = any(p["captured"] and p["plan"] == code for p in self.payments.values() if p["org_id"] == org_id)
            if voucher_ok or paid:
                if PLAN_RANK[code] >= PLAN_RANK[org["plan"]]:
                    org["plan"] = code
                return 200, {"status": "active", "plan": code}, {}
            return 402, {"error": "payment_required"}, {}

        if method == "GET" and path == "/api/v2/account/subscription":
            return 200, {"plan": org["plan"] or "free", "status": "active" if org["plan"] else "inactive", "ui_theme": "aurora"}, {}

        if method == "POST" and path == "/api/v2/data/export":
            return (200, {"export_id": f"exp_{uuid.uuid4().hex[:8]}", "rows": 3}, {}) if PLAN_RANK[org["plan"]] >= 1 else (402, {"error": "payment_required"}, {})

        if method == "GET" and path == "/api/v2/data/enterprise-report":
            return (200, {"report_id": f"rep_{uuid.uuid4().hex[:8]}"}, {}) if org["plan"] == "enterprise" else (403, {"error": "upgrade_required"}, {})

        if method == "POST" and path == "/api/v2/account/refund":
            org["plan"] = None  # a refund properly revokes the entitlement (so the ONLY defect here is the chain)
            return 200, {"status": "ok"}, {}

        return 404, {"error": "not_found"}, {}


async def _serve(target: UltraTarget, reader, writer) -> None:
    try:
        method, path, body, headers = await _read_http_request(reader)
        status, payload_obj, extra = await target.handle(method, path, body, headers)
    except Exception as exc:  # noqa: BLE001
        status, payload_obj, extra = 400, {"error": "bad_request", "detail": str(exc)}, {}
    payload = json.dumps(payload_obj).encode("utf-8")
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in extra.items()) + "\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def start_ultra_target():
    target = UltraTarget()
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


def ultra_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-AUTH-ULTRA", "authorized_by": "qa-benchmark-owner", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": "/api/v2/account/signup", "observed_via": "product_ui"},
            "orgs_self": {"method": "GET", "path": "/api/v2/orgs/self", "observed_via": "authorized_browser_trace"},
            "catalog": {"method": "GET", "path": "/api/v2/billing/catalog", "observed_via": "authorized_browser_trace"},
            "start_checkout": {"method": "POST", "path": "/api/v2/billing/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": "/api/v2/billing/checkout/{payment_id}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": "/api/v2/billing/checkout/return", "observed_via": "authorized_browser_trace"},
            "subscription_view": {"method": "GET", "path": "/api/v2/account/subscription", "observed_via": "product_ui"},
            "claim_voucher": {"method": "POST", "path": "/api/v2/billing/vouchers/claim", "observed_via": "authorized_browser_trace"},
            "estimate": {"method": "POST", "path": "/api/v2/billing/estimate", "observed_via": "authorized_browser_trace"},
            "activate": {"method": "POST", "path": "/api/v2/billing/subscription/activate", "observed_via": "authorized_browser_trace"},
            "request_refund": {"method": "POST", "path": "/api/v2/account/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0}}, "pro": {"prices": {"USD": 49.0}}, "enterprise": {"prices": {"USD": 999.0}}},
        "features": {
            "data_export": {"method": "POST", "path": "/api/v2/data/export", "proof_field": "export_id", "requires_plan": "basic", "observed_via": "product_ui"},
            "enterprise_report": {"method": "GET", "path": "/api/v2/data/enterprise-report", "proof_field": "report_id", "requires_plan": "enterprise", "observed_via": "product_ui"},
        },
        "declared_paid_features": ["data_export", "enterprise_report"],
        "limits": {"max_requests": 4000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 4, "timeout_seconds": 10},
    }


# ----------------------------- independent truth (drive the public API) -----------------------------
async def _c(t: UltraTarget, method, path, *, token=None, body=None):
    h = {"authorization": f"Bearer {token}"} if token else {}
    s, r, _ = await t.handle(method, path, body or {}, h)
    return s, r


async def probe_ultra_truth() -> dict[str, Any]:
    out: dict[str, Any] = {}
    # legit gating: fresh unpaid org denied
    t = UltraTarget()
    _s, who = await _c(t, "POST", "/api/v2/account/signup"); tok = who["token"]
    s_e, _ = await _c(t, "GET", "/api/v2/data/enterprise-report", token=tok)
    out["unpaid_denied"] = s_e in (402, 403)
    # voucher alone is harmless (no plan)
    t = UltraTarget()
    _s, who = await _c(t, "POST", "/api/v2/account/signup"); tok = who["token"]
    await _c(t, "POST", "/api/v2/billing/vouchers/claim", token=tok)
    s_e, _ = await _c(t, "GET", "/api/v2/data/enterprise-report", token=tok)
    out["voucher_alone_harmless"] = s_e in (402, 403)
    # activate without voucher/payment is harmless
    t = UltraTarget()
    _s, who = await _c(t, "POST", "/api/v2/account/signup"); tok = who["token"]
    await _c(t, "POST", "/api/v2/billing/subscription/activate", token=tok, body={"price_id": "price_ent_999"})
    s_e, _ = await _c(t, "GET", "/api/v2/data/enterprise-report", token=tok)
    out["activate_without_voucher_harmless"] = s_e in (402, 403)
    # the full chain: recon + claim + activate(enterprise, voucher) -> free enterprise
    t = UltraTarget()
    _s, who = await _c(t, "POST", "/api/v2/account/signup"); tok = who["token"]
    _s, org = await _c(t, "GET", "/api/v2/orgs/self", token=tok)
    _s, cat = await _c(t, "GET", "/api/v2/billing/catalog", token=tok)
    ent_price = next(p["price_id"] for p in cat["plans"] if p["code"] == "enterprise")
    _s, vch = await _c(t, "POST", "/api/v2/billing/vouchers/claim", token=tok)
    await _c(t, "POST", "/api/v2/billing/subscription/activate", token=tok,
             body={"price_id": ent_price, "billing_account_id": org["billing_account_id"], "voucher_id": vch["voucher_id"]})
    s_e, r_e = await _c(t, "GET", "/api/v2/data/enterprise-report", token=tok)
    out["chain_grants_enterprise"] = s_e == 200 and "report_id" in r_e
    out["bypass_present"] = bool(out["unpaid_denied"] and out["chain_grants_enterprise"])
    return out
