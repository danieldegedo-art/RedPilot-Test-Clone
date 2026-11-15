"""Planner-BLIND target: the SAME logical flaw as the extreme target (a sink activates a
pending plan change when an attached resource is 'fresher', with no coverage check), but
deliberately authored to NOT match the planner's heuristics:

  * off-convention operation names: the stage/mint/sink verbs are 'cycle-entry' / 'perk' /
    'finalize' -- none of which match the planner's role regexes (no settle/activate/schedule/
    credit/voucher/grant/... keyword anywhere);
  * mismatched data-flow field names: the mint returns its handle as `perk_handle`, but the
    sink consumes it under a different name `coverage_ref`, so harvest-by-name cannot wire
    step 1 into step 2;
  * catalog uses `sku`/`fee` instead of `price_id`/`amount`, so the top-tier selector is not
    learnable by the current ranker.

The flaw is just as real (the truth prober drives it end to end). The point: a tool that
only ever sees targets its author tailored to it will score 1.0 and tell you nothing about
unknown flaws. This target is the honest control -- I expect the current engine to MISS it.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from reference_target import _read_http_request, _TrackedServer

TIERS = [
    {"code": "lite", "sku": "sku_lite", "fee": 9.0},
    {"code": "pro", "sku": "sku_pro", "fee": 49.0, "suggested": True},
    {"code": "max", "sku": "sku_max", "fee": 999.0},
]
SKU_TO_TIER = {t["sku"]: t["code"] for t in TIERS}
TIER_FEE = {t["code"]: t["fee"] for t in TIERS}
RANK = {None: 0, "free": 0, "lite": 1, "pro": 2, "max": 3}


class BlindTarget:
    def __init__(self) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.acct_to_org: dict[str, str] = {}
        self.payments: dict[str, dict[str, Any]] = {}
        self.perks: dict[str, dict[str, Any]] = {}
        self.entries: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

    def _seqn(self) -> int:
        self._seq += 1
        return self._seq

    async def handle(self, method, raw_path, body, headers):
        parsed = urlparse(raw_path)
        path, q = parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}
        body = body or {}
        self.request_log.append((method, path))
        self.request_headers_seen.append(dict(headers))
        if path.startswith(("/internal", "/admin", "/__benchmark__")):
            self.internal_hits += 1
            return 404, {"error": "not_found"}, {}

        if method == "POST" and path == "/api/signup":
            oid, acct, tok = f"o_{uuid.uuid4().hex[:8]}", f"acct_{uuid.uuid4().hex[:10]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"tier": None, "account_ref": acct}
            self.acct_to_org[acct] = oid
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and path == "/api/plans":
            return 200, {"tiers": TIERS}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]

        if method == "GET" and path == "/api/account":
            return 200, {"account_ref": org["account_ref"], "tier": org["tier"] or "free"}, {}
        if method == "GET" and path == "/api/me/plan":
            return 200, {"tier": org["tier"] or "free"}, {}

        if method == "POST" and path == "/api/billing/checkout":
            code = body.get("plan") or body.get("tier") or SKU_TO_TIER.get(body.get("sku", ""))
            if code not in TIER_FEE:
                return 400, {"error": "unknown_tier"}, {}
            pid = f"p_{uuid.uuid4().hex[:10]}"
            self.payments[pid] = {"org": oid, "tier": code, "captured": False}
            return 201, {"payment_id": pid, "fee": TIER_FEE[code], "status": "open"}, {}
        if method == "POST" and path.startswith("/api/billing/checkout/") and path.endswith("/capture"):
            p = self.payments.get(path.split("/")[4])
            if p is None or p["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                p["captured"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and path == "/api/billing/checkout/done":
            p = self.payments.get(q.get("payment_id", ""))
            if p is None or p["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if p["captured"] and RANK[p["tier"]] >= RANK[org["tier"]]:
                org["tier"] = p["tier"]
            return 200, {"status": "ok" if p["captured"] else "pending"}, {}

        # --- the three off-convention primitives ---
        if method == "POST" and path == "/api/billing/perk":                       # mint (named 'perk')
            h = f"pk_{uuid.uuid4().hex[:10]}"
            self.perks[h] = {"org": oid, "worth": 5.0, "seq": self._seqn()}
            return 201, {"perk_handle": h, "worth": 5.0}, {}                        # produced as 'perk_handle'
        if method == "POST" and path == "/api/billing/cycle-entry":                 # stage (named 'cycle-entry')
            code = SKU_TO_TIER.get(body.get("sku", "")) or body.get("tier")
            if code not in TIER_FEE:
                return 400, {"error": "unknown_tier"}, {}
            ref = f"ce_{uuid.uuid4().hex[:10]}"
            self.entries[ref] = {"org": oid, "tier": code, "seq": self._seqn()}
            return 201, {"entry_ref": ref, "tier": code, "phase": "open"}, {}
        if method == "POST" and path.startswith("/api/billing/cycle-entry/") and path.endswith("/finalize"):  # sink ('finalize')
            e = self.entries.get(path.split("/")[4])
            if e is None or e["org"] != oid:
                return 404, {"error": "unknown_entry"}, {}
            acct = body.get("account_ref")
            if acct is not None and self.acct_to_org.get(acct) != oid:
                return 403, {"error": "account_not_yours"}, {}
            cov = body.get("coverage_ref")                                          # consumed as 'coverage_ref' (NOT 'perk_handle')
            if cov is None:
                return 422, {"error": "missing_field", "field": "coverage_ref"}, {}  # realistic validation error: names the field (externally discoverable)
            pk = self.perks.get(cov)
            if pk is None or pk["org"] != oid:
                return 403, {"error": "coverage_not_yours"}, {}
            if pk["seq"] <= e["seq"]:
                return 409, {"error": "stale_coverage"}, {}
            # BUG: fresher owned coverage is accepted; worth vs fee is never checked.
            if RANK[e["tier"]] >= RANK[org["tier"]]:
                org["tier"] = e["tier"]
            return 200, {"status": "active", "tier": e["tier"]}, {}

        if method == "POST" and path == "/api/data/export":
            return (200, {"export_id": f"e_{uuid.uuid4().hex[:8]}"}, {}) if RANK[org["tier"]] >= 1 else (402, {"error": "payment_required"}, {})
        if method == "GET" and path == "/api/data/max-report":
            return (200, {"report_id": f"r_{uuid.uuid4().hex[:8]}"}, {}) if org["tier"] == "max" else (403, {"error": "upgrade_required"}, {})
        if method == "POST" and path == "/api/account/refund":
            org["tier"] = None
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


async def _serve(target, reader, writer) -> None:
    try:
        method, path, body, headers = await _read_http_request(reader)
        status, obj, extra = await target.handle(method, path, body, headers)
    except Exception as exc:  # noqa: BLE001
        status, obj, extra = 400, {"error": "bad_request", "detail": str(exc)}, {}
    payload = json.dumps(obj).encode("utf-8")
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def start_blind_target():
    target = BlindTarget()
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


def blind_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-AUTH-BLIND", "authorized_by": "qa-benchmark-owner", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": "/api/signup", "observed_via": "product_ui"},
            "account": {"method": "GET", "path": "/api/account", "observed_via": "authorized_browser_trace"},
            "plans": {"method": "GET", "path": "/api/plans", "observed_via": "authorized_browser_trace"},
            "start_checkout": {"method": "POST", "path": "/api/billing/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": "/api/billing/checkout/{payment_id}/capture", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": "/api/billing/checkout/done", "observed_via": "authorized_browser_trace"},
            "perk": {"method": "POST", "path": "/api/billing/perk", "observed_via": "authorized_browser_trace"},
            "cycle_entry": {"method": "POST", "path": "/api/billing/cycle-entry", "observed_via": "authorized_browser_trace"},
            "finalize": {"method": "POST", "path": "/api/billing/cycle-entry/{entry_ref}/finalize", "observed_via": "authorized_browser_trace"},
            "subscription_view": {"method": "GET", "path": "/api/me/plan", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": "/api/account/refund", "observed_via": "product_ui"},
        },
        "plans": {"lite": {"prices": {"USD": 9.0}}, "pro": {"prices": {"USD": 49.0}}, "max": {"prices": {"USD": 999.0}}},
        "features": {
            "data_export": {"method": "POST", "path": "/api/data/export", "proof_field": "export_id", "requires_plan": "lite", "observed_via": "product_ui"},
            "max_report": {"method": "GET", "path": "/api/data/max-report", "proof_field": "report_id", "requires_plan": "max", "observed_via": "product_ui"},
        },
        "declared_paid_features": ["data_export", "max_report"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 4, "timeout_seconds": 10},
    }


async def _c(t, method, path, *, token=None, body=None):
    h = {"authorization": f"Bearer {token}"} if token else {}
    s, r, _ = await t.handle(method, path, body or {}, h)
    return s, r


async def probe_blind_truth() -> dict[str, Any]:
    out: dict[str, Any] = {}
    t = BlindTarget()
    _s, who = await _c(t, "POST", "/api/signup"); tok = who["token"]
    s_m, _ = await _c(t, "GET", "/api/data/max-report", token=tok)
    out["unpaid_denied"] = s_m in (402, 403)

    t = BlindTarget()
    _s, who = await _c(t, "POST", "/api/signup"); tok = who["token"]
    _s, acct = await _c(t, "GET", "/api/account", token=tok)
    _s, plans = await _c(t, "GET", "/api/plans", token=tok)
    max_sku = next(x["sku"] for x in plans["tiers"] if x["code"] == "max")
    _s, entry = await _c(t, "POST", "/api/billing/cycle-entry", token=tok, body={"sku": max_sku})   # stage first
    _s, perk = await _c(t, "POST", "/api/billing/perk", token=tok)                                   # mint after (fresher)
    await _c(t, "POST", f"/api/billing/cycle-entry/{entry['entry_ref']}/finalize", token=tok,
             body={"coverage_ref": perk["perk_handle"], "account_ref": acct["account_ref"]})         # field-name remap
    s_m, r_m = await _c(t, "GET", "/api/data/max-report", token=tok)
    out["chain_grants_max"] = s_m == 200 and "report_id" in r_m
    out["bypass_present"] = bool(out["unpaid_denied"] and out["chain_grants_max"])
    return out
