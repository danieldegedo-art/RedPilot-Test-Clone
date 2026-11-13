#!/usr/bin/env python3
"""Held-out gauntlet: a SEEDED generator of chain targets whose surface is randomized
independently of the planner (random op names, random required-field name, depth 2 or 3,
optional freshness/ordering constraint). The planner never saw these. Includes:
  * solvable instances  -> the required field name IS disclosed in the 422 error (discoverable)
  * unsolvable instances -> the field name is NEVER disclosed (undiscoverable -> honest BLOCKED/miss)
  * clean instances      -> no bug (false-positive control)

Honest expectation: high detection on solvable, ZERO on unsolvable (that is correct -- a bounded
black-box tool cannot invent an unobservable input), ZERO false positives on clean.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/generic_gauntlet.py [N]
"""
from __future__ import annotations

import asyncio
import json
import random
import sys
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

MINT_NAMES = ["perk", "bonus", "loyalty-token", "goodwill", "voucher", "promo-unit"]
STAGE_NAMES = ["cycle-entry", "draft-change", "hold", "basket", "stage-req", "reservation"]
SINK_NAMES = ["finalize", "lock-in", "apply-cover", "commit-cycle", "redeem-x", "seal"]
COV_FIELDS = ["coverage_ref", "voucher_id", "credit_id", "proof", "entitlement_ref", "cover_handle"]
MINT_IDFIELDS = ["handle", "ref", "token", "id", "grant_ref"]
PREFIXES = ["/api/v2", "/svc/billing", "/v4", "/api/commerce"]


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed)
    pfx = rng.choice(PREFIXES)
    use_stage = rng.random() < 0.6
    return {
        "seed": seed, "kind": kind, "prefix": pfx,
        "mint": rng.choice(MINT_NAMES), "stage": rng.choice(STAGE_NAMES), "sink": rng.choice(SINK_NAMES),
        "cov_field": rng.choice(COV_FIELDS), "mint_idfield": rng.choice(MINT_IDFIELDS),
        "use_stage": use_stage, "freshness": use_stage and rng.random() < 0.6,
        "discloses_field": kind != "unsolvable",
        "has_bug": kind != "clean",
    }


class GenericTarget:
    def __init__(self, spec: dict[str, Any]) -> None:
        self.s = spec
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.mints: dict[str, dict[str, Any]] = {}
        self.stages: dict[str, dict[str, Any]] = {}
        self.payments: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

    def _n(self) -> int:
        self._seq += 1
        return self._seq

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p))
        self.request_headers_seen.append(dict(headers))
        pfx = s["prefix"]

        if method == "POST" and p == f"{pfx}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"tier": None}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{pfx}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                    {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]

        if method == "POST" and p == f"{pfx}/checkout":
            code = body.get("plan")
            if code not in ("basic", "top"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"
            self.payments[pid] = {"org": oid, "plan": code, "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{pfx}/checkout/") and p.endswith("/confirm"):
            pay = self.payments.get(p.split("/")[-2])
            if pay is None or pay["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{pfx}/checkout/return":
            pay = self.payments.get(q.get("payment_id", ""))
            if pay is None or pay["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if pay["captured"] and (org["tier"] != "top"):
                org["tier"] = pay["plan"]
            return 200, {"status": "ok" if pay["captured"] else "pending"}, {}

        if method == "POST" and p == f"{pfx}/{s['mint']}":
            mid = f"m_{uuid.uuid4().hex[:8]}"
            self.mints[mid] = {"org": oid, "seq": self._n()}
            return 201, {s["mint_idfield"]: mid, "worth": 5.0}, {}
        if method == "POST" and p == f"{pfx}/{s['stage']}":
            sid = f"s_{uuid.uuid4().hex[:8]}"
            self.stages[sid] = {"org": oid, "seq": self._n()}
            return 201, {"stage_ref": sid, "phase": "open"}, {}
        # sink: path is .../{sink} or .../{sink}/{stage_ref}... we accept both forms
        if method == "POST" and p.startswith(f"{pfx}/{s['sink']}"):
            # resolve the stage (from path tail or body) if this spec uses a stage
            stage_ok = True
            stage_seq = 0
            if s["use_stage"]:
                sid = p.split("/")[-1] if p != f"{pfx}/{s['sink']}" else body.get("stage_ref")
                st = self.stages.get(sid or "")
                if st is None or st["org"] != oid:
                    return 404, {"error": "unknown_stage"}, {}
                stage_seq = st["seq"]
            cov = body.get(s["cov_field"])
            if cov is None:
                if s["discloses_field"]:
                    return 422, {"error": "missing_field", "field": s["cov_field"]}, {}
                return 402, {"error": "coverage_required"}, {}   # undiscoverable: never names the field
            mt = self.mints.get(cov)
            if mt is None or mt["org"] != oid:
                return 403, {"error": "coverage_not_yours"}, {}
            if s["freshness"] and mt["seq"] <= stage_seq:
                return 409, {"error": "stale_coverage"}, {}
            if s["has_bug"]:                                      # BUG: coverage accepted as settlement; worth vs price never checked
                org["tier"] = "top"
                return 200, {"status": "active", "tier": "top"}, {}
            return 402, {"error": "insufficient_coverage"}, {}    # clean variant: correctly rejects (worth < price)

        if method == "POST" and p == f"{pfx}/data/export":
            return (200, {"export_id": "e"}, {}) if org["tier"] in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "GET" and p == f"{pfx}/data/top":
            return (200, {"report_id": "r"}, {}) if org["tier"] == "top" else (403, {"error": "up"}, {})
        if method == "POST" and p == f"{pfx}/refund":
            org["tier"] = None
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec: dict[str, Any], base_url: str) -> dict[str, Any]:
    pfx = spec["prefix"]
    sink_path = f"{pfx}/{spec['sink']}/{{stage_ref}}" if spec["use_stage"] else f"{pfx}/{spec['sink']}"
    return {
        "authorization_ref": "BENCH-GAUNTLET", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{pfx}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{pfx}/catalog", "observed_via": "authorized_browser_trace"},
            "start_checkout": {"method": "POST", "path": f"{pfx}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{pfx}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{pfx}/checkout/return", "observed_via": "authorized_browser_trace"},
            "aux_mint": {"method": "POST", "path": f"{pfx}/{spec['mint']}", "observed_via": "authorized_browser_trace"},
            **({"aux_stage": {"method": "POST", "path": f"{pfx}/{spec['stage']}", "observed_via": "authorized_browser_trace"}} if spec["use_stage"] else {}),
            "aux_sink": {"method": "POST", "path": sink_path, "observed_via": "authorized_browser_trace"},
            "subscription_view": {"method": "GET", "path": f"{pfx}/data/top", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{pfx}/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0}}, "top": {"prices": {"USD": 900.0}}},
        "features": {
            "data_export": {"method": "POST", "path": f"{pfx}/data/export", "proof_field": "export_id", "requires_plan": "basic", "observed_via": "product_ui"},
            "top_report": {"method": "GET", "path": f"{pfx}/data/top", "proof_field": "report_id", "requires_plan": "top", "observed_via": "product_ui"},
        },
        "declared_paid_features": ["data_export", "top_report"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def _start(spec):
    target = GenericTarget(spec)
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on(reader, writer):
        t = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(t)
        t.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


async def _serve(target, reader, writer):
    try:
        method, path, body, headers = await _read_http_request(reader)
        status, obj, extra = await target.handle(method, path, body, headers)
    except Exception as exc:  # noqa: BLE001
        status, obj, extra = 400, {"error": "bad", "detail": str(exc)}, {}
    payload = json.dumps(obj).encode("utf-8")
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def truth_has_bypass(spec) -> bool:
    """Drive the intended solution in-process to confirm a real bypass exists (has_bug)."""
    if not spec["has_bug"]:
        return False
    t = GenericTarget(spec)
    pfx = spec["prefix"]

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, h)
        return s, r

    _s, who = await c("POST", f"{pfx}/signup"); tok = who["token"]
    sid = None
    if spec["use_stage"]:
        _s, st = await c("POST", f"{pfx}/{spec['stage']}", tok); sid = st["stage_ref"]
    _s, mn = await c("POST", f"{pfx}/{spec['mint']}", tok); mid = mn[spec["mint_idfield"]]
    sink_path = f"{pfx}/{spec['sink']}/{sid}" if spec["use_stage"] else f"{pfx}/{spec['sink']}"
    await c("POST", sink_path, tok, {spec["cov_field"]: mid})
    s_t, r_t = await c("GET", f"{pfx}/data/top", tok)
    return s_t == 200 and "report_id" in r_t


async def engine_confirms(spec) -> bool:
    target, server, port = await _start(spec)
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(brief_for(spec, base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests, max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0", max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True)
        result = await engine.run(None)
        return bool([f for f in result.findings if f.verdict.value == "CONFIRMED_P0"])
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()


async def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    specs = [gen_spec(1000 + i, "solvable") for i in range(n)]
    specs += [gen_spec(5000 + i, "unsolvable") for i in range(3)]
    specs += [gen_spec(8000 + i, "clean") for i in range(3)]

    sol_tp = sol_n = uns_hit = uns_n = clean_fp = clean_n = 0
    for spec in specs:
        truth = await truth_has_bypass(spec)
        conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sol_n += 1; sol_tp += int(truth and conf)
        elif spec["kind"] == "unsolvable":
            uns_n += 1; uns_hit += int(conf)
        else:
            clean_n += 1; clean_fp += int(conf)
        print(f"  {spec['kind']:10s} seed={spec['seed']} stage={spec['use_stage']!s:5s} fresh={spec['freshness']!s:5s} "
              f"sink={spec['sink']:12s} cov={spec['cov_field']:14s} truth={truth!s:5s} engine={'P0' if conf else '-'}", flush=True)

    print("\n== held-out gauntlet (targets the planner never saw) ==")
    print(f"  SOLVABLE detection (discoverable field): {sol_tp}/{sol_n}")
    print(f"  UNSOLVABLE (undiscoverable field) confirmed: {uns_hit}/{uns_n}  (MUST be 0 -- cannot invent an unobservable input)")
    print(f"  CLEAN false positives: {clean_fp}/{clean_n}  (MUST be 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
