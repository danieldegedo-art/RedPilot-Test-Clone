#!/usr/bin/env python3
"""Widened held-out gauntlet -- SEEDED generators for ADDITIONAL flaw families the planner never saw,
each randomized independently of the engine. Families:

  * multifield -- the sink requires TWO server-named references (revealed one at a time); tests the
                  iterative multi-field learner.
  * route      -- the sink lives on an OPAQUE route segment disclosed only in GET /config; tests
                  recon-driven route discovery (reverse engineering the endpoint).

Each family emits solvable / unsolvable / clean instances:
  * solvable   -- every required input is discoverable (field names disclosed; segment in config)  -> should DETECT
  * unsolvable -- one required input is NEVER disclosed (second field name hidden; segment absent) -> MUST stay 0 (honest gap)
  * clean      -- no bug (valid inputs still rejected)                                              -> MUST be 0 false positives

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families.py
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

OPA = ["issue_a", "grantlet", "mint_x", "stub_a", "coupon_a"]
OPB = ["issue_b", "token_b", "mint_y", "stub_b", "coupon_b"]
SINK = ["apply_x", "seal_y", "redeem_z", "finalize_q", "commit_w"]
FIELDS = ["ref_one", "ref_two", "proof_a", "proof_b", "handle_x", "cover_y", "voucher_z", "basis_k"]
SEGKEYS = ["gateway", "segment", "shard", "lane"]
PFX = "/svc"


def gen_spec(seed: int, kind: str, family: str) -> dict[str, Any]:
    rng = random.Random(seed * 7 + hash(family) % 1000)
    f1, f2 = rng.sample(FIELDS, 2)
    return {
        "seed": seed, "kind": kind, "family": family,
        "opA": rng.choice(OPA), "opB": rng.choice(OPB), "sink": rng.choice(SINK),
        "cov1": f1, "cov2": f2, "segkey": rng.choice(SEGKEYS),
        "fA": "a_" + rng.choice(FIELDS), "fB": "b_" + rng.choice(FIELDS),
        "seg": f"rt-{uuid.uuid4().hex[:6]}",
        "discloses_all": kind != "unsolvable",
        "has_bug": kind != "clean",
    }


class FamilyTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs, self.pays = {}, {}, {}
        self.a, self.b = {}, {}
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p))
        self.request_headers_seen.append(dict(headers))

        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"tier": None}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            cfg = {"service": "fam", "api_versions": ["v1", "v2"]}
            if s["family"] == "route" and s["discloses_all"]:
                cfg["endpoints"] = {"settle": {s["segkey"]: s["seg"]}}   # opaque route segment, disclosed only here
            return 200, cfg, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]

        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("basic", "top"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"
            self.pays[pid] = {"org": oid, "plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            pay = self.pays.get(p.split("/")[-2])
            if pay is None or pay["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True
                if org["tier"] != "top":
                    org["tier"] = pay["plan"]      # legit paid path
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = self.pays.get(q.get("payment_id", ""))
            if pay is None or pay["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "ok" if pay["captured"] else "pending"}, {}

        # producers
        if method == "POST" and p == f"{PFX}/{s['opA']}":
            i = f"A_{uuid.uuid4().hex[:8]}"; self.a[i] = oid
            return 201, {s["fA"]: i, "worth": 5.0}, {}
        if method == "POST" and p == f"{PFX}/{s['opB']}":
            i = f"B_{uuid.uuid4().hex[:8]}"; self.b[i] = oid
            return 201, {s["fB"]: i, "worth": 5.0}, {}

        # sink path: fixed for multifield, opaque-segment for route
        sink_here = (p == f"{PFX}/{s['sink']}") if s["family"] == "multifield" else (p == f"{PFX}/{s['seg']}/{s['sink']}")
        if method == "POST" and sink_here:
            c1 = body.get(s["cov1"])
            if c1 is None or self.a.get(c1) != oid:
                return (422, {"error": "missing_field", "field": s["cov1"]}, {}) if True else (402, {}, {})
            if s["family"] == "multifield":
                c2 = body.get(s["cov2"])
                if c2 is None or self.b.get(c2) != oid:
                    if s["discloses_all"]:
                        return 422, {"error": "missing_field", "field": s["cov2"]}, {}
                    return 402, {"error": "coverage_required"}, {}   # second field never named -> undiscoverable
            if s["has_bug"]:
                org["tier"] = "top"
                return 200, {"status": "active"}, {}
            return 402, {"error": "insufficient"}, {}               # clean: valid inputs still rejected

        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if org["tier"] in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["tier"] = None
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    surface = {
        "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
        "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
        "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
        "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
        "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
        "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
        "prod_a": {"method": "POST", "path": f"{PFX}/{s['opA']}", "observed_via": "authorized_browser_trace"},
        "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
        "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
    }
    if s["family"] == "multifield":
        surface["prod_b"] = {"method": "POST", "path": f"{PFX}/{s['opB']}", "observed_via": "authorized_browser_trace"}
        surface["apply_sink"] = {"method": "POST", "path": f"{PFX}/{s['sink']}", "observed_via": "authorized_browser_trace"}
    else:  # route
        surface["apply_sink"] = {"method": "POST", "path": f"{PFX}/{{{s['segkey']}}}/{s['sink']}", "observed_via": "public_api_reference"}
    return {
        "authorization_ref": "BENCH-FAM", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": surface,
        "plans": {"basic": {"prices": {"USD": 9.0}}, "top": {"prices": {"USD": 900.0}}},
        "features": {"use_feature": {"method": "GET", "path": f"{PFX}/use", "proof_field": "ok_id", "requires_plan": "basic", "observed_via": "product_ui"}},
        "declared_paid_features": ["use_feature"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def _start(spec):
    target = FamilyTarget(spec)
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on(reader, writer):
        t = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(t); t.add_done_callback(tracked.tasks.discard)

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
        writer.write(head.encode("utf-8") + payload); await writer.drain()
    finally:
        writer.close()


async def truth_has_bypass(spec) -> bool:
    if not spec["has_bug"]:
        return False
    t = FamilyTarget(spec); s = spec

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, _ = await t.handle(method, path, body or {}, h)
        return st, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, ra = await c("POST", f"{PFX}/{s['opA']}", tok); ida = ra[s["fA"]]
    seg = s["seg"]
    if s["family"] == "multifield":
        _s, rb = await c("POST", f"{PFX}/{s['opB']}", tok); idb = rb[s["fB"]]
        await c("POST", f"{PFX}/{s['sink']}", tok, {s["cov1"]: ida, s["cov2"]: idb})
    else:
        await c("POST", f"{PFX}/{seg}/{s['sink']}", tok, {s["cov1"]: ida})
    st, r = await c("GET", f"{PFX}/use", tok)
    return st == 200 and "ok_id" in r


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


async def measure(family, base_seed, n_solv=6):
    specs = [gen_spec(base_seed + i, "solvable", family) for i in range(n_solv)]
    specs += [gen_spec(base_seed + 100 + i, "unsolvable", family) for i in range(2)]
    specs += [gen_spec(base_seed + 200 + i, "clean", family) for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf): print(f"    {family} SOL MISS seed={spec['seed']} cov1={spec['cov1']} cov2={spec['cov2']}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf: print(f"    {family} UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf: print(f"    {family} CLEAN FP seed={spec['seed']}")
    print(f"  {family:11s}: solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return st, sn, uh, un, cf, cn


async def main() -> int:
    print("== widened held-out gauntlet (NEW families, fresh seeds) ==")
    await measure("multifield", 30000)
    await measure("route", 40000)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
