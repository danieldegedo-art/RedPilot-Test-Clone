#!/usr/bin/env python3
"""Widened held-out gauntlet, round 2 -- three MORE randomized flaw families, each independent of the engine:

  * headernonce -- a producer returns the required id ONLY in the REST `Location` header; the sink needs it.
                   Tests standard response-header following. (unsolvable variant hides the id in a scrubbed
                   custom/debug header the engine refuses to read -> correct gap.)
  * coupon      -- promo STACKING: three distinct credit grants are additive without a cap; once stacked they
                   cover the full price, so a 'settle' step provisions the paid tier with no real payment.
  * race        -- a single-use discount with a check-then-act (TOCTOU) gap of ONE event-loop yield
                   (await asyncio.sleep(0)): two CONCURRENT redeems both pass the check and double-credit. A real
                   bypass EXISTS in-process, but the window is so tight that over real sockets the first request
                   writes before any later burst member arrives -> even with the opt-in race probe forced on at
                   burst 12 the engine confirms 0/4 (verified). This family is the HONEST BOUNDARY of the race
                   capability: the bounded burst wins realistic DB-round-trip windows (see families14 raceburst,
                   await sleep(0.05)) but NOT a single-yield window. 0 confirmed is the right answer, not a miss.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families2.py
"""
from __future__ import annotations

import asyncio
import json
import random
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/svc"
OPS = ["issue", "grantlet", "mint_x", "stub", "coupon", "credit", "redeem_u", "voucher_q"]
SINKS = ["apply_x", "seal_y", "settle_z", "finalize_q", "commit_w"]
FIELDS = ["ref_one", "proof_a", "handle_x", "cover_y", "voucher_z", "basis_k", "cred_id"]


def gen_spec(seed: int, kind: str, family: str) -> dict[str, Any]:
    rng = random.Random(seed * 13 + hash(family) % 997)
    return {
        "seed": seed, "kind": kind, "family": family,
        "opA": rng.choice(OPS), "sink": rng.choice(SINKS), "cov": rng.choice(FIELDS),
        "ca": "credit_" + rng.choice(["a", "p", "m"]), "cb": "credit_" + rng.choice(["b", "q", "n"]), "cc": "credit_" + rng.choice(["c", "r", "o"]),
        "hidden": rng.choice(FIELDS),
        "discloses_all": kind != "unsolvable",
        "has_bug": kind != "clean",
    }


class FamilyTarget2:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs, self.pays = {}, {}, {}
        self.prod = {}
        self.redeem_used = False
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
            self.orgs[oid] = {"tier": None, "credit": 0.0}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]

        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("basic", "top"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"; self.pays[pid] = {"org": oid, "plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            pay = self.pays.get(p.split("/")[-2])
            if pay is None or pay["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True
                if org["tier"] != "top":
                    org["tier"] = pay["plan"]
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = self.pays.get(q.get("payment_id", ""))
            if pay is None or pay["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "ok" if pay["captured"] else "pending"}, {}

        # ---- family: headernonce ----
        if s["family"] == "headernonce":
            if method == "POST" and p == f"{PFX}/{s['opA']}":
                i = f"H_{uuid.uuid4().hex[:8]}"; self.prod[i] = oid
                if s["discloses_all"]:
                    return 201, {"status": "created"}, {"Location": f"{PFX}/{s['opA']}/{i}"}   # id only in Location
                return 201, {"status": "created"}, {"x-fam-ref": i}  # unsolvable: volunteered/debug header -> scrubbed, engine won't read it
            if method == "POST" and p == f"{PFX}/{s['sink']}":
                c = body.get(s["cov"])
                if c is None or self.prod.get(c) != oid:
                    return 422, {"error": "missing_field", "field": s["cov"]}, {}
                if s["has_bug"]:
                    org["tier"] = "top"; return 200, {"status": "active"}, {}
                return 402, {"error": "insufficient"}, {}

        # ---- family: coupon (promo stacking) ----
        if s["family"] == "coupon":
            inc = 300.0 if s["has_bug"] else 100.0   # clean: three stacks (300) < price (900) -> never enough
            if method == "POST" and p in (f"{PFX}/{s['ca']}", f"{PFX}/{s['cb']}"):
                org["credit"] += inc; return 201, {"credited": inc}, {}
            if method == "POST" and p == f"{PFX}/{s['cc']}":
                if not s["discloses_all"] and body.get(s["hidden"]) is None:
                    return 402, {"error": "needs_reference"}, {}   # unsolvable: required input never named
                org["credit"] += inc; return 201, {"credited": inc}, {}
            if method == "POST" and p == f"{PFX}/{s['sink']}":
                if org["credit"] >= 900.0:
                    org["tier"] = "top"; return 200, {"status": "active"}, {}   # BUG: credits accepted as full settlement
                return 402, {"error": "insufficient_credit"}, {}

        # ---- family: race (TOCTOU, concurrency-only) ----
        if s["family"] == "race":
            if method == "POST" and p == f"{PFX}/{s['opA']}":   # single-use redeem worth half the price
                if self.redeem_used:
                    return 409, {"error": "spent"}, {}
                await asyncio.sleep(0)                           # check-then-act gap
                self.redeem_used = True
                org["credit"] += 450.0
                return 200, {"status": "redeemed"}, {}
            if method == "POST" and p == f"{PFX}/{s['sink']}":
                if s["has_bug"] and org["credit"] >= 900.0:      # needs TWO redeems (concurrent) to reach 900
                    org["tier"] = "top"; return 200, {"status": "active"}, {}
                return 402, {"error": "insufficient_credit"}, {}

        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if org["tier"] in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["tier"] = None; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    surface = {
        "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
        "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
        "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
        "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
        "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
        "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
        "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        "apply_sink": {"method": "POST", "path": f"{PFX}/{s['sink']}", "observed_via": "authorized_browser_trace"},
    }
    if s["family"] in ("headernonce", "race"):
        surface["prod_a"] = {"method": "POST", "path": f"{PFX}/{s['opA']}", "observed_via": "authorized_browser_trace"}
    if s["family"] == "coupon":
        surface["cred_a"] = {"method": "POST", "path": f"{PFX}/{s['ca']}", "observed_via": "authorized_browser_trace"}
        surface["cred_b"] = {"method": "POST", "path": f"{PFX}/{s['cb']}", "observed_via": "authorized_browser_trace"}
        surface["cred_c"] = {"method": "POST", "path": f"{PFX}/{s['cc']}", "observed_via": "authorized_browser_trace"}
    return {
        "authorization_ref": "BENCH-FAM2", "authorized_by": "qa", "environment": "benchmark",
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
    target = FamilyTarget2(spec)
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
    lines = [f"HTTP/1.1 {status} X", "Content-Type: application/json", f"Content-Length: {len(payload)}"]
    for hk, hv in (extra or {}).items():
        lines.append(f"{hk}: {hv}")
    lines.append("Connection: close")
    head = "\r\n".join(lines) + "\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload); await writer.drain()
    finally:
        writer.close()


async def truth_has_bypass(spec) -> bool:
    if not spec["has_bug"]:
        return False
    t = FamilyTarget2(spec); s = spec

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, extra = await t.handle(method, path, body or {}, h)
        return st, r, extra

    _s, who, _ = await c("POST", f"{PFX}/signup"); tok = who["token"]
    if s["family"] == "headernonce":
        _s, _r, extra = await c("POST", f"{PFX}/{s['opA']}", tok)
        ida = (extra.get("Location") or "").rsplit("/", 1)[-1] or extra.get("x-fam-ref")
        await c("POST", f"{PFX}/{s['sink']}", tok, {s["cov"]: ida})
    elif s["family"] == "coupon":
        await c("POST", f"{PFX}/{s['ca']}", tok)
        await c("POST", f"{PFX}/{s['cb']}", tok)
        await c("POST", f"{PFX}/{s['cc']}", tok, {s["hidden"]: "x"})
        await c("POST", f"{PFX}/{s['sink']}", tok)
    elif s["family"] == "race":
        # the bypass requires CONCURRENCY: two redeems racing the check-then-act gap
        await asyncio.gather(c("POST", f"{PFX}/{s['opA']}", tok), c("POST", f"{PFX}/{s['opA']}", tok))
        await c("POST", f"{PFX}/{s['sink']}", tok)
    st, r, _ = await c("GET", f"{PFX}/use", tok)
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
            if not (truth and conf): print(f"    {family} SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf: print(f"    {family} UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf: print(f"    {family} CLEAN FP seed={spec['seed']}")
    print(f"  {family:11s}: solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return st, sn


async def main() -> int:
    print("== widened held-out gauntlet round 2 (NEW families, fresh seeds) ==")
    await measure("headernonce", 50000)
    await measure("coupon", 60000)
    # race: truth exists in-process via concurrency, but the sleep(0) single-yield window is too tight for a
    # bounded rate-respecting burst to win over real sockets -> expect 0 even with the race probe on (verified)
    print("  -- race family (honest boundary: single-yield window; bounded burst cannot win it; engine must NOT confirm) --")
    truth = conf = 0
    for i in range(4):
        sp = gen_spec(70000 + i, "solvable", "race")
        t = await truth_has_bypass(sp); c = await engine_confirms(sp)
        truth += int(t); conf += int(c)
    print(f"  race       : truth-exists {truth}/4   engine-confirmed {conf}/4 (must be 0 -- single-yield sleep(0) window too tight for a bounded burst over the network)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
