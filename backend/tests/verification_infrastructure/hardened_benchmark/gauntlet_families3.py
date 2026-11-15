#!/usr/bin/env python3
"""Widened held-out gauntlet, round 3 -- BOLA/IDOR, metering, and a forge/replay boundary.

  * idor   -- a paid activation ref belonging to ANOTHER tenant is LEAKED in a directory response; the sink
              activates the caller from it with no ownership check (BOLA). Honest: solvable only when the ref
              is observably leaked; the unsolvable variant never leaks it (would require enumeration/guessing,
              which the safety contract forbids) -> correct 0.
  * quota  -- a metering balance is conflated with settlement: topping up the (free) metering balance is
              accepted as if it paid for the plan.
  * replay -- the paid path is a provider webhook signed with a SERVER secret. Forging/replaying it would grant
              with no payment, but it requires the secret the black-box client can never observe -> the engine
              CORRECTLY does not confirm it. Honest boundary (0), like the race family.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families3.py
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
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
OPS = ["activate", "redeem", "apply_x", "bind_y", "settle_z", "topup", "credit_bal"]
SINKS = ["finalize", "seal", "commit_w", "apply_q"]
FIELDS = ["ref_one", "paid_ref", "proof_a", "cover_y", "voucher_z", "bal_token"]


def gen_spec(seed: int, kind: str, family: str) -> dict[str, Any]:
    rng = random.Random(seed * 17 + hash(family) % 991)
    return {
        "seed": seed, "kind": kind, "family": family,
        "op": rng.choice(OPS), "sink": rng.choice(SINKS), "cov": rng.choice(FIELDS), "hidden": rng.choice(FIELDS),
        "discloses_all": kind != "unsolvable", "has_bug": kind != "clean",
    }


class FamilyTarget3:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs, self.pays = {}, {}, {}
        self._wsecret = uuid.uuid4().hex.encode()
        self.seed_ref = f"act_{uuid.uuid4().hex[:10]}"   # a paid activation ref belonging to a seeded OTHER tenant
        self.paid_refs = {self.seed_ref}
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))

        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"tier": None, "balance": 0.0, "own_refs": set()}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}

        if s["family"] == "replay" and method == "POST" and p == f"{PFX}/webhooks/pay":
            # provider webhook signed with a SERVER secret; grants with no captured payment (the vuln) --
            # but only a holder of the secret can produce a valid signature.
            sig = headers.get("webhook-signature", "")
            good = "v1," + base64.b64encode(hmac.new(self._wsecret, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).digest()).decode()
            if not (sig and hmac.compare_digest(sig, good)):
                return 401, {"error": "bad_signature"}, {}
            org = self.orgs.get(body.get("org", ""))
            if org is not None and s["has_bug"]:
                org["tier"] = "top"
            return 200, {"status": "processed"}, {}

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

        # ---- idor ----
        if s["family"] == "idor":
            if method == "GET" and p == f"{PFX}/directory":
                items = [{"paid_ref": self.seed_ref}] if s["discloses_all"] else []   # unsolvable: nothing leaked
                return 200, {"items": items}, {}
            if method == "POST" and p == f"{PFX}/{s['sink']}":
                ref = body.get(s["cov"])
                if ref is None:
                    return 422, {"error": "missing_field", "field": s["cov"]}, {}
                if ref not in self.paid_refs and ref not in org["own_refs"]:
                    return 403, {"error": "unknown_ref"}, {}
                if s["has_bug"]:
                    org["tier"] = "top"; return 200, {"status": "active"}, {}        # BOLA: no ownership check
                if ref in org["own_refs"]:
                    org["tier"] = "top"; return 200, {"status": "active"}, {}         # clean: only your OWN ref works
                return 403, {"error": "not_your_ref"}, {}

        # ---- quota (metering balance conflated with settlement) ----
        if s["family"] == "quota":
            if method == "POST" and p == f"{PFX}/{s['op']}":
                if not s["discloses_all"] and body.get(s["hidden"]) is None:
                    return 402, {"error": "needs_reference"}, {}   # unsolvable: required input never named
                org["balance"] += 1000.0
                return 201, {"balance": org["balance"]}, {}
            if method == "POST" and p == f"{PFX}/{s['sink']}":
                if s["has_bug"] and org["balance"] >= 900.0:
                    org["tier"] = "top"; return 200, {"status": "active"}, {}         # BUG: metering balance == payment
                return 402, {"error": "insufficient"}, {}                            # clean: balance is not settlement

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
    if s["family"] == "idor":
        surface["directory"] = {"method": "GET", "path": f"{PFX}/directory", "observed_via": "authorized_browser_trace"}
    if s["family"] == "quota":
        surface["topup"] = {"method": "POST", "path": f"{PFX}/{s['op']}", "observed_via": "authorized_browser_trace"}
    if s["family"] == "replay":
        surface["settle_webhook"] = {"method": "POST", "path": f"{PFX}/webhooks/pay", "observed_via": "public_api_reference"}
    return {
        "authorization_ref": "BENCH-FAM3", "authorized_by": "qa", "environment": "benchmark",
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
    target = FamilyTarget3(spec)
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
    t = FamilyTarget3(spec); s = spec

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        st, r, extra = await t.handle(method, path, body or {}, h)
        return st, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]; oid = who["tenant_id"]
    if s["family"] == "idor":
        await c("GET", f"{PFX}/directory", tok)                       # ref is leaked here (or knowable to a seeded insider)
        await c("POST", f"{PFX}/{s['sink']}", tok, {s["cov"]: t.seed_ref})
    elif s["family"] == "quota":
        await c("POST", f"{PFX}/{s['op']}", tok, {s["hidden"]: "x"})
        await c("POST", f"{PFX}/{s['sink']}", tok)
    elif s["family"] == "replay":
        payload = {"org": oid, "event": "paid"}
        sig = "v1," + base64.b64encode(hmac.new(t._wsecret, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).digest()).decode()
        await c("POST", f"{PFX}/webhooks/pay", None, payload, {"webhook-signature": sig})
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
            if not (truth and conf): print(f"    {family} SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf: print(f"    {family} UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf: print(f"    {family} CLEAN FP seed={spec['seed']}")
    print(f"  {family:11s}: solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")


async def main() -> int:
    print("== widened held-out gauntlet round 3 (BOLA/IDOR, metering, forge/replay boundary) ==")
    await measure("idor", 80000)
    await measure("quota", 90000)
    print("  -- replay family (honest boundary: needs the server webhook secret; engine must NOT confirm) --")
    truth = conf = 0
    for i in range(4):
        sp = gen_spec(95000 + i, "solvable", "replay")
        t = await truth_has_bypass(sp); c = await engine_confirms(sp)
        truth += int(t); conf += int(c)
    print(f"  replay     : truth-exists {truth}/4   engine-confirmed {conf}/4 (must be 0 -- cannot forge a server-secret signature)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
