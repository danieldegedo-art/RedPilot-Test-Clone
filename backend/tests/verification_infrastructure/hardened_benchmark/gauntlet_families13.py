#!/usr/bin/env python3
"""Widened held-out gauntlet, round 13 -- the MULTI-IDENTITY / BOLA family (proves the two-actor orchestration
capability generalizes out-of-sample, and pins the boundary). Grounded in OWASP API1 (BOLA) and the attached
IDOR doc: a true BOLA needs TWO actors -- a victim owns a paid resource, and the attacker references it without
an ownership check. A single-identity composer cannot do this; the capability provisions a victim, has it pay,
harvests the victim's paid resource ref, and redeems it as the (unpaid) attacker.

  * bola2 -- redeeming a PAID pass grants the tier. A correct server checks the pass belongs to the caller.
      - solvable:   no ownership check -> the attacker redeems the VICTIM's paid pass -> granted (attacker never paid).
      - unsolvable: ownership check -> the attacker's redemption of a foreign pass is refused (403) -> 0.
      - clean:      the foreign paid pass is accepted but grants nothing -> 0 false positives.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families13.py
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
PASS_OPS = ["passes", "entitlements", "tickets"]
REDEEM_OPS = ["redeem", "activate", "claim-pass"]


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed * 67 + 17)
    return {"seed": seed, "kind": kind, "pass_op": rng.choice(PASS_OPS), "redeem_op": rng.choice(REDEEM_OPS),
            "ownership_checked": kind == "unsolvable", "grants": kind != "clean"}


class BolaTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs, self.passes = {}, {}, {}
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _eff(self, org):
        return "top" if org["top"] else ("basic" if org["basic"] else None)

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"basic": False, "top": False, "paid": False, "pays": {}}; self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            return 200, {"service": "bola", "passes": f"{PFX}/{s['pass_op']}", "redeem": f"{PFX}/{s['redeem_op']}"}, {}
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]
        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("top",):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"; org["pays"][pid] = {"plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            pay = org["pays"].get(p.split("/")[-2])
            if pay is None:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True; org["paid"] = True; org["top"] = True   # legit payer gets the tier (positive control)
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            return (200, {"status": "ok" if pay["captured"] else "pending"}, {}) if pay else (404, {"error": "unknown_payment"}, {})
        if method == "POST" and p == f"{PFX}/{s['pass_op']}":
            # a pass is tied to its creator and is "paid" only if that identity actually paid
            ref = f"pass_{uuid.uuid4().hex[:10]}"; self.passes[ref] = {"org": oid, "paid": bool(org["paid"])}
            return 201, {"pass_ref": ref, "paid": bool(org["paid"])}, {}
        if method == "POST" and p == f"{PFX}/{s['redeem_op']}":
            ref = body.get("pass_ref")
            if ref is None:
                return 422, {"error": "missing_field", "field": "pass_ref"}, {}
            pr = self.passes.get(ref)
            if pr is None:
                return 422, {"error": "invalid_field", "field": "pass_ref"}, {}
            if not pr["paid"]:
                return 402, {"error": "pass_not_paid"}, {}
            if s["ownership_checked"] and pr["org"] != oid:
                return 403, {"error": "not_pass_owner"}, {}   # correct BOLA defense
            if s["grants"]:
                org["top"] = True
                return 200, {"status": "redeemed", "tier": "top"}, {}
            return 200, {"status": "acknowledged"}, {}
        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    return {
        "authorization_ref": "BENCH-FAM13", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "create_pass": {"method": "POST", "path": f"{PFX}/{s['pass_op']}", "observed_via": "public_api_reference"},
            "redeem_pass": {"method": "POST", "path": f"{PFX}/{s['redeem_op']}", "observed_via": "public_api_reference"},
            "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        },
        "plans": {"top": {"prices": {"USD": 900.0}}},
        "features": {"use_feature": {"method": "GET", "path": f"{PFX}/use", "proof_field": "ok_id", "requires_plan": "top", "observed_via": "product_ui"}},
        "declared_paid_features": ["use_feature"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def _start(spec):
    target = BolaTarget(spec)
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
    if spec["ownership_checked"] or not spec["grants"]:
        return False
    t = BolaTarget(spec); s = spec

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, _ = await t.handle(method, path, body or {}, h)
        return st, r
    # victim pays and mints a paid pass
    _s, vwho = await c("POST", f"{PFX}/signup"); vtok = vwho["token"]
    _s, co = await c("POST", f"{PFX}/checkout", vtok, {"plan": "top"}); pid = co["payment_id"]
    await c("POST", f"{PFX}/checkout/{pid}/confirm", vtok, {"outcome": "success"})
    _s, pr = await c("POST", f"{PFX}/{s['pass_op']}", vtok); vpass = pr["pass_ref"]
    # attacker (never pays) redeems the victim's pass
    _s, awho = await c("POST", f"{PFX}/signup"); atok = awho["token"]
    await c("POST", f"{PFX}/{s['redeem_op']}", atok, {"pass_ref": vpass})
    st, r = await c("GET", f"{PFX}/use", atok)
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


async def main() -> int:
    print("== widened held-out gauntlet round 13 (multi-identity / BOLA family) ==")
    specs = [gen_spec(200000 + i, "solvable") for i in range(6)]
    specs += [gen_spec(200100 + i, "unsolvable") for i in range(3)]
    specs += [gen_spec(200200 + i, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf):
                print(f"    bola2 SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf:
                print(f"    bola2 UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf:
                print(f"    bola2 CLEAN FP seed={spec['seed']}")
    print(f"  bola2      : solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
