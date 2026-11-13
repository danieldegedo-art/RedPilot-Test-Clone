#!/usr/bin/env python3
"""Widened held-out gauntlet, round 4 -- the freshness-signed family (proves the DPoP/HTTP-sig-style
capability generalizes out-of-sample).

  * freshsig -- the sink requires a FRESH signature: a server-issued single-use nonce (handed back in the 422
                `challenge`) + a current timestamp + an HMAC over `nonce.ts.path` with the caller's key.
      - solvable:   the key is provisionable (POST /keys returns it) -> engine constructs the fresh signature.
      - unsolvable: the key is server-side only (never observable) -> engine cannot sign -> correct 0
                    (it must NOT guess a secret key).
      - clean:      no bug (valid signed request still rejected) -> 0 false positives.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families4.py
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import random
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/svc"
OPS = ["issue", "mint_x", "stub", "register"]
SINKS = ["apply_x", "seal_y", "settle_z", "commit_w"]
FIELDS = ["ref_one", "proof_a", "cover_y", "handle_x"]


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed * 19 + 7)
    return {"seed": seed, "kind": kind, "op": rng.choice(OPS), "sink": rng.choice(SINKS), "cov": rng.choice(FIELDS),
            "discloses_all": kind != "unsolvable", "has_bug": kind != "clean"}


class FreshSigTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs, self.pays, self.prod, self.keys, self.nonces = {}, {}, {}, {}, {}, {}
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _sig_gate(self, oid, p, body):
        live = self.nonces.setdefault(oid, {})
        nonce = body.get("nonce")
        if nonce is None or nonce not in live or live[nonce]:
            c = f"ch_{uuid.uuid4().hex[:12]}"; live[c] = False
            return 422, {"error": "missing_field", "field": "nonce", "challenge": c}, {}
        ts = body.get("ts")
        if ts is None:
            return 422, {"error": "missing_field", "field": "ts"}, {}
        try:
            tsi = int(ts)
        except (TypeError, ValueError):
            tsi = -10 ** 12
        if abs(int(time.time()) - tsi) > 300:
            return 422, {"error": "invalid_field", "field": "ts"}, {}
        sig = body.get("request_sig")
        if sig is None:
            return 422, {"error": "missing_field", "field": "request_sig"}, {}
        sk = self.keys.get(oid)
        expected = hmac.new((sk or "").encode(), f"{nonce}.{ts}.{p}".encode(), hashlib.sha256).hexdigest() if sk else None
        if not sk or not hmac.compare_digest(str(sig), expected):
            return 422, {"error": "invalid_field", "field": "request_sig"}, {}
        live[nonce] = True
        return None

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))

        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"tier": None}
            self.by_token[tok] = {"org": oid}
            self.keys[oid] = f"sk_{uuid.uuid4().hex}"   # per-tenant signing key (server-side)
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

        if method == "POST" and p == f"{PFX}/keys":
            if not s["discloses_all"]:
                return 403, {"error": "not_available"}, {}     # unsolvable: key never observable -> can't sign
            return 201, {"signing_key": self.keys[oid], "alg": "HMAC_SHA256_HEX"}, {}
        if method == "POST" and p == f"{PFX}/{s['op']}":
            i = f"R_{uuid.uuid4().hex[:8]}"; self.prod[i] = oid
            return 201, {s["cov"]: i}, {}
        if method == "POST" and p == f"{PFX}/{s['sink']}":
            ref = body.get(s["cov"])
            if ref is None or self.prod.get(ref) != oid:
                return 422, {"error": "missing_field", "field": s["cov"]}, {}
            gate = self._sig_gate(oid, p, body)
            if gate is not None:
                return gate
            if s["has_bug"]:
                org["tier"] = "top"; return 200, {"status": "active"}, {}
            return 402, {"error": "insufficient"}, {}

        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if org["tier"] in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["tier"] = None; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    return {
        "authorization_ref": "BENCH-FAM4", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "provision_key": {"method": "POST", "path": f"{PFX}/keys", "observed_via": "public_api_reference"},
            "prod_a": {"method": "POST", "path": f"{PFX}/{s['op']}", "observed_via": "authorized_browser_trace"},
            "apply_sink": {"method": "POST", "path": f"{PFX}/{s['sink']}", "observed_via": "public_api_reference"},
            "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0}}, "top": {"prices": {"USD": 900.0}}},
        "features": {"use_feature": {"method": "GET", "path": f"{PFX}/use", "proof_field": "ok_id", "requires_plan": "basic", "observed_via": "product_ui"}},
        "declared_paid_features": ["use_feature"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def _start(spec):
    target = FreshSigTarget(spec)
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
    t = FreshSigTarget(spec); s = spec

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, extra = await t.handle(method, path, body or {}, h)
        return st, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]; oid = who["tenant_id"]
    _s, pr = await c("POST", f"{PFX}/{s['op']}", tok); ref = pr[s["cov"]]
    sk = t.keys[oid]   # the prober has server-side access to the key (a real bypass exists regardless of observability)
    path = f"{PFX}/{s['sink']}"
    _s, chal = await c("POST", path, tok, {s["cov"]: ref})
    nonce = chal["challenge"]; ts = str(int(time.time()))
    sig = hmac.new(sk.encode(), f"{nonce}.{ts}.{path}".encode(), hashlib.sha256).hexdigest()
    await c("POST", path, tok, {s["cov"]: ref, "nonce": nonce, "ts": ts, "request_sig": sig})
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


async def main() -> int:
    print("== widened held-out gauntlet round 4 (freshness-signed family) ==")
    specs = [gen_spec(100000 + i, "solvable") for i in range(6)]
    specs += [gen_spec(100100 + i, "unsolvable") for i in range(2)]
    specs += [gen_spec(100200 + i, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf): print(f"    freshsig SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf: print(f"    freshsig UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf: print(f"    freshsig CLEAN FP seed={spec['seed']}")
    print(f"  freshsig   : solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
