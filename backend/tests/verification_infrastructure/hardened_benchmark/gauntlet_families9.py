#!/usr/bin/env python3
"""Widened held-out gauntlet, round 9 -- the ALGORITHM-CONFUSION family (proves the depth-12 'needle'
capability generalizes out-of-sample, and pins the boundary). Structurally unrelated to the Sentinel boss:
different prefix, op names, field names, and randomized per seed.

  * algconfusion -- an authorization endpoint grants the paid tier on a signature verified against the
    server's PUBLISHED authority PUBLIC key. The correct scheme is Ed25519 (unforgeable from outside). A
    legacy compat scheme HMAC-verifies using the raw bytes of that same published public key (RS->HS /
    scheme-downgrade; cf. Stripe "ignore all schemes that aren't v1 to prevent downgrade attacks").
      - solvable:   legacy scheme enabled AND the authorization over-grants -> engine forges via
                    alg-confusion (HMAC over the public key's raw bytes) -> detected.
      - unsolvable: legacy scheme DISABLED (ed25519 only) -> engine cannot forge -> correct 0.
      - clean:      legacy scheme enabled (sig forgeable) BUT a valid authorization does NOT over-grant
                    -> engine forges the sig, tier stays denied -> 0 false positives.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families9.py
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import random
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/svc"
KEY_FIELDS = ["authority_key", "settlement_pubkey", "verify_key", "jws_key"]   # all match /key/ for harvest
SIG_FIELDS = ["auth_sig", "settlement_signature", "grant_mac"]                  # all match /sig|mac/
HOOKS = ["authorize", "settle-grant", "confirm-tier"]


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed * 41 + 5)
    return {"seed": seed, "kind": kind, "key_field": rng.choice(KEY_FIELDS), "sig_field": rng.choice(SIG_FIELDS),
            "hook": rng.choice(HOOKS),
            "downgrade_enabled": kind != "unsolvable",   # the alg-confusion flaw present?
            "over_grants": kind != "clean"}              # does a valid authorization grant the tier?


class AlgConfusionTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self._priv = Ed25519PrivateKey.generate()
        self._raw = self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._pub_b64 = base64.b64encode(self._raw).decode()
        self.nonces: dict[str, dict[str, bool]] = {}
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
            self.orgs[oid] = {"basic": False, "top": False, "pays": {}}; self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            # Publishes the authority PUBLIC key (public -- normal) and documents the schemes.
            return 200, {"service": "ac", "grant_endpoint": f"{PFX}/{s['hook']}",
                         "scheme": "ed25519", "legacy_auth_scheme": "hs256",
                         "input": "nonce.ts.path", s["key_field"]: self._pub_b64}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]

        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("basic", "top"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"; org["pays"][pid] = {"plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            pay = org["pays"].get(p.split("/")[-2])
            if pay is None:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True
                org["basic" if pay["plan"] == "basic" else "top"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            if pay is None:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "ok" if pay["captured"] else "pending"}, {}

        if method == "POST" and p == f"{PFX}/{s['hook']}":
            live = self.nonces.setdefault(oid, {})
            nonce = body.get("nonce")
            if nonce is None or nonce not in live or live[nonce]:
                c = f"n_{uuid.uuid4().hex[:12]}"; live[c] = False
                return 422, {"error": "missing_field", "field": "nonce", "challenge": c}, {}
            ts = body.get("ts")
            if ts is None:
                return 422, {"error": "missing_field", "field": "ts"}, {}
            try:
                fresh = abs(int(time.time()) - int(ts)) <= 300
            except (TypeError, ValueError):
                fresh = False
            if not fresh:
                return 422, {"error": "invalid_field", "field": "ts"}, {}
            sig = body.get(s["sig_field"])
            if sig is None:
                return 422, {"error": "missing_field", "field": s["sig_field"]}, {}
            canonical = f"{nonce}.{ts}.{p}".encode()
            ok = False
            try:
                Ed25519PublicKey.from_public_bytes(self._raw).verify(base64.b64decode(str(sig)), canonical)
                ok = True
            except Exception:  # noqa: BLE001
                ok = False
            if not ok and s["downgrade_enabled"]:   # THE FLAW: HMAC with the public key's raw bytes
                want = hmac.new(self._raw, canonical, hashlib.sha256).hexdigest()
                if hmac.compare_digest(str(sig), want):
                    ok = True
            if not ok:
                return 422, {"error": "invalid_field", "field": s["sig_field"]}, {}
            live[nonce] = True
            if s["over_grants"]:
                org["top"] = True
                return 200, {"status": "granted", "tier": "top"}, {}
            return 200, {"status": "acknowledged"}, {}

        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    return {
        "authorization_ref": "BENCH-FAM9", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "grant_authorize": {"method": "POST", "path": f"{PFX}/{s['hook']}", "observed_via": "public_api_reference"},
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
    target = AlgConfusionTarget(spec)
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
    if not (spec["downgrade_enabled"] and spec["over_grants"]):
        return False
    t = AlgConfusionTarget(spec); s = spec

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, extra = await t.handle(method, path, body or {}, h)
        return st, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config", tok)
    raw = base64.b64decode(cfg[s["key_field"]])
    gpath = f"{PFX}/{s['hook']}"
    _s, ch = await c("POST", gpath, tok, {})
    nonce = ch["challenge"]; ts = str(int(time.time()))
    sig = hmac.new(raw, f"{nonce}.{ts}.{gpath}".encode(), hashlib.sha256).hexdigest()
    await c("POST", gpath, tok, {"nonce": nonce, "ts": ts, s["sig_field"]: sig})
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
    print("== widened held-out gauntlet round 9 (algorithm-confusion family) ==")
    specs = [gen_spec(150000 + i, "solvable") for i in range(6)]
    specs += [gen_spec(150100 + i, "unsolvable") for i in range(3)]
    specs += [gen_spec(150200 + i, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf):
                print(f"    algconfusion SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf:
                print(f"    algconfusion UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf:
                print(f"    algconfusion CLEAN FP seed={spec['seed']}")
    print(f"  algconfusion : solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
