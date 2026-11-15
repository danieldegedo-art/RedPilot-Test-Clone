#!/usr/bin/env python3
"""Widened held-out gauntlet, round 6 -- the signed-WEBHOOK family (proves the honest webhook-takedown
generalizes, and pins the boundary).

  * whsig -- a provider webhook grants the paid tier on a validly-signed event (no payment check).
      - solvable:   the signing secret is LEAKED (shipped in public config) -> engine harvests it and forges
                    a valid Standard-Webhooks signature -> detected (exploits the misconfiguration).
      - unsolvable: the secret is NOT leaked -> engine cannot forge -> correct 0 (a correct webhook stays
                    unforgeable; the engine never breaks the crypto).
      - clean:      no bug (valid signature does NOT over-grant) -> 0 false positives.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families6.py
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

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/svc"
SECRET_FIELDS = ["endpoint_secret", "signing_secret", "wh_secret", "webhook_sign"]
HOOKS = ["billing", "settle", "ledger-sync", "pay-event"]


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed * 29 + 5)
    return {"seed": seed, "kind": kind, "secret_field": rng.choice(SECRET_FIELDS), "hook": rng.choice(HOOKS),
            "discloses_all": kind != "unsolvable", "has_bug": kind != "clean"}


class WhTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self._secret = uuid.uuid4().hex
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
            self.orgs[oid] = {"basic": False, "top": False, "pays": {}}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            cfg = {"service": "wh", "settlement_webhook": f"{PFX}/webhooks/{s['hook']}",
                   "signature_scheme": "standard-webhooks v1 hmac-sha256 id.ts.body"}
            if s["discloses_all"]:
                cfg[s["secret_field"]] = self._secret   # leak (misconfig)
            return 200, cfg, {}

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
                if pay["plan"] == "basic":
                    org["basic"] = True
                else:
                    org["top"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            if pay is None:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "ok" if pay["captured"] else "pending"}, {}

        if method == "POST" and p == f"{PFX}/webhooks/{s['hook']}":
            wid = headers.get("webhook-id", ""); ts = headers.get("webhook-timestamp", ""); sig = headers.get("webhook-signature", "")
            good = "v1," + base64.b64encode(hmac.new(self._secret.encode(), f"{wid}.{ts}.{json.dumps(body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
            if not (sig and hmac.compare_digest(sig, good)):
                return 401, {"error": "bad_signature"}, {}
            if s["has_bug"]:
                org["top"] = True                                  # BUG: signature alone grants, no payment
                return 200, {"status": "processed"}, {}
            return 200, {"status": "acknowledged"}, {}            # clean: valid sig is acknowledged but grants nothing

        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    return {
        "authorization_ref": "BENCH-FAM6", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "settle_webhook": {"method": "POST", "path": f"{PFX}/webhooks/{s['hook']}", "observed_via": "public_api_reference"},
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
    target = WhTarget(spec)
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
    t = WhTarget(spec); s = spec

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        st, r, extra = await t.handle(method, path, body or {}, h)
        return st, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    await c("GET", f"{PFX}/config", tok)
    secret = t._secret   # a prober / insider holds it; black-box only obtains it if leaked
    evt = {"event": "paid"}
    wid, ts = f"evt_{uuid.uuid4().hex}", str(int(time.time()))
    sig = "v1," + base64.b64encode(hmac.new(secret.encode(), f"{wid}.{ts}.{json.dumps(evt, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
    await c("POST", f"{PFX}/webhooks/{s['hook']}", tok, evt, {"webhook-id": wid, "webhook-timestamp": ts, "webhook-signature": sig})
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
    print("== widened held-out gauntlet round 6 (signed-webhook family) ==")
    specs = [gen_spec(120000 + i, "solvable") for i in range(6)]
    specs += [gen_spec(120100 + i, "unsolvable") for i in range(3)]
    specs += [gen_spec(120200 + i, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf): print(f"    whsig SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf: print(f"    whsig UNSOLVABLE FALSE-CONFIRM seed={spec['seed']} (secret not leaked -- must be 0)")
        else:
            cn += 1; cf += int(conf)
            if conf: print(f"    whsig CLEAN FP seed={spec['seed']}")
    print(f"  whsig      : solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
