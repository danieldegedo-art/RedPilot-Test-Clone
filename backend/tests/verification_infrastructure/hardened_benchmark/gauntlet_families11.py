#!/usr/bin/env python3
"""Widened held-out gauntlet, round 11 -- the ASYNC-CALLBACK CORRELATION family (proves the depth-18 capability
generalizes out-of-sample, and pins the boundary). Structurally unrelated to Cosmos: different prefix, op/field
names, randomized per seed.

  * asynccallback -- an enqueue step issues a correlation id; the paid tier is granted only when a signed
    async callback that carries THAT correlation id as its webhook-id (at-least-once dedup binding; Svix/Nylas)
    is ingested. A correct receiver verifies an HMAC over webhook-id.timestamp.idempotency.body.
      - solvable:   the callback signing secret is LEAKED in config -> engine forges a correlation-bound, fresh,
                    idempotent callback -> detected.
      - unsolvable: the secret is NOT leaked -> engine cannot forge -> correct 0.
      - clean:      the callback is accepted but grants nothing -> engine forges yet tier stays denied -> 0 FP.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families11.py
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
SECRET_FIELDS = ["callback_secret", "signing_secret", "wh_secret", "webhook_sign"]           # match /secret|signing|whsec|webhook/
CORR_FIELDS = ["correlation_id", "job_id", "task_ref", "dispatch_id", "message_id"]            # match the correlation regex
HOOKS = ["settle", "callback", "events-ingest", "async-settle"]
ENQ_OPS = ["enqueue", "dispatch", "schedule-settle"]


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed * 59 + 11)
    return {"seed": seed, "kind": kind, "secret_field": rng.choice(SECRET_FIELDS), "corr_field": rng.choice(CORR_FIELDS),
            "hook": rng.choice(HOOKS), "enq_op": rng.choice(ENQ_OPS),
            "discloses_secret": kind != "unsolvable", "over_grants": kind != "clean"}


class AsyncCbTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self._secret = uuid.uuid4().hex
        self.pending: dict[str, dict[str, Any]] = {}
        self.used_idem: set[str] = set()
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
            cfg = {"service": "async", "callback_ingest": f"{PFX}/{s['hook']}",
                   "scheme": "standard-webhooks v1 hmac-sha256 over webhook-id.timestamp.idempotency.body",
                   "note": "webhook-id must equal the issued correlation id"}
            if s["discloses_secret"]:
                cfg[s["secret_field"]] = self._secret
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
                pay["captured"] = True; org["basic" if pay["plan"] == "basic" else "top"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            return (200, {"status": "ok" if pay["captured"] else "pending"}, {}) if pay else (404, {"error": "unknown_payment"}, {})
        if method == "POST" and p == f"{PFX}/{s['enq_op']}":
            corr = f"corr_{uuid.uuid4().hex[:16]}"; self.pending[corr] = {"org": oid, "settled": False}
            return 200, {s["corr_field"]: corr, "status": "enqueued"}, {}
        if method == "POST" and p == f"{PFX}/{s['hook']}":
            idem = headers.get("idempotency-key", "")
            if not idem:
                return 400, {"error": "idempotency_key_required", "field": "idempotency-key"}, {}
            if idem in self.used_idem:
                return 409, {"error": "duplicate_idempotency"}, {}
            wid = headers.get("webhook-id", ""); wts = headers.get("webhook-timestamp", ""); sig = headers.get("webhook-signature", "")
            try:
                fresh = abs(int(time.time()) - int(wts)) <= 300
            except (TypeError, ValueError):
                fresh = False
            if not fresh:
                return 401, {"error": "stale_signature"}, {}
            good = "v1," + base64.b64encode(hmac.new(self._secret.encode(), f"{wid}.{wts}.{idem}.{json.dumps(body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
            if not (sig and hmac.compare_digest(sig, good)):
                return 401, {"error": "bad_signature"}, {}
            job = self.pending.get(wid)   # webhook-id MUST be the issued correlation id
            if job is None or job["org"] != oid:
                return 422, {"error": "unknown_correlation", "field": "webhook-id"}, {}
            self.used_idem.add(idem)
            if not job["settled"]:
                job["settled"] = True
                if s["over_grants"]:
                    org["top"] = True
                    return 200, {"status": "settled", "tier": "top"}, {}
            return 200, {"status": "acknowledged"}, {}
        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    return {
        "authorization_ref": "BENCH-FAM11", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "enqueue_job": {"method": "POST", "path": f"{PFX}/{s['enq_op']}", "observed_via": "public_api_reference"},
            "callback_ingest": {"method": "POST", "path": f"{PFX}/{s['hook']}", "observed_via": "public_api_reference"},
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
    target = AsyncCbTarget(spec)
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
    if not (spec["discloses_secret"] and spec["over_grants"]):
        return False
    t = AsyncCbTarget(spec); s = spec

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        st, r, _ = await t.handle(method, path, body or {}, h)
        return st, r
    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config", tok)
    secret = cfg[s["secret_field"]]
    _s, enq = await c("POST", f"{PFX}/{s['enq_op']}", tok)
    corr = enq[s["corr_field"]]
    cb_body = {"event": "settle"}
    wts = str(int(time.time())); idem = f"idk_{uuid.uuid4().hex}"
    wsig = "v1," + base64.b64encode(hmac.new(secret.encode(), f"{corr}.{wts}.{idem}.{json.dumps(cb_body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
    await c("POST", f"{PFX}/{s['hook']}", tok, cb_body,
            {"webhook-id": corr, "webhook-timestamp": wts, "idempotency-key": idem, "webhook-signature": wsig})
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
    print("== widened held-out gauntlet round 11 (async-callback correlation family) ==")
    specs = [gen_spec(180000 + i, "solvable") for i in range(6)]
    specs += [gen_spec(180100 + i, "unsolvable") for i in range(3)]
    specs += [gen_spec(180200 + i, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf):
                print(f"    asynccallback SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf:
                print(f"    asynccallback UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf:
                print(f"    asynccallback CLEAN FP seed={spec['seed']}")
    print(f"  asynccallback: solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
