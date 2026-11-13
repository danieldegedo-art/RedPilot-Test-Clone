#!/usr/bin/env python3
"""Widened held-out gauntlet, round 10 -- the RELAYED-REQUEST / SSRF-signing family (proves the depth-16
cross-service capability generalizes out-of-sample, and pins the boundary). Structurally unrelated to Olympus:
different prefix, op/field names, randomized per seed.

  * relaysign -- a gateway `relay` endpoint forwards to an internal grant path and returns its response. The
    gateway authorizes the forward with an HMAC over the FORWARDED path (not the gateway's own path), using a
    secret leaked in config. A correct gateway ALLOWLISTS the forward target (OWASP SSRF cheat sheet); the flaw
    is the missing allowlist (OWASP API7).
      - solvable:   allowlist missing + internal grant over-grants -> engine forges the relay signature over
                    the forwarded path and reaches the internal grant -> detected.
      - unsolvable: allowlist enforced -> the internal grant path is refused -> correct 0.
      - clean:      allowlist missing (reachable) but the internal endpoint grants nothing -> 0 false positives.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families10.py
"""
from __future__ import annotations

import asyncio
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
SECRET_FIELDS = ["gateway_secret", "relay_signing_key", "forward_secret", "edge_sign"]  # match /secret|key|sign/
RELAY_OPS = ["relay", "forward", "egress", "proxy-call"]
RELAY_FIELDS = ["forward_path", "target", "relay_dest", "hop_url"]  # all match /forward|target|relay|dest|hop|url|path/


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed * 53 + 7)
    return {"seed": seed, "kind": kind, "secret_field": rng.choice(SECRET_FIELDS), "relay_op": rng.choice(RELAY_OPS),
            "relay_field": rng.choice(RELAY_FIELDS), "inner": f"int{rng.randrange(10**6)}",
            "ssrf_open": kind != "unsolvable", "over_grants": kind != "clean"}


class RelayTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self._secret = uuid.uuid4().hex
        self._allowed = "/internal/health"
        self._grant_path = f"/internal/{spec['inner']}/grant"
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _eff(self, org):
        return "top" if org["top"] else ("basic" if org["basic"] else None)

    def _internal(self, oid, inner_path, body):
        self.internal_hits += 1
        if inner_path != self._grant_path:
            return 404, {"error": "not_found"}
        if self.s["over_grants"]:
            self.orgs[oid]["top"] = True
            return 200, {"status": "granted", "tier": "top"}
        return 200, {"status": "acknowledged"}

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
            # discloses the internal grant path under the SAME field name the relay op consumes, so this family
            # isolates the relay-SIGNING capability (sign over the forwarded path), not field-name mapping.
            return 200, {"service": "relay", "scheme": "hmac-sha256 over the forward target",
                         s["relay_field"]: self._grant_path, s["secret_field"]: self._secret}, {}
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
        if method == "POST" and p == f"{PFX}/{s['relay_op']}":
            fwd = body.get(s["relay_field"])
            if fwd is None:
                return 422, {"error": "missing_field", "field": s["relay_field"]}, {}
            rsig = body.get("relay_sig")
            if rsig is None:
                return 422, {"error": "missing_field", "field": "relay_sig", "note": "hmac over the forward target"}, {}
            want = hmac.new(self._secret.encode(), str(fwd).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(rsig), want):
                return 403, {"error": "bad_relay_signature"}, {}
            if not s["ssrf_open"] and str(fwd) != self._allowed:
                return 403, {"error": "forward_not_allowed"}, {}
            if str(fwd) == self._allowed:
                return 200, {"status": "ok", "service": "health"}, {}
            st, obj = self._internal(oid, str(fwd), body)
            return st, obj, {}
        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 403, {"error": "forbidden"}, {}


def brief_for(spec, base_url):
    s = spec
    return {
        "authorization_ref": "BENCH-FAM10", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "relay_forward": {"method": "POST", "path": f"{PFX}/{s['relay_op']}", "observed_via": "public_api_reference"},
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
    target = RelayTarget(spec)
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
        out = await target.handle(method, path, body, headers)
        status, obj, extra = out if len(out) == 3 else (out[0], out[1], {})
    except Exception as exc:  # noqa: BLE001
        status, obj, extra = 400, {"error": "bad", "detail": str(exc)}, {}
    payload = json.dumps(obj).encode("utf-8")
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload); await writer.drain()
    finally:
        writer.close()


async def truth_has_bypass(spec) -> bool:
    if not (spec["ssrf_open"] and spec["over_grants"]):
        return False
    t = RelayTarget(spec); s = spec

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        out = await t.handle(method, path, body or {}, h)
        return out[0], out[1]
    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config", tok)
    secret = cfg[s["secret_field"]]; grant = cfg[s["relay_field"]]
    rsig = hmac.new(secret.encode(), grant.encode(), hashlib.sha256).hexdigest()
    await c("POST", f"{PFX}/{s['relay_op']}", tok, {s["relay_field"]: grant, "relay_sig": rsig})
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
    print("== widened held-out gauntlet round 10 (relayed-request / SSRF-signing family) ==")
    specs = [gen_spec(170000 + i, "solvable") for i in range(6)]
    specs += [gen_spec(170100 + i, "unsolvable") for i in range(3)]
    specs += [gen_spec(170200 + i, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf):
                print(f"    relaysign SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf:
                print(f"    relaysign UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf:
                print(f"    relaysign CLEAN FP seed={spec['seed']}")
    print(f"  relaysign  : solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
