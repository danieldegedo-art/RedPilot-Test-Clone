#!/usr/bin/env python3
"""Widened held-out gauntlet, round 12 -- the BUSINESS-LOGIC NUMERIC family (proves the value-mutation capability
generalizes out-of-sample, and pins the boundary). Grounded in the Intigriti price-manipulation taxonomy. The
adversarial values (negative quantity, 0, a confused currency code) appear NOWHERE in the target, so an engine
that only replays observed values cannot produce them -- the capability is genuinely required.

  * numeric -- a finalize step grants the paid tier for FREE when a client-supplied numeric/currency value breaks
    the price invariant (total <= 0 via negative quantity / zero amount, or a confused non-USD currency treated as
    paid). A correct server recomputes/validates server-side and never trusts the client value.
      - solvable:   the server trusts the client value -> engine mutates it to break the invariant -> free grant.
      - unsolvable: the server validates (value > 0 and == real price; currency == USD) -> no free path -> 0.
      - clean:      the value is accepted but grants nothing (server recomputes) -> 0 false positives.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families12.py
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
NUM_FIELDS = ["amount", "quantity", "net_total", "units"]
FLAVORS = ["numeric", "currency"]
OPS = ["finalize", "settle-order", "checkout-commit"]


def gen_spec(seed: int, kind: str) -> dict[str, Any]:
    rng = random.Random(seed * 61 + 13)
    flavor = rng.choice(FLAVORS)
    return {"seed": seed, "kind": kind, "flavor": flavor,
            "field": "currency" if flavor == "currency" else rng.choice(NUM_FIELDS), "op": rng.choice(OPS),
            "trusts_client": kind != "unsolvable", "grants": kind != "clean"}


class NumericTarget:
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self._price = 99.0
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
            return 200, {"plans": [{"code": "top", "price_id": "pr_t", "amount": self._price, "currency": "USD"}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            return 200, {"service": "num", "finalize": f"{PFX}/{s['op']}", "price": self._price, "currency": "USD"}, {}
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
                pay["captured"] = True; org["top"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            return (200, {"status": "ok" if pay["captured"] else "pending"}, {}) if pay else (404, {"error": "unknown_payment"}, {})
        if method == "POST" and p == f"{PFX}/{s['op']}":
            fld = s["field"]
            v = body.get(fld)
            if v is None:
                return 422, {"error": "missing_field", "field": fld}, {}
            # determine whether the supplied value breaks the price invariant to yield a FREE (no-payment) grant
            free = False
            if s["flavor"] == "currency":
                if str(v).upper() != "USD":
                    # confused currency: a correct server rejects it; a trusting server treats it as paid
                    if s["trusts_client"]:
                        free = True
                    else:
                        return 402, {"error": "currency_mismatch", "detail": "amount/currency must match plan"}, {}
                else:
                    return 402, {"error": "payment_required"}, {}
            else:
                try:
                    num = float(v)
                except (TypeError, ValueError):
                    return 422, {"error": "invalid_field", "field": fld}, {}
                if s["trusts_client"]:
                    # BUG: net total trusted from the client; <= 0 (negative qty / zero) => free
                    if num <= 0:
                        free = True
                    else:
                        return 402, {"error": "payment_required"}, {}
                else:
                    # correct: quantity/amount must be a positive real price; no free path
                    if num <= 0:
                        return 422, {"error": "invalid_field", "field": fld, "detail": "must be positive"}, {}
                    return 402, {"error": "payment_required"}, {}
            if free and s["grants"]:
                org["top"] = True
                return 200, {"status": "fulfilled", "tier": "top", "charged": 0}, {}
            return 200, {"status": "recorded"}, {}
        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def brief_for(spec, base_url):
    s = spec
    return {
        "authorization_ref": "BENCH-FAM12", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "finalize_order": {"method": "POST", "path": f"{PFX}/{s['op']}", "observed_via": "public_api_reference"},
            "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        },
        "plans": {"top": {"prices": {"USD": 99.0}}},
        "features": {"use_feature": {"method": "GET", "path": f"{PFX}/use", "proof_field": "ok_id", "requires_plan": "top", "observed_via": "product_ui"}},
        "declared_paid_features": ["use_feature"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def _start(spec):
    target = NumericTarget(spec)
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
    if not (spec["trusts_client"] and spec["grants"]):
        return False
    t = NumericTarget(spec); s = spec

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, _ = await t.handle(method, path, body or {}, h)
        return st, r
    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    val = "INR" if s["flavor"] == "currency" else -100
    await c("POST", f"{PFX}/{s['op']}", tok, {s["field"]: val})
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
    print("== widened held-out gauntlet round 12 (business-logic numeric family) ==")
    specs = [gen_spec(190000 + i, "solvable") for i in range(6)]
    specs += [gen_spec(190100 + i, "unsolvable") for i in range(3)]
    specs += [gen_spec(190200 + i, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_has_bypass(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf):
                print(f"    numeric SOL seed={spec['seed']} flavor={spec['flavor']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf:
                print(f"    numeric UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf:
                print(f"    numeric CLEAN FP seed={spec['seed']}")
    print(f"  numeric    : solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
