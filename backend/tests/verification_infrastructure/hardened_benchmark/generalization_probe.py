#!/usr/bin/env python3
"""Generalization / recon-breadth probe.

Each base flaw in the fixture is implemented via the EXACT channel the engine's
oracle already probes (e.g. the return-flow ?status= claim). This asks a different
question: when a real access-without-payment bypass exists via a channel the engine
does NOT currently probe, does it still find it -- or does it RULE OUT (false
assurance)? The ground truth is set by a thorough prober that DOES try these
channels; the engine faces the same target with only the ordinary brief (which, as
in reality, does not mention the backdoor).

Novel mechanisms (all genuine "access/tier without payment", different channel):
  * header backdoor : feature granted when header X-Entitlement-Override: 1 is sent
  * query backdoor  : feature granted when ?preview=true is sent
  * hidden endpoint : POST /api/v1/promo/apply grants enterprise for free

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/generalization_probe.py
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from purity_benchmark.customer_target import CustomerLevelTarget, TargetFlags, _serve_connection
from purity_benchmark.lab import public_brief
from reference_target import _TrackedServer

SIGNUP = "/api/v1/account/signup"
EXPORT = "/api/v1/premium/export"
ENTERPRISE = "/api/v1/premium/enterprise-report"
PROMO = "/api/v1/promo/apply"


@dataclass(frozen=True)
class VariantFlags:
    grant_via_header: bool = False
    grant_via_query: bool = False
    hidden_promo_endpoint: bool = False


class VariantTarget(CustomerLevelTarget):
    """Base customer target plus out-of-channel bypasses (undisclosed in the brief)."""

    def __init__(self, vflags: VariantFlags) -> None:
        super().__init__(TargetFlags())  # otherwise a correct target
        self.v = vflags

    async def handle(self, method, raw_path, body, headers):
        parsed = urlparse(raw_path)
        path = parsed.path
        query = parse_qs(parsed.query)
        auth = headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        ident = self._by_token.get(token)
        if ident is not None:
            if method == "POST" and path == EXPORT:
                if self.v.grant_via_header and headers.get("x-entitlement-override") == "1":
                    self.request_log.append((method, path))
                    return 200, {"export_id": "exp_backdoor", "rows": 3}, {}
                if self.v.grant_via_query and query.get("preview") == ["true"]:
                    self.request_log.append((method, path))
                    return 200, {"export_id": "exp_backdoor", "rows": 3}, {}
            if method == "POST" and path == PROMO and self.v.hidden_promo_endpoint:
                self._ent(ident.tenant_id)["plan"] = "enterprise"
                self.request_log.append((method, path))
                return 200, {"status": "promo_applied", "plan": "enterprise"}, {}
        return await super().handle(method, raw_path, body, headers)


async def _start(target: VariantTarget):
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return tracked, server.sockets[0].getsockname()[1]


# ---- thorough ground truth: try the backdoor channels directly (in-process) --------
async def _signup(t: VariantTarget) -> str:
    _s, r, _h = await t.handle("POST", SIGNUP, {}, {})
    return r["token"]


async def truth_has_free_access(v: VariantFlags) -> bool:
    t = VariantTarget(v)
    tok = await _signup(t)
    if v.grant_via_header:
        s, r, _ = await t.handle("POST", EXPORT, {}, {"authorization": f"Bearer {tok}", "x-entitlement-override": "1"})
        if s == 200 and "export_id" in r:
            return True
    if v.grant_via_query:
        s, r, _ = await t.handle("POST", EXPORT + "?preview=true", {}, {"authorization": f"Bearer {tok}"})
        if s == 200 and "export_id" in r:
            return True
    if v.hidden_promo_endpoint:
        await t.handle("POST", PROMO, {"plan": "enterprise"}, {"authorization": f"Bearer {tok}"})
        s, r, _ = await t.handle("GET", ENTERPRISE, {}, {"authorization": f"Bearer {tok}"})
        if s == 200 and "report_id" in r:
            return True
    return False


async def engine_confirms_any(v: VariantFlags) -> tuple[bool, dict]:
    target = VariantTarget(v)
    server, port = await _start(target)
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief_dict = public_brief(base)
        brief = ExecutionBrief.from_dict(brief_dict, env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base)
        result = await engine.run(None)
        verdicts = {f.hypothesis_id: f.verdict.value for f in result.findings}
        confirmed = any(v2 == "CONFIRMED_P0" for v2 in verdicts.values())
        return confirmed, verdicts
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()


async def main() -> int:
    cases = {
        "control_clean": VariantFlags(),
        "header_backdoor": VariantFlags(grant_via_header=True),
        "query_backdoor": VariantFlags(grant_via_query=True),
        "hidden_endpoint": VariantFlags(hidden_promo_endpoint=True),
    }
    print(f"{'case':18s} {'truth_P0':9s} {'engine_P0':10s} verdict")
    detected = relevant = 0
    for name, v in cases.items():
        truth = await truth_has_free_access(v)
        confirmed, verdicts = await engine_confirms_any(v)
        confirms = {k: val for k, val in verdicts.items() if val == "CONFIRMED_P0"}
        mark = ""
        if truth:
            relevant += 1
            detected += int(confirmed)
            mark = "  <-- MISS (false assurance)" if not confirmed else "  detected"
        print(f"{name:18s} {str(truth):9s} {str(confirmed):10s} {sorted(confirms) or '-'}{mark}")
    print(f"\nnovel-mechanism detection: {detected}/{relevant} "
          f"({'headroom found' if detected < relevant else 'engine generalized'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
