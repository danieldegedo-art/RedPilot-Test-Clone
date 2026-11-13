"""Independent ground-truth prober for the hardened purity benchmark.

WHY THIS EXISTS
---------------
The base purity benchmark's truth is hand-authored in purity_benchmark/scenarios.py
by the same author as the engine. The scorecard flags this as "shared-authorship
bias". This module removes that bias from the TRUTH side: it decides, for each
synthetic target, whether each payment-integrity property is actually violated by
*driving the target's public customer API as an all-knowing attacker* and observing
what happens -- the same evidence an external black-box tester could in principle
obtain, computed with ZERO reference to:
  * the engine's oracle implementation (app/testing/integrity/*), and
  * the target's seeded-flaw flags (TargetFlags).

It talks to the target IN-PROCESS via ``CustomerLevelTarget.handle`` (no sockets),
on a FRESH target instance constructed from the same flags -- so probing never
pollutes the state the engine under test will see. Behaviour is fully determined by
the flags, so a fresh same-flags instance yields the same truth.

TRUTH VOCABULARY (matches purity_benchmark/scorer.py)
  P0   : an external, clean-session differential actually demonstrates the bypass.
  SAFE : the gate is present and observable and no bypass demonstrably grants.
  UNK  : the property is not externally provable here -- feature open to everyone,
         answered asynchronously (202), or the sandbox is broken. Never claim P0/SAFE.
  DIV  : UI/view claims entitlement while the server-enforced feature stays denied.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from purity_benchmark.customer_target import (
    CREDITS_PER_PAYMENT,
    PRICES,
    CustomerLevelTarget,
    TargetFlags,
)

EXPERIMENTS = ("PBB-U", "PBB-F", "PBB-H", "PBB-C", "PBB-G", "PBB-X", "PBB-R", "PBB-E")

# Paths are the public customer surface (same vocabulary a browser trace would reveal).
SIGNUP = "/api/v1/account/signup"
CHECKOUT = "/api/v1/checkout"
RETURN = "/api/v1/checkout/return"
SUBSCRIPTION = "/api/v1/account/subscription"
REFUND = "/api/v1/account/refund"
EXPORT = "/api/v1/premium/export"            # requires basic
CREDITS = "/api/v1/premium/credits/use"      # requires basic, consumes quota
ENTERPRISE = "/api/v1/premium/enterprise-report"  # requires enterprise


@dataclass
class TruthResult:
    truth: dict[str, str]
    open_present: bool = False
    leak_present: bool = False
    notes: list[str] = field(default_factory=list)

    def as_scorer_truth(self) -> dict[str, str]:
        return dict(self.truth)


class _Probe:
    """A thin in-process client around one CustomerLevelTarget instance."""

    def __init__(self, flags: TargetFlags) -> None:
        self.t = CustomerLevelTarget(flags)

    async def _call(self, method: str, path: str, *, token: str | None = None,
                    body: dict | None = None, query: dict | None = None) -> tuple[int, dict]:
        raw = path + ("?" + urlencode(query) if query else "")
        headers = {"authorization": f"Bearer {token}"} if token else {}
        status, resp, _hdrs = await self.t.handle(method, raw, body or {}, headers)
        return status, resp

    async def new_identity(self) -> tuple[str, str]:
        _s, r = await self._call("POST", SIGNUP)
        return r["token"], r["tenant_id"]

    async def checkout(self, token: str, *, plan: str, currency: str = "USD",
                       amount: float | None = None, coupon: str | None = None) -> tuple[int, dict]:
        body: dict[str, Any] = {"plan": plan, "currency": currency}
        if amount is not None:
            body["amount"] = amount
        if coupon is not None:
            body["coupon"] = coupon
        return await self._call("POST", CHECKOUT, token=token, body=body)

    async def sandbox_pay(self, token: str, payment_id: str, outcome: str) -> tuple[int, dict]:
        return await self._call("POST", f"{CHECKOUT}/{payment_id}/sandbox-pay",
                                token=token, body={"outcome": outcome})

    async def return_flow(self, token: str, payment_id: str, *, status: str | None = None,
                          plan: str | None = None, tenant: str | None = None) -> tuple[int, dict]:
        q: dict[str, str] = {"payment_id": payment_id}
        if status is not None:
            q["status"] = status
        if plan is not None:
            q["plan"] = plan
        if tenant is not None:
            q["tenant"] = tenant
        return await self._call("GET", RETURN, token=token, query=q)

    async def feature(self, token: str, path: str) -> tuple[int, dict]:
        method = "GET" if path == ENTERPRISE else "POST"
        return await self._call(method, path, token=token)

    async def works(self, token: str, path: str) -> bool:
        s, r = await self.feature(token, path)
        proof = {EXPORT: "export_id", CREDITS: "credit_used", ENTERPRISE: "report_id"}[path]
        return s == 200 and proof in r

    async def is_async(self, token: str, path: str = EXPORT) -> bool:
        s, _ = await self.feature(token, path)
        return s == 202

    async def legit_enterprise_denied(self, token: str) -> bool:
        """Enterprise feature correctly denied to a non-enterprise identity."""
        s, _ = await self.feature(token, ENTERPRISE)
        return s in (402, 403)

    async def pay_basic(self, *, currency: str = "USD") -> tuple[str, str, str]:
        """Happy path: a fresh identity legitimately buys basic. Returns (token, tenant, payment_id)."""
        token, tenant = await self.new_identity()
        _s, co = await self.checkout(token, plan="basic", currency=currency)
        pid = co["payment_id"]
        await self.sandbox_pay(token, pid, "success")
        await self.return_flow(token, pid, status="success")
        return token, tenant, pid


async def probe_truth(flags: TargetFlags, *, sla: float = 1.0) -> TruthResult:
    """Compute independent ground truth for a target described by ``flags``."""
    res = TruthResult(truth={e: "SAFE" for e in EXPERIMENTS})

    # ---- 1. Is the feature gate even present and synchronously observable? -------------
    p = _Probe(flags)
    unpaid_token, _ = await p.new_identity()

    if await p.is_async(unpaid_token):
        res.truth = {e: "UNK" for e in EXPERIMENTS}
        res.notes.append("feature answers 202 to everyone: not synchronously provable -> UNK")
        return res

    # broken sandbox: we cannot establish a paid baseline at all
    probe_setup = _Probe(flags)
    tok_s, _ = await probe_setup.new_identity()
    _s, co = await probe_setup.checkout(tok_s, plan="basic")
    pay_status, _ = await probe_setup.sandbox_pay(tok_s, co["payment_id"], "success")
    if pay_status >= 500:
        res.truth = {e: "UNK" for e in EXPERIMENTS}
        res.notes.append("sandbox payment step is down (5xx): cannot establish a paid baseline -> UNK/BLOCKED")
        return res

    # feature open to the unpaid?
    if await p.works(unpaid_token, EXPORT):
        res.open_present = True
        res.truth = {e: "UNK" for e in EXPERIMENTS}
        res.notes.append("primary feature works with no payment: gating absent, differential not executable -> UNK (OPEN reported)")
        return res

    # global entitlement leak: after SOMEONE pays, an unrelated unpaid identity gains access
    pleak = _Probe(flags)
    await pleak.pay_basic()
    leak_tok, _ = await pleak.new_identity()
    if await pleak.works(leak_tok, EXPORT):
        res.leak_present = True
        res.truth = {e: "UNK" for e in EXPERIMENTS}
        res.notes.append("a payment by one identity unlocks the feature for an unrelated identity: global leak -> UNK (LEAK reported)")
        return res

    # ---- 2. Gate present & observable. Test each bypass with fresh clean sessions. ------
    res.truth["PBB-U"], res.truth["PBB-E"] = await _probe_u_and_e(flags)
    res.truth["PBB-F"] = await _probe_f(flags)
    res.truth["PBB-H"] = await _probe_h(flags)
    res.truth["PBB-C"] = await _probe_c(flags)
    res.truth["PBB-G"] = await _probe_g(flags)
    res.truth["PBB-X"] = await _probe_x(flags)
    res.truth["PBB-R"] = await _probe_r(flags, sla=sla)
    return res


async def _probe_u_and_e(flags: TargetFlags) -> tuple[str, str]:
    """PBB-U: an unconfirmed/declined payment grants real server access.
    PBB-E: the view claims entitlement while the server feature stays denied (UI-only divergence)."""
    p = _Probe(flags)
    token, _ = await p.new_identity()
    _s, co = await p.checkout(token, plan="basic")
    pid = co["payment_id"]
    await p.sandbox_pay(token, pid, "declined")  # payment did NOT succeed
    _s, ret = await p.return_flow(token, pid, status="success")  # but the return claims success
    server_grants = await p.works(token, EXPORT)
    if server_grants:
        return "P0", "SAFE"  # real bypass dominates; not a mere UI lie
    # no server grant: is the view nonetheless claiming premium? -> divergence
    claims = bool(ret.get("premium_badge")) or "unlock" in str(ret.get("message", "")).lower()
    _s, sub = await p.feature(token, SUBSCRIPTION)
    claims = claims or sub.get("badge") == "premium" or sub.get("status") == "active" and sub.get("plan") not in (None, "free")
    if claims:
        return "DIV", "DIV"
    return "SAFE", "SAFE"


async def _probe_f(flags: TargetFlags) -> str:
    """PBB-F: a tier is obtained without paying that tier's price (plan/amount/enforcement binding)."""
    # (a) client-controlled amount for the top tier
    p = _Probe(flags)
    tok, _ = await p.new_identity()
    s, co = await p.checkout(tok, plan="enterprise", amount=0.01)
    if s == 201 and co.get("amount") == 0.01:
        await p.sandbox_pay(tok, co["payment_id"], "success")
        await p.return_flow(tok, co["payment_id"], status="success")
        if await p.works(tok, ENTERPRISE):
            return "P0"
    # (b) plan named at return is trusted
    p = _Probe(flags)
    tok, _ = await p.new_identity()
    _s, co = await p.checkout(tok, plan="basic")
    await p.sandbox_pay(tok, co["payment_id"], "success")
    await p.return_flow(tok, co["payment_id"], status="success", plan="enterprise")
    if await p.works(tok, ENTERPRISE):
        return "P0"
    # (c) top-tier feature not enforced against a lesser-but-paying tenant
    p = _Probe(flags)
    tok, _, _ = await p.pay_basic()
    if await p.works(tok, ENTERPRISE):
        return "P0"
    return "SAFE"


async def _probe_h(flags: TargetFlags) -> str:
    """PBB-H: currency confusion -- the top tier granted for a non-USD price equal to the USD number."""
    p = _Probe(flags)
    tok, _ = await p.new_identity()
    s, co = await p.checkout(tok, plan="enterprise", currency="JPY")
    if s != 201:
        return "SAFE"
    billed = co.get("amount")
    jpy_price = PRICES["enterprise"]["JPY"]
    underbilled = isinstance(billed, (int, float)) and billed < jpy_price
    if not underbilled:
        return "SAFE"
    await p.sandbox_pay(tok, co["payment_id"], "success")
    await p.return_flow(tok, co["payment_id"], status="success")
    return "P0" if await p.works(tok, ENTERPRISE) else "SAFE"


async def _probe_c(flags: TargetFlags) -> str:
    """PBB-C: duplicate paid value -- repeating the return flow grants the quota again."""
    p = _Probe(flags)
    tok, _ = await p.new_identity()
    _s, co = await p.checkout(tok, plan="basic")
    pid = co["payment_id"]
    await p.sandbox_pay(tok, pid, "success")
    await p.return_flow(tok, pid, status="success")  # grant #1 (CREDITS_PER_PAYMENT)
    await p.return_flow(tok, pid, status="success")  # replay
    used = 0
    for _ in range(CREDITS_PER_PAYMENT * 3):
        if await p.works(tok, CREDITS):
            used += 1
        else:
            break
    return "P0" if used > CREDITS_PER_PAYMENT else "SAFE"


async def _probe_g(flags: TargetFlags) -> str:
    """PBB-G: cross-tenant -- a payer can name another tenant as the beneficiary."""
    p = _Probe(flags)
    victim_tok, victim_tenant = await p.new_identity()
    attacker_tok, _ = await p.new_identity()
    _s, co = await p.checkout(attacker_tok, plan="basic")
    pid = co["payment_id"]
    await p.sandbox_pay(attacker_tok, pid, "success")
    await p.return_flow(attacker_tok, pid, status="success", tenant=victim_tenant)
    return "P0" if await p.works(victim_tok, EXPORT) else "SAFE"


async def _probe_x(flags: TargetFlags) -> str:
    """PBB-X: cross-identity -- an identity redeems a payment it did not make."""
    p = _Probe(flags)
    owner_tok, _ = await p.new_identity()
    _s, co = await p.checkout(owner_tok, plan="basic")
    pid = co["payment_id"]
    await p.sandbox_pay(owner_tok, pid, "success")
    attacker_tok, _ = await p.new_identity()
    await p.return_flow(attacker_tok, pid, status="success")  # 403 unless payment_owner_unchecked
    return "P0" if await p.works(attacker_tok, EXPORT) else "SAFE"


async def _probe_r(flags: TargetFlags, *, sla: float) -> str:
    """PBB-R: entitlement retained beyond the declared revocation SLA after a refund."""
    p = _Probe(flags)
    tok, _, pid = await p.pay_basic()
    if not await p.works(tok, EXPORT):
        return "SAFE"  # never got the entitlement; nothing to retain
    s, _ = await p._call("POST", REFUND, token=tok, body={"payment_id": pid})
    if s != 200:
        return "SAFE"  # refund not accepted; out of scope for retention
    await asyncio.sleep(sla + 0.3)  # let any scheduled revocation fire; then check past the SLA
    return "P0" if await p.works(tok, EXPORT) else "SAFE"
