"""Enterprise-grade HARD benchmark targets.

Design goal (explicit owner request): make it hard, like a real enterprise target.
Real payment-integrity bypasses are hidden behind channels an ordinary brief does
NOT disclose (recon-only), and buried under adversarial decoys that look like flaws
but are not. A tester that pattern-matches, or trusts a response body / a lookalike
endpoint, will either MISS the real flaw or raise a FALSE POSITIVE.

Real bypasses (recon-only channels):
  * grant_via_header     : the declared feature grants when header X-Entitlement-Override: 1 is sent
  * grant_via_query      : ...when ?preview=true is sent
  * unsigned_grant_token : ...when an unverified X-Grant token is sent (broken object-level auth)
  * hidden_comp_endpoint : POST /api/v1/account/comp grants enterprise for free (undocumented)

Hard decoys (NO real entitlement -- must NOT be confirmed):
  * shadow_success_endpoint : GET /api/v1/premium/sample returns a convincing 200 that grants nothing durable
  * intermittent_badge      : the subscription view flaps a 'premium' badge while the server-enforced feature stays denied (DIV)
  * cosmetic_entitled_field : bodies carry entitled:true that is never server-enforced
  * lying_hints             : debug headers name a flaw that does not exist

Plus optional base in-channel flaws (TargetFlags) so a real flaw can be buried in noise.
Truth is computed by a thorough prober that tries EVERY channel (ground_truth for the
base flags, plus the novel channels here); nothing here is given to the engine.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from hardened_benchmark.ground_truth import EXPERIMENTS, probe_truth
from purity_benchmark.customer_target import CustomerLevelTarget, TargetFlags, _serve_connection
from reference_target import _TrackedServer
import asyncio

SIGNUP = "/api/v1/account/signup"
EXPORT = "/api/v1/premium/export"
ENTERPRISE = "/api/v1/premium/enterprise-report"
SUBSCRIPTION = "/api/v1/account/subscription"
COMP = "/api/v1/account/comp"          # undocumented free-grant endpoint
SAMPLE = "/api/v1/premium/sample"       # decoy: looks like the feature, grants nothing


@dataclass(frozen=True)
class HardFlags:
    # real bypasses via recon-only channels
    grant_via_header: bool = False
    grant_via_query: bool = False
    unsigned_grant_token: bool = False
    hidden_comp_endpoint: bool = False
    # hard decoys (no real entitlement)
    shadow_success_endpoint: bool = False
    intermittent_badge: bool = False
    cosmetic_entitled_field: bool = False
    lying_hints: bool = False
    # optional base in-channel flaw(s) and controls, to bury a real flaw in noise
    base_flags: dict[str, Any] = field(default_factory=dict)
    sla: float = 1.0

    def has_novel_bypass(self) -> bool:
        return self.grant_via_header or self.grant_via_query or self.unsigned_grant_token or self.hidden_comp_endpoint


class EnterpriseTarget(CustomerLevelTarget):
    def __init__(self, hard: HardFlags) -> None:
        super().__init__(TargetFlags(**hard.base_flags))
        self.h = hard
        self._view_counter = 0

    async def handle(self, method, raw_path, body, headers):
        parsed = urlparse(raw_path)
        path = parsed.path
        query = parse_qs(parsed.query)
        auth = headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        ident = self._by_token.get(token)

        if ident is not None:
            if method == "POST" and path == EXPORT:
                if self.h.grant_via_header and headers.get("x-entitlement-override") == "1":
                    self.request_log.append((method, path))
                    return 200, {"export_id": "exp_backdoor", "rows": 3}, {}
                if self.h.grant_via_query and query.get("preview") == ["true"]:
                    self.request_log.append((method, path))
                    return 200, {"export_id": "exp_backdoor", "rows": 3}, {}
                if self.h.unsigned_grant_token and headers.get("x-grant"):
                    self.request_log.append((method, path))
                    return 200, {"export_id": "exp_backdoor", "rows": 3}, {}
            if method == "POST" and path == COMP and self.h.hidden_comp_endpoint:
                self._ent(ident.tenant_id)["plan"] = "enterprise"
                self.request_log.append((method, path))
                return 200, {"status": "comped", "plan": "enterprise"}, {}
            if method == "GET" and path == SAMPLE and self.h.shadow_success_endpoint:
                self.request_log.append((method, path))
                return 200, {"export_id": "sample_only", "sample": True, "rows": 1}, {}

        status, respbody, extra = await super().handle(method, raw_path, body, headers)

        if self.h.intermittent_badge and method == "GET" and path == SUBSCRIPTION and isinstance(respbody, dict):
            self._view_counter += 1
            if self._view_counter % 2 == 0:
                respbody = dict(respbody, badge="premium", status="active")
        if self.h.cosmetic_entitled_field and isinstance(respbody, dict) and "entitled" not in respbody:
            respbody = dict(respbody, entitled=True)  # cosmetic; never server-enforced
        if self.h.lying_hints:
            extra = dict(extra, **{"X-Debug-Entitlement": "granted", "X-Benchmark-Flaw-Hint": "return_trusts_status_claim"})
        return status, respbody, extra


async def start_enterprise_target(hard: HardFlags):
    target = EnterpriseTarget(hard)
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


# ---------------- thorough independent truth (tries every channel) ------------------
async def _signup(t: EnterpriseTarget) -> str:
    _s, r, _h = await t.handle("POST", SIGNUP, {}, {})
    return r["token"]


async def _real_feature_used_unpaid(h: HardFlags) -> bool:
    """Does a never-paid identity obtain the DECLARED feature through any novel channel?
    (The shadow endpoint does NOT count -- it is a different path that grants nothing.)"""
    t = EnterpriseTarget(h)
    tok = await _signup(t)
    if h.grant_via_header:
        s, r, _ = await t.handle("POST", EXPORT, {}, {"authorization": f"Bearer {tok}", "x-entitlement-override": "1"})
        if s == 200 and r.get("export_id") not in (None, "sample_only"):
            return True
    if h.grant_via_query:
        s, r, _ = await t.handle("POST", EXPORT + "?preview=true", {}, {"authorization": f"Bearer {tok}"})
        if s == 200 and r.get("export_id") not in (None, "sample_only"):
            return True
    if h.unsigned_grant_token:
        grant = base64.b64encode(b"plan=enterprise").decode()
        s, r, _ = await t.handle("POST", EXPORT, {}, {"authorization": f"Bearer {tok}", "x-grant": grant})
        if s == 200 and r.get("export_id") not in (None, "sample_only"):
            return True
    if h.hidden_comp_endpoint:
        await t.handle("POST", COMP, {"plan": "enterprise"}, {"authorization": f"Bearer {tok}"})
        s, r, _ = await t.handle("GET", ENTERPRISE, {}, {"authorization": f"Bearer {tok}"})
        if s == 200 and "report_id" in r:
            return True
    return False


@dataclass
class HardTruth:
    bypass_present: bool
    novel_channel: bool
    base_p0: bool
    div_present: bool
    note: str = ""


async def probe_enterprise_truth(h: HardFlags) -> HardTruth:
    novel = await _real_feature_used_unpaid(h)
    base = await probe_truth(TargetFlags(**h.base_flags), sla=h.sla)
    base_p0 = any(base.truth[e] == "P0" for e in EXPERIMENTS)
    div = h.intermittent_badge or any(base.truth[e] == "DIV" for e in EXPERIMENTS)
    return HardTruth(bypass_present=novel or base_p0, novel_channel=novel, base_p0=base_p0, div_present=div)


# --------------------------------- hard population ----------------------------------
_DECOYS = dict(shadow_success_endpoint=True, intermittent_badge=True, cosmetic_entitled_field=True, lying_hints=True)


def hard_population(seed: int = 0) -> list[tuple[str, HardFlags]]:
    """A fixed, adversarial enterprise population. Deterministic (no RNG timing)."""
    pop: list[tuple[str, HardFlags]] = []

    # real bypass via a recon-only channel, buried under every decoy
    for ch in ("grant_via_header", "grant_via_query", "unsigned_grant_token", "hidden_comp_endpoint"):
        pop.append((f"novel:{ch}+decoys", HardFlags(**{ch: True}, **_DECOYS)))
        pop.append((f"novel:{ch}+clean", HardFlags(**{ch: True})))

    # hard decoy-only targets: NO real flaw, maximal lure -> must be TN (false-positive test)
    pop.append(("decoy_only:all", HardFlags(**_DECOYS)))
    pop.append(("decoy_only:shadow", HardFlags(shadow_success_endpoint=True, cosmetic_entitled_field=True)))
    pop.append(("decoy_only:badge", HardFlags(intermittent_badge=True, lying_hints=True)))
    pop.append(("decoy_only:cosmetic", HardFlags(cosmetic_entitled_field=True)))

    # base in-channel flaws buried under decoys (combination traps) -> must still be TP
    for bf in ("return_trusts_status_claim", "tenant_claim_trusted", "payment_owner_unchecked", "replay_grants_again"):
        pop.append((f"buried:{bf}", HardFlags(base_flags={bf: True}, **_DECOYS)))

    # clean enterprise targets with decoys -> TN
    pop.append(("clean+decoys", HardFlags(**_DECOYS)))
    pop.append(("clean+badge+cosmetic", HardFlags(intermittent_badge=True, cosmetic_entitled_field=True)))

    # within-SLA refund jitter under decoys -> TN (not an R finding)
    pop.append(("within_sla+decoys", HardFlags(base_flags={"revoke_delay_s": 0.3}, sla=1.0, **_DECOYS)))

    return pop
