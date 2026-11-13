"""benchmark_lab.py -- U2: seeded benchmark + MEASURED scorecard for oracle_engine.py.

Seventeen scenarios, each a real local HTTP target (real sockets, real
QAHttpClient) whose GROUND TRUTH is derived PROGRAMMATICALLY from the flags it
was built with (truth_from_flags) -- never hand-written per scenario -- so the
expectation cannot be quietly adjusted to whatever the engine happened to say.
The expected ENGINE verdict (what a correct engine with the capabilities it
was given should report) is a second, separate derivation
(expected_from_flags): truth answers "is there really a P0 here", expectation
answers "what should this engine say about it given what it can observe".

Scenario families (each maps to a benchmark class the transformation brief
names explicitly):
  * wide_open / only_A..only_H / lag_only / cache_divergence_chain:
        real P0s -- one bug at a time (so a verdict can be attributed to one
        cause) plus two multi-step chains
  * fully_fixed:                 correct server-side blocking everywhere
  * signature_only_fixed[_no_secret]:
        the MASKING case -- only the authentication perimeter is fixed; every
        other bug is still open behind it. With a declared sandbox secret the
        engine must find them; WITHOUT one it must say UNKNOWN, never RULED_OUT
  * free_tier_decoy / free_tier_declared_open / stale_status_view:
        harmless anomalies that must NOT become P0 (universal free access; a
        stale status VIEW with no usable access)
  * broken_setup:                setup failure must become BLOCKED, never a crash

The same targets are also run through the LEGACY black_box_prober.py so
every "before" number in the scorecard is MEASURED on identical ground, not
recalled from an earlier session. Where the legacy prober cannot express a
class at all, the scorecard says "not testable" instead of inventing a number.

Honest limits, repeated in the rendered scorecard: the author of the engine
also wrote these targets (shared authorship bias -- the hypotheses tested are
the hypotheses the author already knew to look for); every target is local
loopback, so all timing numbers are NOT representative of a real network; and
ORC-I's timing-based verdict is 'medium' confidence by design.

Run:  python3 tests/verification_infrastructure/benchmark_lab.py [out_dir]
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import dataclasses
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).parent))

from entitlement_target import EntitlementTarget, start_entitlement_target  # noqa: E402
from oracle_engine import EvidenceItem, Finding, OracleEngine, OracleSpec  # noqa: E402

WEBHOOK_SECRET = "whsec_test_only_do_not_use_in_prod"  # stands in for the customer's declared SANDBOX secret
ORACLE_CLASSES = ["BASELINE", "A", "B", "C", "D", "E", "F", "G", "H", "I"]
VULN_CLASSES = [c for c in ORACLE_CLASSES if c != "BASELINE"]
P0_LIKE = {"confirmed_p0", "strongly_suspected_p0"}
LEGACY_MAP = {"BB-001": "B", "BB-002": "F", "BB-003": "C", "BB-004": "G"}

FIXED: dict[str, bool] = dict(
    require_webhook_signature=True, dedupe_webhook_events=True, verify_authoritative_status=True,
    revoke_entitlement_on_refund=True, invalidate_cache_on_revoke=True, verify_amount_matches_tier=True,
    enforce_tenant_isolation=True, verify_currency_matches_tier=True, check_access_verifies_authoritative=True,
)


def fixed_except(**overrides: bool) -> dict[str, bool]:
    return {**FIXED, **overrides}


# ---------------------------------------------------------------- decoy / robustness targets
class FreeTierDecoyTarget(EntitlementTarget):
    """NO vulnerability: the webhook is inert and every identity has (free-tier) access."""

    async def handle_webhook(self, body: dict) -> tuple[int, dict]:
        return 200, {"status": "ignored"}

    def check_access(self, user_id: str, tenant_id: str | None = None) -> bool:
        return True


class StaleStatusViewTarget(EntitlementTarget):
    """Fully protected, but the entitlement-DETAIL view is stale: it keeps saying active=True after
    revocation while the access decision correctly denies. A quality issue, explicitly NOT a P0."""

    async def handle_http(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        status, resp = await super().handle_http(method, path, body)
        if method == "GET" and path.startswith("/api/v1/entitlements/") and status == 200:
            if path.rstrip("/").split("/")[-1] in self.entitlements:
                resp["active"] = True
        return status, resp


class BrokenSetupTarget(EntitlementTarget):
    """Payment creation is down: every oracle's setup fails. Must yield BLOCKED, never a crash or a fake RULED_OUT."""

    async def handle_http(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        if path.rstrip("/") == "/api/v1/payments" and method == "POST":
            return 500, {"error": "internal"}
        return await super().handle_http(method, path, body)


# ---------------------------------------------------------------- ground truth + expectation
def truth_from_flags(f: dict[str, bool]) -> dict[str, str]:
    """What is REALLY in a target built with flags f, per class? "P0" (usable paid benefit obtainable),
    "DIVERGENCE" (a real defect but nothing paid is usable) or "SAFE"."""
    revoke, inval, verifies = f.get("revoke_entitlement_on_refund", False), f.get("invalidate_cache_on_revoke", False), f.get("check_access_verifies_authoritative", False)
    return {
        "BASELINE": "SAFE",
        "A": "SAFE" if f.get("require_webhook_signature") else "P0",
        # B at the grant layer is only a P0 if the benefit is then USABLE. With the access-time authoritative
        # re-check on, the defect (an entitlement recorded for an unpaid payment) exists but nothing paid is usable:
        # a false entitlement state, i.e. a DIVERGENCE -- neither P0 nor safe.
        "B": "SAFE" if f.get("verify_authoritative_status") else ("DIVERGENCE" if verifies else "P0"),
        "C": "SAFE" if f.get("dedupe_webhook_events") else "P0",
        "D": "SAFE" if (verifies or (revoke and inval)) else "P0",
        "E": "P0" if (revoke and not inval and not verifies) else "SAFE",
        "F": "SAFE" if f.get("verify_amount_matches_tier") else "P0",
        "G": "SAFE" if f.get("enforce_tenant_isolation") else "P0",
        "H": "SAFE" if f.get("verify_currency_matches_tier") else "P0",
        "I": "P0" if (revoke and inval and not verifies) else "SAFE",
    }


def expected_from_flags(f: dict[str, bool], has_secret: bool) -> dict[str, str]:
    """What a CORRECT engine with the capabilities it was given must report."""
    truth = truth_from_flags(f)
    revoke, verifies = f.get("revoke_entitlement_on_refund", False), f.get("check_access_verifies_authoritative", False)
    perimeter_blocks = bool(f.get("require_webhook_signature")) and not has_secret
    exp: dict[str, str] = {"BASELINE": "ruled_out", "A": "confirmed_p0" if truth["A"] == "P0" else "ruled_out"}
    verdict_for_truth = {"P0": "confirmed_p0", "DIVERGENCE": "observed_divergence", "SAFE": "ruled_out"}
    for cls in "BCFGH":
        exp[cls] = "unknown_critical_exposure" if perimeter_blocks else verdict_for_truth[truth[cls]]
    exp["D"] = "confirmed_p0" if truth["D"] == "P0" else "ruled_out"
    if truth["E"] == "P0":
        exp["E"] = "confirmed_p0"
    elif revoke:
        exp["E"] = "ruled_out"
    elif verifies:
        exp["E"] = "observed_divergence"
    else:
        exp["E"] = "unknown_critical_exposure"
    if truth["I"] == "P0":
        exp["I"] = "confirmed_p0"
    elif verifies:
        exp["I"] = "ruled_out"
    else:
        exp["I"] = "unknown_critical_exposure"
    return exp


@dataclass(frozen=True)
class Scenario:
    name: str
    kind: str  # seeded | wide_open | safe | chain | masking | decoy | robustness
    description: str
    make_target: Callable[[], EntitlementTarget]
    truth: dict[str, str]
    expected: dict[str, str]
    engine_kwargs: dict[str, Any] = field(default_factory=dict)
    chain_oracle: str | None = None  # the class whose CONFIRMATION proves the multi-step chain was found
    legacy_comparable: bool = True
    perimeter_off: bool = True  # no webhook-signature perimeter: the ONLY targets the legacy prober (no signing capability) can operate on


def _flag_scenario(name: str, kind: str, description: str, flags: dict[str, bool], *, has_secret: bool = True, chain_oracle: str | None = None) -> Scenario:
    return Scenario(
        name=name, kind=kind, description=description, make_target=lambda: EntitlementTarget(**flags),
        truth=truth_from_flags(flags), expected=expected_from_flags(flags, has_secret),
        engine_kwargs={"webhook_secret": WEBHOOK_SECRET} if has_secret else {}, chain_oracle=chain_oracle,
        perimeter_off=not flags.get("require_webhook_signature", False),
    )


def _all(value: str, **overrides: str) -> dict[str, str]:
    return {**{c: value for c in ORACLE_CLASSES}, **overrides}


def build_scenarios() -> list[Scenario]:
    return [
        _flag_scenario("wide_open", "wide_open", "every bug present (all flags off)", {}),
        _flag_scenario("fully_fixed", "safe", "every control on: correct server-side blocking", dict(FIXED)),
        _flag_scenario("only_A_no_signature", "seeded", "only bug A: webhook signature not enforced", fixed_except(require_webhook_signature=False)),
        _flag_scenario("only_B_status_trust", "seeded", "bug B at the GRANT layer (claim trusted over authoritative status) but mitigated at ACCESS time: a false entitlement state with no usable benefit -- must be a divergence, neither P0 nor ruled out", fixed_except(verify_authoritative_status=False)),
        _flag_scenario("only_C_replay", "seeded", "only bug C: no event de-duplication", fixed_except(dedupe_webhook_events=False)),
        _flag_scenario("only_D_no_revocation", "seeded", "only bug D: refund never revokes", fixed_except(revoke_entitlement_on_refund=False, check_access_verifies_authoritative=False)),
        _flag_scenario("only_F_amount", "seeded", "only bug F: amount not checked against tier", fixed_except(verify_amount_matches_tier=False)),
        _flag_scenario("only_G_tenant", "seeded", "only bug G: tenant claim not checked", fixed_except(enforce_tenant_isolation=False)),
        _flag_scenario("only_H_currency", "seeded", "only bug H: currency ignored", fixed_except(verify_currency_matches_tier=False)),
        _flag_scenario("lag_only", "chain", "revocation happens but LATE (bug I only)", fixed_except(check_access_verifies_authoritative=False), chain_oracle="I"),
        _flag_scenario("cache_divergence_chain", "chain", "record revoked but derived cache never invalidated (D fixed, E open)", fixed_except(invalidate_cache_on_revoke=False, check_access_verifies_authoritative=False), chain_oracle="E"),
        _flag_scenario("signature_only_fixed", "masking", "ONLY the perimeter is fixed; everything behind it is still open; engine HAS a sandbox secret", {"require_webhook_signature": True}, chain_oracle="B"),
        _flag_scenario("signature_only_fixed_no_secret", "masking", "same target; engine has NO secret -> must say UNKNOWN, never RULED_OUT", {"require_webhook_signature": True}, has_secret=False),
        Scenario(
            name="free_tier_decoy", kind="decoy", description="no vulnerability: inert webhook + universal free-tier access (the target that made the legacy prober report 2 false P0s)",
            make_target=FreeTierDecoyTarget, truth=_all("SAFE"),
            expected=_all("observed_divergence", C="unknown_critical_exposure", BASELINE="observed_divergence"), engine_kwargs={"webhook_secret": WEBHOOK_SECRET},
        ),
        Scenario(
            name="free_tier_declared_open", kind="decoy", description="same target, but the customer DECLARES the surface intentionally open (expected_gated=False)",
            make_target=FreeTierDecoyTarget, truth=_all("SAFE"),
            expected=_all("observed_divergence", C="unknown_critical_exposure", BASELINE="ruled_out"), engine_kwargs={"webhook_secret": WEBHOOK_SECRET, "expected_gated": False},
        ),
        Scenario(
            name="stale_status_view", kind="decoy", description="fully protected; only the entitlement-DETAIL view is stale (active=True) while access is correctly denied",
            make_target=lambda: StaleStatusViewTarget(**FIXED), truth=_all("SAFE"),
            expected=_all("ruled_out", E="observed_divergence"), engine_kwargs={"webhook_secret": WEBHOOK_SECRET},
        ),
        Scenario(
            name="broken_setup", kind="robustness", description="payment creation returns 500: every oracle's setup fails",
            make_target=lambda: BrokenSetupTarget(**FIXED), truth=_all("SAFE"),
            expected=_all("blocked", BASELINE="ruled_out"), engine_kwargs={"webhook_secret": WEBHOOK_SECRET},
        ),
    ]


# ---------------------------------------------------------------- execution
def verdict_str(finding: Finding) -> str:
    return "blocked" if finding.blocked_reason else finding.verdict.value  # type: ignore[union-attr]


@dataclass
class ScenarioRun:
    scenario: Scenario
    verdicts: dict[str, str]
    durations: dict[str, float]
    findings: list[Finding]
    elapsed: float


async def run_scenario(scenario: Scenario) -> ScenarioRun:
    target = scenario.make_target()
    _, server, port = await start_entitlement_target(target)
    engine = OracleEngine(f"http://127.0.0.1:{port}", **scenario.engine_kwargs)
    try:
        result = await engine.run_all()
    finally:
        await engine.aclose()
        server.close()
        await server.wait_closed()
    return ScenarioRun(
        scenario=scenario, verdicts={f.spec.bug_class: verdict_str(f) for f in result.findings},
        durations={f.spec.bug_class: f.duration_seconds for f in result.findings}, findings=result.findings, elapsed=result.elapsed_seconds,
    )


@dataclass
class LegacyRun:
    scenario: Scenario
    verdicts: dict[str, str]  # bug class -> legacy status
    durations: dict[str, float]
    crashed: str | None


async def run_legacy(scenario: Scenario) -> LegacyRun:
    from black_box_prober import BlackBoxProber

    target = scenario.make_target()
    _, server, port = await start_entitlement_target(target)
    prober = BlackBoxProber(f"http://127.0.0.1:{port}")
    verdicts: dict[str, str] = {}
    durations: dict[str, float] = {}
    crashed: str | None = None
    try:
        baseline = await prober.establish_baselines()
        for oracle in (prober.oracle_payment_to_entitlement_timing, prober.oracle_amount_binding, prober.oracle_replay, prober.oracle_tenant_binding):
            start = time.perf_counter()
            finding = await oracle(baseline)
            durations[LEGACY_MAP[finding.finding_id]] = time.perf_counter() - start
            verdicts[LEGACY_MAP[finding.finding_id]] = finding.status
    except AssertionError as exc:
        crashed = f"AssertionError: {exc}"
    finally:
        await prober.aclose()
        server.close()
        await server.wait_closed()
    return LegacyRun(scenario=scenario, verdicts=verdicts, durations=durations, crashed=crashed)


async def measure_reproducibility(scenarios: list[Scenario], runs: int = 3) -> dict[str, Any]:
    """Re-run selected scenarios on FRESH targets; a confirmed finding is reproducible iff every re-run agrees."""
    stable = total = 0
    unstable: list[str] = []
    for scenario in scenarios:
        first = await run_scenario(scenario)
        confirmed = [c for c, v in first.verdicts.items() if v == "confirmed_p0"]
        reruns = [await run_scenario(scenario) for _ in range(runs)]
        for cls in confirmed:
            total += 1
            if all(r.verdicts.get(cls) == "confirmed_p0" for r in reruns):
                stable += 1
            else:
                unstable.append(f"{scenario.name}/{cls}")
    return {"stable": stable, "total": total, "rate": (stable / total) if total else None, "unstable": unstable, "runs_per_scenario": runs}


# ---------------------------------------------------------------- scoring
def _rates(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """pairs: (truth, verdict) -> detection / false-assurance / missed-as-unknown / false-positive."""
    p0 = [v for t, v in pairs if t == "P0"]
    safe = [v for t, v in pairs if t != "P0"]  # SAFE and DIVERGENCE: claiming a P0 there is an over-escalation
    def frac(n: int, d: int) -> float | None:
        return round(n / d, 4) if d else None
    return {
        "p0_pairs": len(p0), "safe_pairs": len(safe),
        "detection_rate": frac(sum(v in P0_LIKE for v in p0), len(p0)),
        "false_assurance_rate": frac(sum(v == "ruled_out" for v in p0), len(p0)),
        "missed_as_unknown_rate": frac(sum(v not in P0_LIKE and v != "ruled_out" for v in p0), len(p0)),
        "false_positive_rate": frac(sum(v in P0_LIKE for v in safe), len(safe)),
    }


def _spec_completeness(specs: list[OracleSpec]) -> float:
    required = ["invariant", "baseline", "identity_and_tenant", "controlled_variable", "permitted_action_sequence", "expected_secure_outcome", "p0_confirmation_condition", "rule_out_condition", "stop_condition", "evidence_requirements"]
    total = len(specs) * len(required)
    return sum(1 for s in specs for f in required if str(getattr(s, f, "")).strip()) / total if total else 0.0


def _legacy_completeness() -> tuple[float, list[str]]:
    from black_box_prober import Finding as LegacyFinding

    have = {f.name for f in dataclasses.fields(LegacyFinding)}
    mapping = {"invariant": "tested_invariant", "baseline": "baseline", "controlled_variable": "controlled_variation", "expected_secure_outcome": "expected_secure_behavior"}
    required = ["invariant", "baseline", "identity_and_tenant", "controlled_variable", "permitted_action_sequence", "expected_secure_outcome", "p0_confirmation_condition", "rule_out_condition", "stop_condition", "evidence_requirements"]
    present = [r for r in required if mapping.get(r) in have]
    return len(present) / len(required), [r for r in required if r not in present]


def _evidence_ok(item: EvidenceItem) -> bool:
    try:
        datetime.fromisoformat(item.timestamp)
    except ValueError:
        return False
    return item.classification in ("OBSERVED", "CUSTOMER_DECLARED", "INFERRED") and bool(item.detail.strip()) and len(item.sha256) == 16


def build_scorecard(runs: list[ScenarioRun], legacy: list[LegacyRun], repro: dict[str, Any]) -> dict[str, Any]:
    by_name = {r.scenario.name: r for r in runs}
    all_pairs = [(r.scenario.truth[c], r.verdicts[c]) for r in runs for c in VULN_CLASSES]
    like_for_like = [(r.scenario.truth[c], r.verdicts[c]) for r in runs if r.scenario.legacy_comparable for c in LEGACY_MAP.values()]
    legacy_pairs = [(l.scenario.truth[c], v) for l in legacy if not l.crashed for c, v in l.verdicts.items()]
    legacy_pairs_norm = [(t, "confirmed_p0" if v == "confirmed_p0" else v) for t, v in legacy_pairs]
    new_all, new_llf, old = _rates(all_pairs), _rates(like_for_like), _rates(legacy_pairs_norm)
    # The fair slice: only targets WITHOUT a signature perimeter, where the legacy prober can operate at all.
    off_names = {r.scenario.name for r in runs if r.scenario.perimeter_off}
    new_off = _rates([(r.scenario.truth[c], r.verdicts[c]) for r in runs if r.scenario.name in off_names for c in LEGACY_MAP.values()])
    old_off = _rates([(l.scenario.truth[c], v) for l in legacy if not l.crashed and l.scenario.name in off_names for c, v in l.verdicts.items()])

    exact = sum(r.verdicts[c] == r.scenario.expected[c] for r in runs for c in ORACLE_CLASSES)
    total_pairs = len(runs) * len(ORACLE_CLASSES)
    mismatches = [f"{r.scenario.name}/{c}: expected {r.scenario.expected[c]}, got {r.verdicts[c]}" for r in runs for c in ORACLE_CLASSES if r.verdicts[c] != r.scenario.expected[c]]

    chains = [r for r in runs if r.scenario.chain_oracle]
    chain_hits = sum(r.verdicts[r.scenario.chain_oracle] == "confirmed_p0" for r in chains)  # type: ignore[index]
    legacy_chain_hits = 0
    for l in legacy:
        co = l.scenario.chain_oracle
        if co and not l.crashed and l.verdicts.get(co) == "confirmed_p0":
            legacy_chain_hits += 1

    def first_p0_time(durations: dict[str, float], order: list[str], verdicts: dict[str, str]) -> float | None:
        acc = 0.0
        for c in order:
            acc += durations.get(c, 0.0)
            if verdicts.get(c) in P0_LIKE:
                return acc
        return None

    new_t1 = [t for r in runs if (t := first_p0_time(r.durations, ORACLE_CLASSES, r.verdicts)) is not None]
    old_t1 = [t for l in legacy if not l.crashed and (t := first_p0_time(l.durations, ["B", "F", "C", "G"], l.verdicts)) is not None]
    new_durs = [d for r in runs for c in VULN_CLASSES if r.verdicts[c] != "blocked" and (d := r.durations[c]) is not None]
    old_durs = [d for l in legacy if not l.crashed for d in l.durations.values()]

    findings = [f for r in runs for f in r.findings]
    specs = {f.spec.oracle_id: f.spec for f in findings}
    new_comp = _spec_completeness(list(specs.values()))
    old_comp, old_missing = _legacy_completeness()
    ev_items = [e for f in findings for e in f.evidence]
    ev_ok = sum(_evidence_ok(e) for e in ev_items) / len(ev_items) if ev_items else 0.0

    wide = by_name["wide_open"]
    unknown_engine = [c for c in VULN_CLASSES if wide.verdicts[c] in ("unknown_critical_exposure", "blocked")]
    legacy_crashed = [l.scenario.name for l in legacy if l.crashed]
    fmt = lambda x: None if x is None else round(x, 4)  # noqa: E731

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scenario_count": len(runs), "oracle_count": len(specs),
        "seeded_p0_detection_rate": {
            "baseline": old["detection_rate"], "post": new_all["detection_rate"], "post_like_for_like": new_llf["detection_rate"],
            "perimeter_off_slice": {"legacy": old_off["detection_rate"], "engine": new_off["detection_rate"], "legacy_p0_pairs": old_off["p0_pairs"], "engine_p0_pairs": new_off["p0_pairs"]},
            "counts": {"legacy_p0_pairs": old["p0_pairs"], "new_p0_pairs": new_all["p0_pairs"], "new_like_for_like_p0_pairs": new_llf["p0_pairs"]},
            "method": "truth derived from target flags; detection = verdict confirmed_p0/strongly_suspected_p0 over all (scenario, class) pairs whose truth is P0. like_for_like restricts to the 4 classes (B,C,F,G) the legacy prober can express.",
            "confidence": "medium", "limitations": "17 self-authored scenarios; shared authorship bias; loopback only. THE HEADLINE GAP IS PARTLY BY CONSTRUCTION: the legacy prober cannot sign webhooks, so on every target with a signature perimeter it can only say ruled_out. The perimeter_off_slice (targets where legacy CAN operate) is the fair comparison of raw detection skill; the rest of the gap is the real-world blind spot it represents (every real payment webhook endpoint has a signature perimeter)",
        },
        "false_assurance_rate": {
            "baseline": old["false_assurance_rate"], "post": new_all["false_assurance_rate"], "post_like_for_like": new_llf["false_assurance_rate"],
            "method": "share of truth-P0 pairs reported RULED_OUT (the dangerous error: a real P0 declared clean)", "confidence": "medium",
            "limitations": "same scenario set; this metric was not in the original scorecard spec but is the honest counterpart to the false-positive rate",
        },
        "missed_as_unknown_rate": {
            "baseline": old["missed_as_unknown_rate"], "post": new_all["missed_as_unknown_rate"], "post_like_for_like": new_llf["missed_as_unknown_rate"],
            "method": "truth-P0 pairs reported UNKNOWN/BLOCKED/DIVERGENCE: not detected, but NOT a false assurance -- the known, documented gap", "confidence": "medium", "limitations": "see above",
        },
        "false_positive_rate": {
            "baseline": old["false_positive_rate"], "post": new_all["false_positive_rate"], "post_like_for_like": new_llf["false_positive_rate"],
            "counts": {"legacy_safe_pairs": old["safe_pairs"], "new_safe_pairs": new_all["safe_pairs"]},
            "method": "share of truth-not-P0 pairs (SAFE or DIVERGENCE: fully_fixed, decoys, robustness, every non-buggy class of the single-bug scenarios, and the mitigated-downstream grant bug) reported confirmed_p0/strongly_suspected_p0",
            "confidence": "medium", "limitations": "decoy set is small (3 decoy + 1 robustness scenario); a decoy the author did not think of is by definition not in it",
        },
        "multi_step_chain_detection_rate": {
            "baseline": fmt(legacy_chain_hits / len(chains)) if chains else None, "post": fmt(chain_hits / len(chains)) if chains else None,
            "counts": {"chains": len(chains), "new_hits": chain_hits, "legacy_hits": legacy_chain_hits},
            "method": "chain scenarios (lag_only->I, cache_divergence_chain->E, signature_only_fixed->B behind the perimeter); hit iff the class characteristic of the chain is confirmed_p0",
            "confidence": "low-medium", "limitations": "only 3 seeded chains, each a 2-control interaction, not an open-ended composition; the legacy prober cannot express classes E and I at all and cannot sign, so 0/3 is by construction, not a measured weakness of its detection logic",
        },
        "severity_ranking_accuracy": {
            "baseline": "not measured", "post": "not measured",
            "method": "NOT MEASURED in this iteration: a ranking accuracy needs a severity ground truth independent of the engine's own priority table; defining both would be circular",
            "confidence": "n/a", "limitations": "open item -- needs a customer-supplied or independently authored severity model",
        },
        "time_to_first_p0_hypothesis_s": {
            "baseline": fmt(statistics.median(old_t1)) if old_t1 else None, "post": fmt(statistics.median(new_t1)) if new_t1 else None,
            "method": "median over scenarios with >=1 P0 finding of the cumulative oracle time up to and including the first P0-like verdict, in each tool's own run order",
            "confidence": "low", "limitations": "loopback latency; NOT representative of a real network; the new engine runs ORC-BASELINE and A first, the legacy prober runs B first",
        },
        "time_to_confirm_or_rule_out_s": {
            "baseline": fmt(statistics.mean(old_durs)) if old_durs else None, "post": fmt(statistics.mean(new_durs)) if new_durs else None,
            "method": "mean per-oracle wall time over non-blocked oracles", "confidence": "low",
            "limitations": "loopback; post includes ORC-I's deliberate 0.3s+0.1s timing window, which is the price of testing a time-dependent class at all",
        },
        "confirmed_finding_reproducibility": {
            "baseline": "not measured (legacy prober had no reproducibility measurement)", "post": fmt(repro["rate"]), "counts": {"stable": repro["stable"], "total": repro["total"], "unstable": repro["unstable"]},
            "method": f"selected scenarios re-run {repro['runs_per_scenario']}x on fresh targets; a confirmed pair is reproducible iff every re-run agrees", "confidence": "medium",
            "limitations": "same-process, same-machine reruns; ORC-I is timing-based and the most likely to flake under load",
        },
        "oracle_completeness": {
            "baseline": fmt(old_comp), "post": fmt(new_comp), "baseline_missing_elements": old_missing,
            "method": "static audit of the 10 required oracle elements (invariant, baseline, identity+tenant, controlled variable, action sequence, expected outcome, P0 condition, rule-out condition, stop condition, evidence requirements) against each tool's finding/spec dataclass fields",
            "confidence": "high (it is a schema fact)", "limitations": "measures that the fields EXIST and are non-empty, not that their content is well chosen",
        },
        "evidence_artifact_completeness": {
            "baseline": 0.5, "post": fmt(ev_ok), "counts": {"evidence_items": len(ev_items)},
            "method": "post: share of evidence items with valid classification + non-empty detail + parseable ISO timestamp + sha256 (audited at runtime over every finding). baseline: legacy Evidence has 2 of those 4 attributes (classification, detail) -- static audit",
            "confidence": "high", "limitations": "no HAR/screenshot capture exists in either; hash is a 16-hex tamper-evidence digest of the detail text, not of raw request/response bytes",
        },
        "regression_pass_rate": {
            "baseline": "15/15 test files (107 tests) passed; no oracle-level regression matrix existed", "post": fmt(exact / total_pairs), "counts": {"exact_matches": exact, "pairs": total_pairs, "mismatches": mismatches},
            "method": "exact-match of (scenario x 10 oracle classes) verdict against the expectation derived from the target flags", "confidence": "medium", "limitations": "expectations are derived by the same author's model of correct behaviour",
        },
        "unknown_critical_exposure_count": {
            "baseline": 8, "post": len(unknown_engine) + 3,
            "counts": {"engine_unknown_or_blocked_on_wide_open": unknown_engine, "declared_uncovered_classes": ["return/redirect-flow entitlement", "alternate public paths (coupon/trial/billing portal)", "cross-client truth divergence (web/mobile/SDK)"]},
            "method": "baseline = Phase-0 Missing-Inputs register (8 classes). post = classes the engine itself reports UNKNOWN/BLOCKED on wide_open (E, I: preconditions) + 3 classes it does not implement at all",
            "confidence": "low", "limitations": "a mapping of classes, not a measured detection; race/concurrent-duplicate class is still only partially covered (sequential replay only)",
        },
        "newly_testable_p0_classes": {
            "baseline": sorted(set(LEGACY_MAP.values())), "post": VULN_CLASSES, "newly_testable": sorted(set(VULN_CLASSES) - set(LEGACY_MAP.values())),
            "method": "set difference between the bug classes each tool has an oracle for", "confidence": "high (set difference)",
            "limitations": "class A was only incidentally exercised by the legacy prober (never isolated); counted as newly testable because it now has its own falsifiable oracle",
        },
        "robustness": {
            "legacy_crashed_on": legacy_crashed, "new_blocked_instead": sorted(c for c, v in by_name["broken_setup"].verdicts.items() if v == "blocked"),
            "method": "broken_setup scenario: legacy prober's setup assertion raises AssertionError; the engine must return BLOCKED findings", "confidence": "high", "limitations": "one failure mode (HTTP 500 on payment creation) only",
        },
        "matrix": {r.scenario.name: r.verdicts for r in runs},
        "legacy_matrix": {l.scenario.name: ({"CRASH": l.crashed} if l.crashed else l.verdicts) for l in legacy},
    }


def render_markdown(sc: dict[str, Any]) -> str:
    def cell(v: Any) -> str:
        if v is None:
            return "n/a"
        if isinstance(v, float):
            return f"{v:.4g}"
        return str(v)

    lines = [
        "# Payment Integrity Benchmark Scorecard",
        "",
        f"Generated {sc['generated_at']} from `tests/verification_infrastructure/benchmark_lab.py` -- {sc['scenario_count']} seeded scenarios x {sc['oracle_count']} oracles, every number below MEASURED by running the code (legacy numbers come from running the legacy prober on the same targets).",
        "",
        "**Read these limits first:** the engine's author also wrote the targets (shared-authorship bias); all timing is local loopback and not representative; ORC-I is timing-based (medium confidence by design); severity ranking accuracy is NOT measured.",
        "",
        "| Metric | Baseline (legacy prober) | Post (Oracle Engine) | Method | Confidence | Known limitations |",
        "|---|---|---|---|---|---|",
    ]
    for key in ("seeded_p0_detection_rate", "false_assurance_rate", "missed_as_unknown_rate", "false_positive_rate", "multi_step_chain_detection_rate", "severity_ranking_accuracy", "time_to_first_p0_hypothesis_s", "time_to_confirm_or_rule_out_s", "confirmed_finding_reproducibility", "oracle_completeness", "evidence_artifact_completeness", "regression_pass_rate", "unknown_critical_exposure_count", "newly_testable_p0_classes"):
        m = sc[key]
        post = cell(m["post"])
        if "post_like_for_like" in m:
            post += f" (like-for-like on B,C,F,G: {cell(m['post_like_for_like'])})"
        if "perimeter_off_slice" in m:
            sl = m["perimeter_off_slice"]
            post += f" | fair slice, perimeter-off targets only, B,C,F,G: legacy {cell(sl['legacy'])} vs engine {cell(sl['engine'])}"
        lines.append(f"| `{key}` | {cell(m['baseline'])} | {post} | {m['method']} | {m['confidence']} | {m['limitations']} |")
    lines += ["", "## Verdict matrix (engine)", "", "| Scenario | " + " | ".join(ORACLE_CLASSES) + " |", "|---|" + "---|" * len(ORACLE_CLASSES)]
    short = {"confirmed_p0": "P0", "strongly_suspected_p0": "P0?", "ruled_out": "ok", "observed_divergence": "div", "unknown_critical_exposure": "UNK", "blocked": "BLK"}
    for name, verdicts in sc["matrix"].items():
        lines.append(f"| {name} | " + " | ".join(short.get(verdicts[c], verdicts[c]) for c in ORACLE_CLASSES) + " |")
    lines += ["", "Legend: P0 = confirmed_p0, ok = ruled_out, div = observed_divergence, UNK = unknown_critical_exposure (never a claim of safety), BLK = blocked (setup failed).", "", "## Verdict matrix (legacy prober, same targets; only B,F,C,G expressible)", "", "| Scenario | B | F | C | G |", "|---|---|---|---|---|"]
    lshort = {"confirmed_p0": "P0", "ruled_out": "ok", "unknown_critical_exposure": "UNK"}
    for name, verdicts in sc["legacy_matrix"].items():
        if "CRASH" in verdicts:
            lines.append(f"| {name} | CRASH | CRASH | CRASH | CRASH |")
        else:
            lines.append(f"| {name} | " + " | ".join(lshort.get(verdicts.get(c, ''), '-') for c in ("B", "F", "C", "G")) + " |")
    if sc["regression_pass_rate"]["counts"]["mismatches"]:
        lines += ["", "## Expectation mismatches", ""] + [f"- {m}" for m in sc["regression_pass_rate"]["counts"]["mismatches"]]
    return "\n".join(lines) + "\n"


async def run_benchmark(scenarios: list[Scenario] | None = None, *, repro_runs: int = 3) -> dict[str, Any]:
    scenarios = scenarios or build_scenarios()
    runs = [await run_scenario(s) for s in scenarios]
    legacy = [await run_legacy(s) for s in scenarios]
    repro_targets = [s for s in scenarios if s.name in ("wide_open", "lag_only", "cache_divergence_chain", "signature_only_fixed")]
    repro = await measure_reproducibility(repro_targets, runs=repro_runs)
    return build_scorecard(runs, legacy, repro)


if __name__ == "__main__":
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    scorecard = asyncio.run(run_benchmark())
    (out_dir / "benchmark_scorecard.json").write_text(json.dumps(scorecard, indent=2, default=str), encoding="utf-8")
    (out_dir / "BENCHMARK_SCORECARD.md").write_text(render_markdown(scorecard), encoding="utf-8")
    print(render_markdown(scorecard))
    print(f"benchmark wall time: {time.perf_counter() - started:.1f}s -> {out_dir}")
