"""Independent post-run scorer. It is the ONLY place where engine output meets ground truth, and it runs after the engine has finished.

Pair outcome classes (truth x verdict):
  truth P0  : CONFIRMED_P0 -> TP | RULED_OUT -> FALSE_ASSURANCE (dangerous) | anything else -> MISSED_AS_UNKNOWN (honest gap)
  truth SAFE: CONFIRMED_P0 -> FP | RULED_OUT -> TN | anything else -> INCONCLUSIVE_ON_SAFE
  truth UNK : CONFIRMED_P0 -> FP | RULED_OUT -> FALSE_ASSURANCE_UNPROVABLE (claimed safe where nothing external can prove it) | else HONEST_UNKNOWN
  truth DIV : CONFIRMED_P0 -> FP | RULED_OUT/PARTIALLY_VALIDATED with a reported divergence -> DIV_OK | otherwise DIV_MISSED
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, Iterable

from app.testing.integrity.findings import SPECS
from app.core.control_port import compute_integrity_hash
from purity_benchmark.lab import ScenarioRun
from purity_benchmark.scenarios import EXPERIMENTS

NOT_CLAIMED = {"CONFIRMED_P0": False}
UNKNOWN_CLASS = {"UNKNOWN", "BLOCKED", "PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE", "SUSPECTED_PAYMENT_INTEGRITY_ISSUE"}


@dataclass(frozen=True)
class Pair:
    scenario: str
    hypothesis: str
    truth: str
    verdict: str
    outcome: str
    divergences: int


def classify(truth: str, verdict: str, divergences: int) -> str:
    p0 = verdict == "CONFIRMED_P0"
    if truth == "P0":
        return "TP" if p0 else "FALSE_ASSURANCE" if verdict == "RULED_OUT" else "MISSED_AS_UNKNOWN"
    if truth == "SAFE":
        return "FP" if p0 else "TN" if verdict == "RULED_OUT" else "INCONCLUSIVE_ON_SAFE"
    if truth == "UNK":
        return "FP" if p0 else "FALSE_ASSURANCE_UNPROVABLE" if verdict == "RULED_OUT" else "HONEST_UNKNOWN"
    if truth == "DIV":
        if p0:
            return "FP"
        return "DIV_OK" if verdict in ("RULED_OUT", "PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE") and divergences > 0 else "DIV_MISSED"
    raise ValueError(f"unknown truth {truth!r}")


AUX = {"PBB-OPEN": ("UNK", "paid feature open to unpaid identities: confirmation pattern not executable -> never CONFIRMED"), "PBB-LEAK": ("P0", "entitlement leaks to an unrelated identity")}


def pairs_for(run: ScenarioRun) -> list[Pair]:
    by_id = run.result.by_id()
    out: list[Pair] = []
    expected_aux = {"PBB-OPEN": run.scenario.expects_open_finding, "PBB-LEAK": run.scenario.expects_leak_finding}
    for aux, (truth, _) in AUX.items():  # auxiliary findings: expected exactly where the scenario seeds them; an unexpected one counts against the engine
        f = by_id.get(aux)
        if expected_aux[aux]:
            verdict = f.verdict.value if f else "MISSING"
            out.append(Pair(run.scenario.name, aux, truth, verdict, classify(truth, verdict, len(f.divergences) if f else 0) if f else ("MISSED_AS_UNKNOWN" if truth == "P0" else "HONEST_UNKNOWN"), 0))
        elif f is not None:
            out.append(Pair(run.scenario.name, aux, "SAFE", f.verdict.value, classify("SAFE", f.verdict.value, 0), 0))
    for hyp in EXPERIMENTS:
        f = by_id.get(hyp)
        verdict = f.verdict.value if f else "MISSING"
        div = len(f.divergences) if f else 0
        out.append(Pair(run.scenario.name, hyp, run.scenario.truth[hyp], verdict, classify(run.scenario.truth[hyp], verdict, div) if f else "MISSING", div))
    return out


def _rate(num: int, den: int) -> float | None:
    return None if den == 0 else round(num / den, 4)


_EXTERNAL = {"external_browser", "external_customer_api", "external_notification", "approved_sandbox_payment", "controlled_black_box_benchmark"}
_SECRET_SHAPES = ("tok_", "pay_", "Bearer ", "ten_")  # token / raw payment id / bearer header / raw tenant id formats of the benchmark target


def evidence_integrity(run: ScenarioRun) -> dict[str, Any]:
    """Independent re-verification of every admitted artifact: hash recomputed from scratch, five-class provenance, required fields, redaction of the target's
    token/payment/tenant id formats (the scorer knows the formats; the engine does not)."""
    import json as _json

    from app.core.control_port import compute_integrity_hash

    accepted = list(run.ledger.accepted.values()) if run.ledger is not None else []
    bad_hash = bad_class = bad_fields = leaked = 0
    for art in accepted:
        p = art.provenance
        if p is None or compute_integrity_hash(art.payload, p.hash_inputs()) != p.integrity_hash:
            bad_hash += 1
        if p is None or p.classification not in _EXTERNAL:
            bad_class += 1
        if p is None or not all(getattr(p, f) for f in ("source_type", "identity_alias", "target", "timestamp", "session_isolation_id", "authorization_ref", "redaction_status", "integrity_hash")):
            bad_fields += 1
        text = _json.dumps(art.payload)
        if any(shape in text for shape in _SECRET_SHAPES):
            leaked += 1
    return {"artifacts": len(accepted), "bad_hash": bad_hash, "bad_classification": bad_class, "missing_provenance_fields": bad_fields, "unredacted_identifiers_or_tokens": leaked}


def score(runs: Iterable[ScenarioRun]) -> dict[str, Any]:
    runs = list(runs)
    pairs = [p for r in runs for p in pairs_for(r)]
    n = lambda *names: sum(1 for p in pairs if p.outcome in names)  # noqa: E731
    truth = lambda t: sum(1 for p in pairs if p.truth == t)  # noqa: E731
    p0, safe, unk, div = truth("P0"), truth("SAFE"), truth("UNK"), truth("DIV")
    hint_runs = [r for r in runs if r.scenario.emits_hints]
    all_artifacts_ok = all(r.result.ledger_summary["rejected"] == 0 and r.result.ledger_summary["accepted"] > 0 for r in runs if r.result.ledger_summary["accepted"] > 0 or r.result.stats["customer_level_calls"] > 0)
    purity_denials = sum((r.result.stats.get("guard") or {}).get("purity_gate", {}).get("denied", 0) for r in runs)
    spec_complete = sum(s.completeness() for s in SPECS.values()) / len(SPECS)
    return {
        "scenarios": len(runs), "pairs": len(pairs),
        "truth_counts": {"P0": p0, "SAFE": safe, "UNK": unk, "DIV": div},
        "outcome_counts": {k: n(k) for k in ("TP", "FALSE_ASSURANCE", "MISSED_AS_UNKNOWN", "FP", "TN", "INCONCLUSIVE_ON_SAFE", "FALSE_ASSURANCE_UNPROVABLE", "HONEST_UNKNOWN", "DIV_OK", "DIV_MISSED")},
        "seeded_p0_detection_rate": _rate(n("TP"), p0),
        "false_positive_rate": _rate(n("FP"), safe + unk + div),
        "false_assurance_rate": _rate(n("FALSE_ASSURANCE", "FALSE_ASSURANCE_UNPROVABLE"), p0 + unk),
        "missed_as_unknown_rate": _rate(n("MISSED_AS_UNKNOWN"), p0),
        "unknown_honesty_rate": _rate(n("HONEST_UNKNOWN"), unk),
        "safe_ruled_out_rate": _rate(n("TN"), safe),
        "ui_only_false_positive_resistance": _rate(n("DIV_OK"), div),
        "confirmed_p0_without_external_oracle": 0,  # unconstructible (Finding.__post_init__); verified by tests/test_purity_enforcement.py
        "internal_route_hits_total": sum(r.internal_hits for r in runs),
        "scenarios_with_internal_route_hits": sum(1 for r in runs if r.internal_hits),
        "hint_scenarios": len(hint_runs), "hint_scenarios_where_hints_were_present_and_dropped": sum(1 for r in hint_runs if r.result.stats["volunteered_hints_dropped"] > 0),
        "purity_gate_denials_caused_by_engine": purity_denials,
        "evidence_rejected_total": sum(r.result.ledger_summary["rejected"] for r in runs),
        "evidence_accepted_total": sum(r.result.ledger_summary["accepted"] for r in runs),
        "every_artifact_externally_classified": all_artifacts_ok,
        "customer_level_calls_total": sum(r.result.stats["customer_level_calls"] for r in runs),
        "oracle_spec_completeness": round(spec_complete, 4),
        "blindness_checks_total": sum(r.blindness_checks for r in runs),
        "blind_spot_flaws_total": sum(len(r.scenario.unprobed_flaws) for r in runs),
        "blind_spot_flaws_detected": 0,  # no experiment models them; reporting 0 is the point (see blind_spot_flaws_listed_as_gap)
        "blind_spot_flaws_listed_as_gap": sum(len(r.scenario.unprobed_flaws) for r in runs if r.brief is not None and _lifecycle_gap_blocked(r)),
        "evidence_integrity": _sum_integrity(runs),
        "pairs_detail": [dataclasses.asdict(p) for p in pairs],
    }


def _lifecycle_gap_blocked(run: ScenarioRun) -> bool:
    from app.testing.integrity.gaps import capability_gaps
    from app.testing.purity.taxonomy import Coverage

    return any(g.p0_class == "lifecycle_trial_coupon_renewal_expiry_downgrade" and g.coverage == Coverage.BLOCKED for g in capability_gaps(run.brief, run.result))


def _sum_integrity(runs: Iterable[ScenarioRun]) -> dict[str, int]:
    total: dict[str, int] = {}
    for r in runs:
        for k, v in evidence_integrity(r).items():
            total[k] = total.get(k, 0) + v
    return total


def metamorphic_equal(a: ScenarioRun, b: ScenarioRun) -> tuple[bool, list[str]]:
    """Two runs that differ only in benchmark-environment noise (hints on/off) must yield identical verdicts."""
    va, vb = a.result.verdicts(), b.result.verdicts()
    diffs = [f"{k}: {va.get(k)} vs {vb.get(k)}" for k in sorted(set(va) | set(vb)) if va.get(k) != vb.get(k)]
    return not diffs, diffs
