"""ZR-034 (Section 15.1): the Standard Engagement Completion Report.

The spec fixes the format as seven sections -- Summary, Requirements Matrix,
Implemented Changes, Coverage, Findings, Verification, Not-Implemented -- owned
by A15 and generated at the end of every engagement (distinct from the external
per-CONFIRMED_P0 disclosure report). All seven are different renderings of ONE
source of truth -- the EngineResult, its findings (ZR-019 schema), the coverage
report (ZR-006/ZR-022) and the regression spec (ZR-023) -- never independently
maintained documents that can drift.

The `not_implemented` section is mandated by the format itself: "no confirmed
P0" never means "no P0 exists", so every UNKNOWN/BLOCKED experiment and every
pure-black-box-impossible class is listed here with the input that would unlock
it -- the report cannot present a clean engagement by omission.

Stdlib only; pure (reads a finished EngineResult -- no engine/httpx import)."""
from __future__ import annotations

from typing import Any

from app.core.control_port.contract import now_iso
from app.testing.integrity.findings import EXPERIMENT_CLASSES, EngineResult
from app.testing.integrity.gaps import coverage_report
from app.testing.purity.taxonomy import Verdict

COMPLETION_REPORT_VERSION = "engagement-completion-report/1.0"
SECTIONS = ("summary", "requirements_matrix", "implemented_changes", "coverage", "findings", "verification", "not_implemented")

_PURITY_ATTESTATION = {
    "source_code_used": False, "repository_access_used": False, "database_access_used": False, "server_log_access_used": False,
    "admin_or_privileged_access_used": False, "internal_api_access_used": False, "payment_provider_dashboard_used": False,
    "real_customer_data_used": False, "external_evidence_only": True, "internal_causal_claims_made": False,
}


def _engagement_status(findings: list[Any]) -> str:
    if any(f.verdict == Verdict.CONFIRMED_P0 for f in findings):
        return "P0_CONFIRMED"
    if findings and all(f.verdict == Verdict.RULED_OUT and not getattr(f, "divergences", None) for f in findings):
        return "CLEAN"
    return "INCOMPLETE"  # at least one experiment did not reach a conclusive, divergence-free RULED_OUT


def _finding_row(f: Any) -> dict[str, Any]:
    return {
        "hypothesis_id": f.hypothesis_id, "p0_class": f.p0_class, "title": f.title, "verdict": f.verdict.value,
        "confidence": f.confidence, "priority": f.priority, "affected_flow": f.affected_flow,
        "reproduction_status": f.reproduction_status, "reproduction_steps": f.reproduction_steps,
        "regression_test_reference": f.regression_test_reference, "schema_completeness": round(f.schema_completeness(), 4),
        "summary": f.summary,
    }


def build_completion_report(result: EngineResult, brief: Any | None = None) -> dict[str, Any]:
    """Assemble the seven-section report from one EngineResult (+ optional brief
    for fingerprint/authorization context). Nothing is inferred; every figure is
    read from the finished run."""
    findings = list(result.findings)
    by_id = result.by_id()
    confirmed = [f for f in findings if f.verdict == Verdict.CONFIRMED_P0]
    cov = coverage_report(brief, result)
    class_coverage = {c["experiments"][0]: c["coverage"] for c in (cov["coverage_matrix"] or {}).get("cells", [])
                      if c["dimension"] == "hypothesis_class" and c["experiments"]}
    verdict_tally: dict[str, int] = {}
    for f in findings:
        verdict_tally[f.verdict.value] = verdict_tally.get(f.verdict.value, 0) + 1

    authorization_ref = getattr(brief, "authorization_ref", None)
    if authorization_ref is None:
        authorization_ref = next((b.get("authorization_ref") for b in result.replay_bundles.values()), None)

    requirements_matrix = []
    for hyp, p0_class in EXPERIMENT_CLASSES.items():
        f = by_id.get(hyp)
        requirements_matrix.append({
            "p0_class": p0_class, "experiment": hyp, "tested": f is not None,
            "verdict": f.verdict.value if f is not None else "NOT_RUN",
            "coverage": class_coverage.get(hyp, "NOT_RUN"),
            "regression_test_reference": getattr(f, "regression_test_reference", None) if f is not None else None,
        })

    not_implemented = [
        {"experiment": f.hypothesis_id, "p0_class": f.p0_class, "verdict": f.verdict.value, "why": f.summary,
         "reasons": list(f.reasons)}
        for f in findings if f.verdict in (Verdict.UNKNOWN, Verdict.BLOCKED)
    ]
    # plus the classes a pure black-box tester structurally cannot reach (from the gap register)
    not_implemented += [
        {"experiment": None, "p0_class": g["p0_class"], "verdict": g["coverage"], "why": g["reason"],
         "required_input": g["required_input"]}
        for g in cov["capability_gaps"] if g["coverage"] == "BLOCKED" and g["experiment"] is None
    ]

    return {
        "report_type": "engagement_completion_report",
        "format_version": COMPLETION_REPORT_VERSION,
        "engine_version": result.engine_version,
        "generated_at": now_iso(),
        "summary": {
            "status": _engagement_status(findings),
            "confirmed_p0": len(confirmed),
            "findings_total": len(findings),
            "verdict_tally": dict(sorted(verdict_tally.items())),
            "brief_fingerprint": result.brief_fingerprint,
            "authorization_ref": authorization_ref,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "headline": ("At least one payment-integrity P0 was CONFIRMED with external proof."
                         if confirmed else "No P0 was confirmed in this run; see Not-Implemented for what was NOT establishable."),
        },
        "requirements_matrix": requirements_matrix,
        "implemented_changes": {
            "note": "For a QA engagement these are the experiments executed and flows exercised this run (not source changes).",
            "experiments_executed": list(result.stats.get("experiment_order", [f.hypothesis_id for f in findings])),
            "flows_exercised": sorted({f.affected_flow for f in findings if f.affected_flow}),
            "synthetic_identities_used": result.stats.get("synthetic_identities_used", []),
        },
        "coverage": cov,
        "findings": [_finding_row(f) for f in findings],
        "verification": {
            "black_box_purity_attestation": dict(_PURITY_ATTESTATION),
            "controls": result.controls,
            "evidence_ledger": result.ledger_summary,
            "replay_bundles_available": sorted(result.replay_bundles.keys()),
            "note": "Every CONFIRMED_P0 carries an oracle token + admitted evidence; reproduction_steps + a replay bundle accompany each finding with cited evidence.",
        },
        "not_implemented": not_implemented,
    }


def completion_report_markdown(report: dict[str, Any]) -> str:
    """Render the structured report as Markdown (the human-facing delivery artifact)."""
    s = report["summary"]
    out = [f"# Engagement Completion Report", f"_{report['format_version']} · {report['engine_version']} · generated {report['generated_at']}_", ""]
    out += ["## Summary", f"- **Status:** {s['status']}", f"- **Confirmed P0:** {s['confirmed_p0']} of {s['findings_total']} findings",
            f"- **Verdict tally:** {s['verdict_tally']}", f"- **Brief fingerprint:** {s['brief_fingerprint']}",
            f"- **Authorization:** {s['authorization_ref']}", f"- {s['headline']}", ""]
    out += ["## Requirements Matrix", "| P0 class | Experiment | Tested | Verdict | Coverage |", "|---|---|---|---|---|"]
    out += [f"| {r['p0_class']} | {r['experiment']} | {'yes' if r['tested'] else 'no'} | {r['verdict']} | {r['coverage']} |" for r in report["requirements_matrix"]]
    ic = report["implemented_changes"]
    out += ["", "## Implemented Changes", f"- _{ic['note']}_", f"- Experiments executed: {ic['experiments_executed']}", f"- Flows exercised: {ic['flows_exercised']}", ""]
    cm = report["coverage"].get("coverage_matrix")
    out += ["## Coverage", f"- Verdict tally: {cm['verdict_tally'] if cm else 'n/a'}",
            f"- P0 classes covered: {report['coverage']['summary']['p0_classes_covered']} / {report['coverage']['summary']['p0_classes_total']}",
            f"- Uncovered cells: {len(cm['uncovered']) if cm else 'n/a'}", ""]
    out += ["## Findings"]
    for f in report["findings"]:
        out.append(f"- **[{f['verdict']}] {f['hypothesis_id']}** ({f['p0_class']}) — {f['title']}; regression={f['regression_test_reference']}; schema={f['schema_completeness']}")
    v = report["verification"]
    out += ["", "## Verification", f"- External evidence only: {v['black_box_purity_attestation']['external_evidence_only']}",
            f"- Replay bundles available: {v['replay_bundles_available']}", f"- {v['note']}", ""]
    out += ["## Not-Implemented (never 'passed' by omission)"]
    if report["not_implemented"]:
        out += [f"- **{n['p0_class']}** ({n.get('experiment') or 'structural'}): {n['verdict']} — {n['why']}" for n in report["not_implemented"]]
    else:
        out.append("- Every targeted class reached a conclusive verdict this run.")
    return "\n".join(out)
