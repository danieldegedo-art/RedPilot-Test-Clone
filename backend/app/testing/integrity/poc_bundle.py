"""PoC Bundle -- one developer-ready proof-of-concept per finding.

XBOW-style delivery standard: every finding ships with (1) the evidence it rests
on, (2) a replayable request/response path, (3) a proof-of-impact statement, and
(4) remediation guidance. This module assembles those four from what RedPilot
already produces for each finding -- the ZR-019 finding schema, the ZR-015 replay
bundle (reproduction steps + admitted request/response artifacts), and the
evidence ledger -- into one portable, JSON-safe object plus a Markdown rendering
a developer can act on.

It INVENTS nothing. Every field is read from the finished finding/bundle; absent
data is reported as absent (a non-CONFIRMED verdict asserts no impact; a class
with no fix template says so), never fabricated -- an honest PoC is the whole
point of the differential-oracle method. Only artifact field NAMES and provenance
are surfaced for the request/response path, never payload VALUES: the replay
bundle already carries the (ledger-redacted) bodies, and a PoC meant to be shared
should leak nothing the ledger would have rejected.

Scope: packaging/presentation only. It issues no traffic, consults no oracle, and
adds no capability -- purely a reshaping of a finished run's own evidence.
Duck-typed on the finding (reads attributes; no Finding import) so it stays
unit-testable in isolation, exactly like replay.build_replay_bundle.

Stdlib only; pure and deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

POC_BUNDLE_VERSION = "poc-bundle/1.0"


def _request_response_path(replay_bundle: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """The ordered request/response path from the replay bundle's admitted
    artifacts: provenance + payload FIELD NAMES only (never values -- the full,
    ledger-redacted bodies live in the replay bundle itself)."""
    if not replay_bundle:
        return []
    out: list[dict[str, Any]] = []
    for art in replay_bundle.get("artifacts", []):
        prov = art.get("provenance") or {}
        payload = art.get("payload") or {}
        out.append({
            "artifact_id": art.get("artifact_id"),
            "source_type": prov.get("source_type"),
            "classification": prov.get("classification"),
            "target": prov.get("target"),
            "redaction_status": prov.get("redaction_status"),
            "integrity_hash": (prov.get("integrity_hash") or "")[:12],
            "payload_fields": sorted(payload.keys()),  # NAMES only, never values
        })
    return out


@dataclass(frozen=True)
class PoCBundle:
    """A portable, JSON-safe, developer-ready PoC for ONE finding."""

    hypothesis_id: str
    p0_class: str
    title: str
    verdict: str
    confidence: str
    evidence: dict[str, Any]
    replayable_path: dict[str, Any]
    proof_of_impact: dict[str, Any]
    remediation: dict[str, Any]
    version: str = POC_BUNDLE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "hypothesis_id": self.hypothesis_id, "p0_class": self.p0_class,
            "title": self.title, "verdict": self.verdict, "confidence": self.confidence,
            "evidence": self.evidence, "replayable_path": self.replayable_path,
            "proof_of_impact": self.proof_of_impact, "remediation": self.remediation,
        }

    def to_markdown(self) -> str:
        e, rp, pi, rem = self.evidence, self.replayable_path, self.proof_of_impact, self.remediation
        out = [f"## PoC — {self.hypothesis_id}: {self.title}",
               f"**Verdict:** {self.verdict}  ·  **confidence:** {self.confidence}  ·  **class:** {self.p0_class}", ""]
        out += ["### 1. Evidence",
                f"- artifacts cited: {e['artifact_count']} ({', '.join(e['artifact_ids']) or 'none'})",
                f"- evidence-DAG completeness: {e['evidence_dag_completeness']}  ·  schema completeness: {e['schema_completeness']}",
                f"- confirmation token present (independently reproduced): {e['confirmation_token_present']}"]
        if e["missing_artifact_ids"]:
            out.append(f"- NOTE: cited-but-unbundled artifacts (recorded, never reconstructed): {e['missing_artifact_ids']}")
        out += ["", "### 2. Replayable request/response path", f"- reproduction status: {rp['reproduction_status']}"]
        if rp["request_response_path"]:
            for i, step in enumerate(rp["request_response_path"], start=1):
                out.append(f"  {i}. {step['source_type']} [{step['classification']}] @ {step['target']} "
                           f"(redaction {step['redaction_status']}, hash {step['integrity_hash']}); fields: {step['payload_fields']}")
        else:
            out.append("  - (no cited request/response artifacts to replay)")
        if rp["steps"]:
            out += ["", "  Reproduction steps:"] + [f"  - {s}" for s in rp["steps"]]
        out += ["", "### 3. Proof of impact", f"- {pi['note']}"]
        if pi["impact"]:
            out.append(f"- impact: {pi['impact']}")
        out += [f"- server-side oracle: {pi['server_side_oracle']}",
                f"- expected vs actual: {pi['expected_state']} → {pi['actual_state']}",
                f"- payment state: {pi['payment_state']}  ·  entitlement state: {pi['entitlement_state']}"]
        if pi["divergences"]:
            out.append(f"- divergences: {pi['divergences']}")
        if pi["metrics"]:
            out.append(f"- metrics: {pi['metrics']}")
        out += ["", "### 4. Remediation"]
        out.append(f"- recommended fix: {rem['recommended_fix']}" if rem["available"]
                   else "- no fix template registered for this class; see the finding summary and affected flow.")
        out += [f"- affected flow: {rem['affected_flow']}",
                f"- regression test reference: {rem['regression_test_reference']}"]
        return "\n".join(out)


def build_poc_bundle(finding: Any, replay_bundle: Mapping[str, Any] | None = None) -> PoCBundle:
    """Assemble the PoC bundle for one finding (+ its replay bundle dict, if any,
    from ``EngineResult.replay_bundles[hypothesis_id]``). Duck-typed on the
    finding, so it needs no import of the Finding type."""
    confirmed = getattr(finding, "token", None) is not None
    repro_steps = finding.reproduction_steps
    if isinstance(repro_steps, str) and repro_steps:
        steps: Sequence[str] = repro_steps.splitlines()
    else:
        steps = list((replay_bundle or {}).get("reproduction_steps", []))

    evidence = {
        "artifact_ids": list(finding.artifact_ids),
        "artifact_count": len(finding.artifact_ids),
        "evidence_dag_completeness": (replay_bundle or {}).get("graph", {}).get("completeness"),
        "missing_artifact_ids": list((replay_bundle or {}).get("missing_artifact_ids", [])),
        "schema_completeness": round(finding.schema_completeness(), 4),
        "confirmation_token_present": confirmed,
    }
    replayable_path = {
        "reproduction_status": finding.reproduction_status,
        "steps": list(steps),
        "request_response_path": _request_response_path(replay_bundle),
    }
    proof_of_impact = {
        "verdict": finding.verdict.value,
        "impact": finding.impact,
        "server_side_oracle": finding.server_side_oracle,
        "expected_state": finding.expected_state,
        "actual_state": finding.actual_state,
        "payment_state": finding.payment_state,
        "entitlement_state": finding.entitlement_state,
        "divergences": list(finding.divergences),
        "metrics": dict(finding.metrics or {}),
        "independently_reproduced": confirmed,
        "note": ("Server-side-verified and independently reproduced (confirmation token issued)." if confirmed
                 else f"Not a confirmed P0 (verdict {finding.verdict.value}); no impact is asserted."),
    }
    remediation = {
        "recommended_fix": finding.recommended_fix,
        "affected_flow": finding.affected_flow,
        "precondition": list(finding.precondition) if finding.precondition else [],
        "effect": list(finding.effect) if finding.effect else [],
        "regression_test_reference": finding.regression_test_reference,
        "available": finding.recommended_fix is not None,
    }
    return PoCBundle(
        hypothesis_id=finding.hypothesis_id, p0_class=getattr(finding, "p0_class", ""), title=getattr(finding, "title", ""),
        verdict=finding.verdict.value, confidence=getattr(finding, "confidence", ""),
        evidence=evidence, replayable_path=replayable_path, proof_of_impact=proof_of_impact, remediation=remediation,
    )


def build_poc_bundles(result: Any) -> dict[str, dict[str, Any]]:
    """One PoC bundle per finding in a finished EngineResult, keyed by hypothesis
    id, each pairing the finding with its replay bundle (if one was built)."""
    bundles = getattr(result, "replay_bundles", {}) or {}
    return {f.hypothesis_id: build_poc_bundle(f, bundles.get(f.hypothesis_id)).to_dict() for f in result.findings}


def poc_bundles_markdown(result: Any) -> str:
    """All PoC bundles for a run rendered as one Markdown document."""
    bundles = getattr(result, "replay_bundles", {}) or {}
    parts = ["# Proof-of-Concept Bundles", f"_{POC_BUNDLE_VERSION} · {len(result.findings)} finding(s)_", ""]
    for f in result.findings:
        parts.append(build_poc_bundle(f, bundles.get(f.hypothesis_id)).to_markdown())
        parts.append("")
    return "\n".join(parts)
