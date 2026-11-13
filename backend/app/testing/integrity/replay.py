"""ZR-015 / B20 (reproduction half): Replay Bundles -- "full reproducibility
from stored evidence".

B20's PERSISTENCE half is already closed (ZR-009: TestResult write-through +
EvidenceLedger.flush_pending). This module adds the REPRODUCTION half: one
portable object that lets an authorized reviewer re-examine and re-run a
finding from stored evidence alone, without access to the original live target.

A ReplayBundle for a single finding carries:
  * the finding's identity + verdict + the p0_class it tested,
  * its evidence DAG (evidence_graph_for_finding -> to_dict: nodes, edges,
    topological order, completeness), and
  * the actual admitted artifact BODIES (EvidenceArtifact.to_dict()) for every
    request/response node, IN THE GRAPH'S TOPOLOGICAL ORDER, plus the oracle
    observations the finding cites.

Purity: only artifacts already ADMITTED to the EvidenceLedger are bundled --
they have passed provenance + redaction + protected-value + internal-field
checks, so a bundle can carry no secret or internal value the ledger would have
rejected. A cited artifact that is NOT in the ledger is recorded in
``missing_artifact_ids``, never fabricated.

Every bundled artifact keeps its provenance integrity hash, so ``verify()``
recomputes it from the bundled payload+provenance and reports tampering or
storage corruption. ``reproduction_steps()`` renders the ordered,
human-readable procedure that fills ``Finding.reproduction_steps`` (ZR-019's
last field that was deferred pending this capability).

Stdlib only; pure and deterministic (ordered/sorted), so a bundle can ride
inside a persisted finding/result row via ZR-009's write-through -- no
separate store is required for the reproduction half.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from app.core.control_port.contract import compute_integrity_hash
from app.testing.integrity.evidence_graph import artifact_timestamps_from_ledger, evidence_graph_for_finding

logger = logging.getLogger("qa.integrity.replay")

BUNDLE_VERSION = "replay-bundle/1.0"
_RR_PREFIX = "rr:"  # EvidenceGraph node-id prefix for request/response (artifact) nodes


@dataclass(frozen=True)
class ReplayBundle:
    """A self-contained, portable, JSON-safe reproduction package for ONE finding."""

    hypothesis_id: str
    p0_class: str
    verdict: str
    engine_version: str
    brief_fingerprint: str
    authorization_ref: str
    graph: dict[str, Any]              # evidence_graph_for_finding(...).to_dict()
    artifacts: list[dict[str, Any]]    # EvidenceArtifact.to_dict(), request/response nodes in topological order
    observations: list[dict[str, Any]]  # OracleObservation.to_dict() cited by this finding, sorted by oracle_id
    missing_artifact_ids: list[str] = field(default_factory=list)
    version: str = BUNDLE_VERSION

    def reproduction_steps(self) -> list[str]:
        """Ordered, human-readable replay procedure, derived ONLY from stored
        evidence (never invented). Artifact payload VALUES are not inlined
        here -- the full bodies live in ``self.artifacts`` -- only field names
        and provenance, which keeps this concise and leaks nothing the ledger
        did not already admit."""
        steps: list[str] = [
            f"Authorized black-box replay of {self.hypothesis_id} ({self.p0_class}); verdict at capture: {self.verdict}.",
            f"Preconditions: fresh synthetic identity (no stored cookies/tokens), same environment class, "
            f"brief fingerprint {self.brief_fingerprint}, authorization ref {self.authorization_ref}.",
        ]
        for i, art in enumerate(self.artifacts, start=1):
            prov = art.get("provenance") or {}
            payload_fields = sorted((art.get("payload") or {}).keys())
            steps.append(
                f"{i}. replay {prov.get('source_type', '?')} [{prov.get('classification', '?')}] at {prov.get('target', '?')} "
                f"(session {str(prov.get('session_isolation_id', ''))[:8]}, {prov.get('redaction_status', '?')}, "
                f"hash {str(prov.get('integrity_hash', ''))[:10]}); payload fields: {payload_fields}"
            )
        for obs in self.observations:
            steps.append(
                f"observed: feature {obs.get('feature_id')} for identity {obs.get('identity_alias')} "
                f"-> {obs.get('outcome')} (oracle {obs.get('oracle_id')}, proof_present={obs.get('proof_present')})"
            )
        g = self.graph
        steps.append(
            f"evidence DAG: {len(g.get('nodes', []))} nodes, {len(g.get('edges', []))} edges, "
            f"completeness {g.get('completeness')}; full bodies + edges attached in this {self.version}."
        )
        if self.missing_artifact_ids:
            steps.append(
                f"NOTE: {len(self.missing_artifact_ids)} cited artifact(s) were not in the evidence ledger "
                f"and could not be bundled (recorded, not reconstructed): {self.missing_artifact_ids}"
            )
        return steps

    def reproduction_text(self) -> str:
        return "\n".join(self.reproduction_steps())

    def verify(self) -> list[str]:
        """Recompute every bundled artifact's integrity hash from its own
        bundled payload + provenance and compare with the stored hash. Returns
        a list of problems; empty means the bundle is internally intact (not
        tampered with / not corrupted in storage)."""
        problems: list[str] = []
        for art in self.artifacts:
            aid = art.get("artifact_id")
            prov = art.get("provenance")
            if not prov:
                problems.append(f"{aid}: artifact has no provenance")
                continue
            stored = prov.get("integrity_hash") or ""
            hash_inputs = {k: v for k, v in prov.items() if k not in ("integrity_hash", "truth_label")}
            recomputed = compute_integrity_hash(art.get("payload"), hash_inputs)
            if recomputed != stored:
                problems.append(f"{aid}: integrity hash mismatch (stored {stored[:10]}..., recomputed {recomputed[:10]}...)")
        return problems

    def integrity_ok(self) -> bool:
        return not self.verify()

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "hypothesis_id": self.hypothesis_id, "p0_class": self.p0_class, "verdict": self.verdict,
            "engine_version": self.engine_version, "brief_fingerprint": self.brief_fingerprint, "authorization_ref": self.authorization_ref,
            "graph": self.graph, "artifacts": self.artifacts, "observations": self.observations,
            "missing_artifact_ids": list(self.missing_artifact_ids), "reproduction_steps": self.reproduction_steps(),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ReplayBundle":
        """Rebuild from to_dict(). The derived ``reproduction_steps`` key is
        ignored on load (recomputed), so from_dict(b.to_dict()).to_dict() ==
        b.to_dict()."""
        return cls(
            hypothesis_id=d["hypothesis_id"], p0_class=d.get("p0_class", ""), verdict=d["verdict"],
            engine_version=d.get("engine_version", ""), brief_fingerprint=d.get("brief_fingerprint", ""),
            authorization_ref=d.get("authorization_ref", ""), graph=dict(d.get("graph", {})),
            artifacts=list(d.get("artifacts", [])), observations=list(d.get("observations", [])),
            missing_artifact_ids=list(d.get("missing_artifact_ids", [])), version=d.get("version", BUNDLE_VERSION),
        )


def _relevant_observations(finding_artifact_ids: Iterable[str], observations: Iterable[Any]) -> list[Any]:
    cited = set(finding_artifact_ids)
    return [o for o in observations if cited & set(getattr(o, "artifact_ids", ()))]


def build_replay_bundle(
    finding: Any, *, ledger_accepted: Mapping[str, Any], observations: Iterable[Any], admission_order: Sequence[str],
    brief_fingerprint: str, authorization_ref: str, engine_version: str,
) -> ReplayBundle:
    """Assemble the replay bundle for one finding from already-collected,
    already-admitted evidence. Duck-typed on the finding (``hypothesis_id``,
    ``p0_class``, ``verdict.value``, ``artifact_ids``) so it needs no import of
    the Finding type and stays unit-testable in isolation."""
    observations = list(observations)
    artifact_ts = artifact_timestamps_from_ledger(ledger_accepted)
    graph = evidence_graph_for_finding(
        finding.hypothesis_id, finding.artifact_ids, observations=observations,
        admission_order=admission_order, artifact_timestamps=artifact_ts,
    )
    graph_dict = graph.to_dict()

    artifacts: list[dict[str, Any]] = []
    missing: list[str] = []
    for node_id in graph_dict["order"]:
        if not node_id.startswith(_RR_PREFIX):
            continue  # oracle_result / state_transition nodes carry no stand-alone body to replay
        aid = node_id[len(_RR_PREFIX):]
        art = ledger_accepted.get(aid)
        if art is None:
            missing.append(aid)  # cited but never admitted -- recorded, never reconstructed
            continue
        artifacts.append(art.to_dict())

    relevant = _relevant_observations(finding.artifact_ids, observations)
    obs_dicts = sorted((o.to_dict() for o in relevant), key=lambda d: d.get("oracle_id", ""))

    return ReplayBundle(
        hypothesis_id=finding.hypothesis_id, p0_class=getattr(finding, "p0_class", ""), verdict=finding.verdict.value,
        engine_version=engine_version, brief_fingerprint=brief_fingerprint, authorization_ref=authorization_ref,
        graph=graph_dict, artifacts=artifacts, observations=obs_dicts, missing_artifact_ids=sorted(set(missing)),
    )


def attach_replay_bundles(
    findings: Iterable[Any], *, ledger_accepted: Mapping[str, Any], observations: Iterable[Any], admission_order: Sequence[str],
    brief_fingerprint: str, authorization_ref: str, engine_version: str,
) -> dict[str, dict[str, Any]]:
    """Build a replay bundle for every finding that CITES evidence, set that
    finding's ``reproduction_steps`` from the bundle (closing ZR-019's last
    deferred field), and return the bundles keyed by hypothesis id.

    A finding with no cited artifacts has nothing to reproduce, so its
    ``reproduction_steps`` is left None -- honest, not a fabricated step list.
    Best-effort per finding: a failure on one finding is logged loudly and
    leaves that finding untouched, never taking a completed run down (the same
    per-item isolation the engine applies to experiments)."""
    observations = list(observations)
    bundles: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not getattr(finding, "artifact_ids", None):
            continue
        try:
            bundle = build_replay_bundle(
                finding, ledger_accepted=ledger_accepted, observations=observations, admission_order=admission_order,
                brief_fingerprint=brief_fingerprint, authorization_ref=authorization_ref, engine_version=engine_version,
            )
            finding.reproduction_steps = bundle.reproduction_text()
            bundles[finding.hypothesis_id] = bundle.to_dict()
        except Exception:  # noqa: BLE001 - reproduction packaging must never take a completed run down
            logger.exception("replay bundle for %r could not be built; leaving reproduction_steps unset", getattr(finding, "hypothesis_id", "?"))
    return bundles
