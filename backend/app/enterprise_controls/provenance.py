"""Evidence admission (mandate: 'Evidence-source provenance', 'Fail closed').

Every evidence artifact carries its origin: source type, authorised identity alias, tenant alias, target, timestamp, session
isolation id, authorisation reference, redaction status, an integrity hash and one of five EXTERNAL classifications. The
``EvidenceLedger`` is the only door into findings, scoring and reports: an artifact with internal, privileged, unknown or
unverifiable provenance is REJECTED (recorded with the exact reason) and can never support a verdict. Stdlib only.

The record types (EvidenceProvenance, EvidenceArtifact, build_artifact, compute_integrity_hash, now_iso) live in
``app.core.control_port.contract`` (K5): they are data construction the engine needs even when this component is unavailable.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, Iterable

from app.core.control_port.contract import (
    EvidenceArtifact, EvidenceClass, EvidenceProvenance, ProvenanceRejected, Reason, build_artifact, canonical_json as _canonical, compute_integrity_hash, now_iso,
)  # noqa: F401  (record types are re-exported for the control layer's own tests)
from app.enterprise_controls.access_gate import AccessGate
from app.enterprise_controls.allowlists import INTERNAL_PROVENANCE_MARKERS
from app.enterprise_controls.blindness import find_internal_fields

logger = logging.getLogger("qa.evidence_ledger")

PersistArtifactFn = Callable[[EvidenceArtifact], Awaitable[None]]


async def _noop_persist_artifact(artifact: EvidenceArtifact) -> None:
    """Default: do nothing, same as this module's behaviour before this fix.
    Every existing EvidenceLedger(...) call site keeps working unchanged --
    only a caller that explicitly supplies persist_artifact opts in, same
    backward-compatibility shape as runner.py's _noop_persist_result."""
    return None
from app.testing.purity.taxonomy import TruthLabel

_REQUIRED_FIELDS = ("source_type", "classification", "identity_alias", "target", "timestamp", "session_isolation_id", "authorization_ref", "redaction_status", "integrity_hash", "truth_label")


class EvidenceLedger:
    """Admission control + store for evidence. Rejections are recorded, never raised past ``try_admit`` silently."""

    def __init__(self, *, authorization_ref: str, access_gate: AccessGate | None = None, approved_identity_aliases: Iterable[str] = (),
                 approved_tenant_aliases: Iterable[str] = (), persist_artifact: PersistArtifactFn | None = None) -> None:
        self.authorization_ref = authorization_ref
        self._gate = access_gate or AccessGate()
        self._identities = set(approved_identity_aliases)
        self._tenants = set(approved_tenant_aliases)
        self._protected: set[str] = set()
        self.accepted: dict[str, EvidenceArtifact] = {}
        self.rejected: list[dict[str, Any]] = []
        self._persist_artifact: PersistArtifactFn = persist_artifact or _noop_persist_artifact
        self._pending_persist: list[EvidenceArtifact] = []
        # ZR-009: artifact ids admitted to self.accepted (so still usable
        # within this run -- the oracle_gate condition this supports stays
        # intact either way) but NOT confirmed durable. Same visibility
        # pattern as runner.py's persist_failures / api/v1/runs.py's
        # summary["persistence_failures"].
        self.persist_failures: list[str] = []

    def protect(self, *values: str) -> None:
        """Register raw sensitive values (tokens, payment/tenant ids). An artifact whose payload still contains one is REJECTED (fail closed)."""
        for v in values:
            if isinstance(v, str) and len(v) >= 4:
                self._protected.add(v)

    def register_identity(self, alias: str, tenant_alias: str | None = None) -> None:
        self._identities.add(alias)
        if tenant_alias:
            self._tenants.add(tenant_alias)

    def validate(self, artifact: EvidenceArtifact | None) -> list[Reason]:
        if artifact is None or artifact.provenance is None:
            return [Reason("provenance_missing", "artifact", "evidence without provenance is never admitted")]
        p, reasons = artifact.provenance, []
        for name in _REQUIRED_FIELDS:
            if not isinstance(getattr(p, name, None), str) or not getattr(p, name).strip():
                reasons.append(Reason("provenance_field_missing", f"provenance.{name}", "required provenance field is empty"))
        cls = (p.classification or "").strip().lower()
        if cls not in {c.value for c in EvidenceClass}:
            internal = cls in INTERNAL_PROVENANCE_MARKERS or any(m in cls for m in ("internal", "privileged", "admin", "database", "log", "dashboard", "ground_truth"))
            reasons.append(Reason("provenance_internal_source" if internal else "provenance_classification_invalid", "provenance.classification",
                                  f"classification {p.classification!r} is not one of the five external classifications"))
        if p.truth_label not in {t.value for t in TruthLabel}:
            reasons.append(Reason("provenance_truth_label_invalid", "provenance.truth_label", f"unknown truth label {p.truth_label!r}"))
        if p.identity_alias and self._identities and p.identity_alias not in self._identities:
            reasons.append(Reason("provenance_identity_unapproved", "provenance.identity_alias", f"identity alias {p.identity_alias!r} is not an approved synthetic identity"))
        if p.tenant_alias and self._tenants and p.tenant_alias not in self._tenants:
            reasons.append(Reason("provenance_tenant_unapproved", "provenance.tenant_alias", f"tenant alias {p.tenant_alias!r} is not an approved synthetic tenant"))
        if p.authorization_ref and p.authorization_ref != self.authorization_ref:
            reasons.append(Reason("provenance_authorization_mismatch", "provenance.authorization_ref", "authorization reference does not match the run's Execution Brief"))
        try:
            datetime.fromisoformat(p.timestamp)
        except (TypeError, ValueError):
            reasons.append(Reason("provenance_timestamp_invalid", "provenance.timestamp", "timestamp is not ISO-8601"))
        if p.redaction_status not in ("redacted", "not_required"):
            reasons.append(Reason("provenance_redaction_missing", "provenance.redaction_status", "redaction status must be 'redacted' or 'not_required'"))
        if p.integrity_hash and compute_integrity_hash(artifact.payload, p.hash_inputs()) != p.integrity_hash:
            reasons.append(Reason("provenance_hash_mismatch", "provenance.integrity_hash", "artifact content does not match its integrity hash (tampered or incomplete)"))
        if p.target and not self._gate.check(p.target, count=False).allowed:
            reasons.append(Reason("provenance_target_not_customer_facing", "provenance.target", "target is not a customer-facing surface"))
        if self._protected:
            text = _canonical(artifact.payload)
            if any(raw in text for raw in self._protected):
                reasons.append(Reason("provenance_unredacted_sensitive_value", "payload", "payload still contains a registered sensitive value (token / payment id / tenant id): redaction failed, artifact not admitted"))
        internal_fields = find_internal_fields(artifact.payload)
        if internal_fields:
            reasons.append(Reason("provenance_internal_field_present", "payload", f"payload still contains internal/hint fields {internal_fields[:3]}"))
        return reasons

    def try_admit(self, artifact: EvidenceArtifact | None) -> tuple[bool, list[Reason]]:
        reasons = self.validate(artifact)
        if reasons:
            self.rejected.append({"artifact_id": getattr(artifact, "artifact_id", None), "reasons": [r.__dict__ for r in reasons]})
            return False, reasons
        assert artifact is not None
        self.accepted[artifact.artifact_id] = artifact
        self._pending_persist.append(artifact)
        return True, []

    async def flush_pending(self) -> None:
        """ZR-009: write every artifact admitted since the last flush through
        to durable storage. Callers should call this periodically during a
        run (PureBlackBoxEngine.run() calls it after every experiment, not
        only once at the end) so a mid-run crash only loses what was never
        flushed, not everything the run collected -- the same "durable as it
        happens, not batched to the end" property runner.py's
        _persist_one_result already has for TestResults. Never raises: a
        failure here is logged and recorded in persist_failures, and the
        artifact stays usable via self.accepted for the rest of this run
        either way.
        """
        pending, self._pending_persist = self._pending_persist, []
        for artifact in pending:
            try:
                await self._persist_artifact(artifact)
            except Exception:
                logger.exception("Failed to write-through evidence artifact %s -- kept in self.accepted only", artifact.artifact_id)
                self.persist_failures.append(artifact.artifact_id)

    def admit(self, artifact: EvidenceArtifact | None) -> EvidenceArtifact:
        ok, reasons = self.try_admit(artifact)
        if not ok:
            raise ProvenanceRejected(reasons)
        assert artifact is not None
        return artifact

    def is_admitted(self, artifact_id: str) -> bool:
        return artifact_id in self.accepted

    def ids(self) -> list[str]:
        return list(self.accepted)

    def summary(self) -> dict[str, Any]:
        by_class: dict[str, int] = {}
        for a in self.accepted.values():
            by_class[a.provenance.classification] = by_class.get(a.provenance.classification, 0) + 1  # type: ignore[union-attr]
        return {"accepted": len(self.accepted), "rejected": len(self.rejected), "accepted_by_classification": by_class,
                "rejected_reasons": sorted({r["code"] for rej in self.rejected for r in rej["reasons"]})}
