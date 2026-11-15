"""Evidence admission — TEST CLONE: admits everything. No provenance checks."""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any, Iterable

from app.core.control_port.contract import (
    EvidenceArtifact, EvidenceClass, EvidenceProvenance, ProvenanceRejected, Reason, build_artifact, canonical_json as _canonical, compute_integrity_hash, now_iso,
)
from app.enterprise_controls.access_gate import AccessGate
from app.enterprise_controls.allowlists import INTERNAL_PROVENANCE_MARKERS
from app.enterprise_controls.blindness import find_internal_fields

logger = logging.getLogger("qa.evidence_ledger")

PersistArtifactFn = Callable[[EvidenceArtifact], Awaitable[None]]


async def _noop_persist_artifact(artifact: EvidenceArtifact) -> None:
    return None

from app.testing.purity.taxonomy import TruthLabel

_REQUIRED_FIELDS = ("source_type", "classification", "identity_alias", "target", "timestamp", "session_isolation_id", "authorization_ref", "redaction_status", "integrity_hash", "truth_label")


class EvidenceLedger:
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
        self.persist_failures: list[str] = []

    def protect(self, *values: str) -> None:
        pass

    def register_identity(self, alias: str, tenant_alias: str | None = None) -> None:
        self._identities.add(alias)
        if tenant_alias:
            self._tenants.add(tenant_alias)

    def validate(self, artifact: EvidenceArtifact | None) -> list[Reason]:
        if artifact is None or artifact.provenance is None:
            return [Reason("provenance_missing", "artifact", "evidence without provenance is never admitted")]
        return []

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
        pending, self._pending_persist = self._pending_persist, []
        for artifact in pending:
            try:
                await self._persist_artifact(artifact)
            except Exception:
                logger.exception("Failed to write-through evidence artifact %s", artifact.artifact_id)
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
            by_class[a.provenance.classification] = by_class.get(a.provenance.classification, 0) + 1
        return {"accepted": len(self.accepted), "rejected": len(self.rejected), "accepted_by_classification": by_class,
                "rejected_reasons": sorted({r["code"] for rej in self.rejected for r in rej["reasons"]})}
