"""Contract of the Control Adapter: the types, constants and records that BOTH sides of the boundary need.

The Main System talks to the Enterprise Controls only through ``app.control_adapter``. Whatever the Main System itself catches,
instantiates or reads has to exist even when ``app.enterprise_controls`` is unavailable (fail-open availability mode), so it lives
here and not in the optional component:

  K1  exception types       ScopeViolation, PurityViolation (+ subclasses), BriefRejected, Reason
  K2  constants             SCOPE_ERROR_PREFIX, NEGATIVE_ACCESS_CONTROL
  K3  gate data types       OracleObservation, ConfirmationCandidate, GateDecision, KIND_FEATURE_USE
  K4  vocabulary            EvidenceClass
  K5  provenance record     EvidenceProvenance, EvidenceArtifact, build_artifact, compute_integrity_hash, now_iso
                            (a record builder, not a gate: the admission decision is ``EvidenceLedger`` in enterprise_controls)

Stdlib only (plus the core vocabulary enum ``TruthLabel``). Moved here unchanged from purity/errors.py, scope_guard.py,
integrity/brief.py, purity/oracle_gate.py, purity/provenance.py and purity/taxonomy.py.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.testing.purity.taxonomy import TruthLabel

# ----------------------------------------------------------------------------------------------------------------------------------
# K1  exception types
# ----------------------------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Reason:
    """One concrete reason something was rejected. Never contains the offending VALUE (it may be a secret)."""

    code: str
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.code} at {self.location}: {self.message}"


class PurityViolation(Exception):
    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}


class TargetAccessRejected(PurityViolation):
    """A request/host/port/scheme/path is not a customer-facing surface (allowlist, internal-surface denylist)."""


class CredentialRejected(PurityViolation):
    """A credential, secret, role or config key is not customer-level synthetic-test material."""

    def __init__(self, reasons: list[Reason]) -> None:
        super().__init__("credential_rejected", "; ".join(str(r) for r in reasons) or "rejected", details={"reasons": [r.__dict__ for r in reasons]})
        self.reasons = list(reasons)


class ProvenanceRejected(PurityViolation):
    """An evidence artifact has missing, internal, privileged, unknown or unverifiable provenance."""

    def __init__(self, reasons: list[Reason]) -> None:
        super().__init__("provenance_rejected", "; ".join(str(r) for r in reasons) or "rejected", details={"reasons": [r.__dict__ for r in reasons]})
        self.reasons = list(reasons)


class BenchmarkLeak(PurityViolation):
    """Benchmark ground truth / flaw identifiers / fixture metadata reached the system under assessment."""


class QuarantinedModuleError(PurityViolation, ImportError):
    """A quarantined White-/Grey-Box module was loaded (or tried to load) in Pure Black-Box mode."""


class ConfirmationRefused(PurityViolation):
    """CONFIRMED_P0 was requested without a valid external Protected-Feature Oracle chain."""


class BriefRejected(PurityViolation):
    def __init__(self, reasons: list[Reason]) -> None:
        super().__init__("brief_rejected", "; ".join(str(r) for r in reasons) or "rejected", details={"reasons": [r.__dict__ for r in reasons]})
        self.reasons = list(reasons)


class ScopeViolation(Exception):
    """A request would leave the authorised scope or exceed a bound."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ----------------------------------------------------------------------------------------------------------------------------------
# K2  constants
# ----------------------------------------------------------------------------------------------------------------------------------
SCOPE_ERROR_PREFIX = "scope_violation"
NEGATIVE_ACCESS_CONTROL = "negative_access_control"

# ----------------------------------------------------------------------------------------------------------------------------------
# K3  gate data types (instantiated by the engine, evaluated by enterprise_controls.oracle_gate)
# ----------------------------------------------------------------------------------------------------------------------------------
KIND_FEATURE_USE = "protected_feature_use"


@dataclass(frozen=True)
class OracleObservation:
    oracle_id: str
    feature_id: str
    identity_alias: str
    tenant_alias: str | None
    outcome: str  # allowed | denied | indeterminate
    kind: str
    proof_present: bool
    session_isolation_id: str
    artifact_ids: tuple[str, ...]
    discriminating: bool | None = None
    observed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"oracle_id": self.oracle_id, "feature_id": self.feature_id, "identity_alias": self.identity_alias, "tenant_alias": self.tenant_alias,
                "outcome": self.outcome, "kind": self.kind, "proof_present": self.proof_present, "session_isolation_id": self.session_isolation_id,
                "artifact_ids": list(self.artifact_ids), "discriminating": self.discriminating, "observed_at": self.observed_at}


@dataclass(frozen=True)
class ConfirmationCandidate:
    hypothesis_id: str
    control_denied: OracleObservation | None
    scenario_allowed: OracleObservation | None
    clean_reproduction: OracleObservation | None
    qualifying_payment_present: bool
    signals_used: tuple[str, ...] = (KIND_FEATURE_USE,)
    evidence_classes: tuple[str, ...] = ()
    extra_artifact_ids: tuple[str, ...] = ()


class UncertaintyStatus(str, Enum):
    """ZR-024: the only vocabulary for an UNPROVEN suspicion -- i.e. a
    ConfirmationCandidate that ConfirmationGate.evaluate() did not confirm.
    None of these four is ever a finding on its own and none is ever
    silently upgraded to CONFIRMED_P0 by a scoring threshold alone; the only
    way a candidate becomes CONFIRMED_P0 is evaluate() returning
    confirmed=True with a minted token. A decision with confirmed=False
    always carries exactly one of these (see oracle_gate._classify_uncertainty) --
    UNLESS the ONLY reason is qualifying_payment_present, in which case
    uncertainty_status is None, because that is not an unproven suspicion at
    all: it is a conclusively determined non-finding (the access is correct
    behaviour), and the existing qualifying_payment_present reason string
    already says so more precisely than any of these four buckets would."""

    BLOCKED_BY_MISSING_ORACLE = "BLOCKED BY MISSING SERVER-SIDE ORACLE"
    NOT_SUFFICIENTLY_PROVABLE = "NOT SUFFICIENTLY PROVABLE"
    PARTIALLY_VERIFIED = "PARTIALLY VERIFIED"
    UNCONFIRMED = "UNCONFIRMED"


@dataclass(frozen=True)
class GateDecision:
    confirmed: bool
    reasons: tuple[str, ...]
    token: Any = None  # a ConfirmationToken minted by enterprise_controls.oracle_gate; None when not confirmed
    uncertainty_status: UncertaintyStatus | None = None  # ZR-024; None iff confirmed, or the qualifying-payment case above


# ----------------------------------------------------------------------------------------------------------------------------------
# K4  vocabulary
# ----------------------------------------------------------------------------------------------------------------------------------
class EvidenceClass(str, Enum):
    """The ONLY provenance classifications an evidence artifact may carry. Anything else is rejected."""

    EXTERNAL_BROWSER = "external_browser"
    EXTERNAL_CUSTOMER_API = "external_customer_api"
    EXTERNAL_NOTIFICATION = "external_notification"
    APPROVED_SANDBOX_PAYMENT = "approved_sandbox_payment"
    CONTROLLED_BLACK_BOX_BENCHMARK = "controlled_black_box_benchmark"


# ----------------------------------------------------------------------------------------------------------------------------------
# K5  provenance record
# ----------------------------------------------------------------------------------------------------------------------------------
def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class EvidenceProvenance:
    source_type: str
    classification: str
    identity_alias: str
    tenant_alias: str | None
    target: str
    timestamp: str
    session_isolation_id: str
    authorization_ref: str
    redaction_status: str
    integrity_hash: str
    truth_label: str = TruthLabel.EXTERNALLY_OBSERVED.value

    def hash_inputs(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if k not in ("integrity_hash", "truth_label")}


def compute_integrity_hash(payload: Any, prov_fields: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json({"payload": payload, "prov": prov_fields}).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceArtifact:
    artifact_id: str
    provenance: EvidenceProvenance | None
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"artifact_id": self.artifact_id, "provenance": asdict(self.provenance) if self.provenance else None, "payload": self.payload}


def build_artifact(
    *, payload: dict[str, Any], source_type: str, classification: EvidenceClass | str, identity_alias: str, tenant_alias: str | None, target: str,
    session_isolation_id: str, authorization_ref: str, redaction_status: str = "redacted", truth_label: TruthLabel | str = TruthLabel.EXTERNALLY_OBSERVED, sequence: int = 0,
) -> EvidenceArtifact:
    cls = classification.value if isinstance(classification, EvidenceClass) else str(classification)
    label = truth_label.value if isinstance(truth_label, TruthLabel) else str(truth_label)
    fields = {"source_type": source_type, "classification": cls, "identity_alias": identity_alias, "tenant_alias": tenant_alias, "target": target,
              "timestamp": now_iso(), "session_isolation_id": session_isolation_id, "authorization_ref": authorization_ref, "redaction_status": redaction_status}
    digest = compute_integrity_hash(payload, fields)
    prov = EvidenceProvenance(**fields, integrity_hash=digest, truth_label=label)
    return EvidenceArtifact(artifact_id=f"ev-{sequence:04d}-{digest[:10]}", provenance=prov, payload=payload)


__all__ = [
    "Reason", "PurityViolation", "TargetAccessRejected", "CredentialRejected", "ProvenanceRejected", "BenchmarkLeak", "QuarantinedModuleError",
    "ConfirmationRefused", "BriefRejected", "ScopeViolation", "SCOPE_ERROR_PREFIX", "NEGATIVE_ACCESS_CONTROL", "KIND_FEATURE_USE", "OracleObservation",
    "ConfirmationCandidate", "GateDecision", "EvidenceClass", "EvidenceProvenance", "EvidenceArtifact", "build_artifact", "compute_integrity_hash",
    "canonical_json", "now_iso",
]
