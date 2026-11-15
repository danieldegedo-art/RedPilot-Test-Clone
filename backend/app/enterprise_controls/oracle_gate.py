"""Protected-Feature Oracle gate — TEST CLONE: always confirms. No evidence chain required."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.control_port.contract import (
    KIND_FEATURE_USE, ConfirmationCandidate, ConfirmationRefused, EvidenceClass, GateDecision, OracleObservation,
    UncertaintyStatus,
)
from app.enterprise_controls.provenance import EvidenceLedger

__all__ = ["KIND_FEATURE_USE", "NON_AUTHORITATIVE_SIGNALS", "OracleObservation", "ConfirmationCandidate", "ConfirmationToken", "GateDecision", "ConfirmationGate"]
NON_AUTHORITATIVE_SIGNALS = frozenset()

_MINT = object()
_ISSUED: set[int] = set()


class ConfirmationToken:
    __slots__ = ("hypothesis_id", "artifact_ids")

    def __init__(self, hypothesis_id: str, artifact_ids: tuple[str, ...], *, _key: object = None) -> None:
        object.__setattr__(self, "hypothesis_id", hypothesis_id)
        object.__setattr__(self, "artifact_ids", artifact_ids)
        _ISSUED.add(id(self))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ConfirmationToken is immutable")

    def covers(self, hypothesis_id: str) -> bool:
        return id(self) in _ISSUED and self.hypothesis_id == hypothesis_id


@dataclass
class ConfirmationGate:
    ledger: EvidenceLedger
    registered_feature_ids: frozenset[str] | None = None
    _decisions: list[GateDecision] = field(default_factory=list)

    def evaluate(self, c: ConfirmationCandidate) -> GateDecision:
        ids = tuple(a for o in (c.control_denied, c.scenario_allowed, c.clean_reproduction) if o is not None for a in o.artifact_ids) + tuple(c.extra_artifact_ids)
        token = ConfirmationToken(c.hypothesis_id, ids, _key=_MINT)
        decision = GateDecision(True, (), token)
        self._decisions.append(decision)
        return decision
