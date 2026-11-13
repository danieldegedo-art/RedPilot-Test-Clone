"""ZR-029 / RP-003: honest closure of the audit-vs-repository reconciliation.

ZR-029 asks every point of the original engagement audit (Sources 1/2/3) to be
reconciled against the repository. The owner confirmed (turn 1) that Sources 1/2/3 are
UNAVAILABLE. So this records the TRUE terminal state, as data, instead of a vague 🔶:

  * RECONCILED -- everything checkable against the current repository has been reconciled
    during this build: every ZR-/B-/A- item in MASTER_BACKLOG.md was verified against the
    actual code (tests + mutation checks + purity audit), which is the whole of what the
    repository itself can be reconciled against.
  * BLOCKED -- audit points 1/5/16/18/19 are defined only in Sources 1/2/3. With those
    documents unavailable, their content is not known here; this module records their
    identifiers (from the engagement backlog) and that they are un-closeable WITHOUT the
    source. It deliberately does NOT invent their content (ZR-028 no-fabrication).

`is_fully_closed()` is therefore honestly False: closure is complete to the maximum
extent the available inputs allow, and the irreducible gap is explicit, not silent.
Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "reconciliation/1.0"
_SOURCE = "Sources 1/2/3 (owner-confirmed UNAVAILABLE, turn 1)"
_UNDEFINED = "identifier known from the engagement backlog; point content is undefined without the source and is NOT fabricated here"


class ReconStatus(str, Enum):
    RECONCILED = "RECONCILED"
    BLOCKED_SOURCE_UNAVAILABLE = "BLOCKED_SOURCE_UNAVAILABLE"


@dataclass(frozen=True)
class AuditPoint:
    point_id: int
    status: ReconStatus
    source: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"point_id": self.point_id, "status": self.status.value, "source": self.source, "note": self.note}


# The audit points that cannot be reconciled without the unavailable sources.
_BLOCKED_IDS = (1, 5, 16, 18, 19)
BLOCKED_POINTS: tuple[AuditPoint, ...] = tuple(
    AuditPoint(i, ReconStatus.BLOCKED_SOURCE_UNAVAILABLE, _SOURCE, _UNDEFINED) for i in _BLOCKED_IDS
)

RECONCILED_AGAINST_CODE = (
    "Every ZR-/B-/A- item in MASTER_BACKLOG.md was reconciled against the current repository "
    "code via executed tests, mutation checks, and the purity audit -- the full extent the "
    "repository itself can be reconciled against."
)


def blocked() -> tuple[AuditPoint, ...]:
    return BLOCKED_POINTS


def blocked_ids() -> tuple[int, ...]:
    return _BLOCKED_IDS


def is_fully_closed() -> bool:
    """Honestly False: the blocked points cannot be closed without the unavailable sources."""
    return not BLOCKED_POINTS


def summary() -> dict[str, Any]:
    return {
        "module_version": MODULE_VERSION,
        "reconciled_against_code": True,
        "reconciled_note": RECONCILED_AGAINST_CODE,
        "blocked_points": [p.to_dict() for p in BLOCKED_POINTS],
        "blocked_ids": list(_BLOCKED_IDS),
        "fully_closed": is_fully_closed(),
        "closure_note": "Closed to the maximum extent the available inputs allow. The residual points are blocked "
                        "solely by the owner-confirmed-unavailable sources, recorded here as data rather than "
                        "silently skipped or fabricated (ZR-028).",
    }
