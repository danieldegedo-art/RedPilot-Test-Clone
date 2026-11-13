"""B11: Duplicate & Novelty Fingerprinting (local, no external API).

A finding is fingerprinted by its NORMALIZED structured shape -- issue class
(p0_class), payment flow family, and target surface -- and compared against the
platform's OWN finding history so it does not re-raise a class it has already
found and reported for a target.

HONEST SCOPE (spec Section 7.2 -- not negotiable): "novelty" here means ONLY
dedup against this platform's own history. It cannot and does not claim novelty
against another researcher's private, undisclosed submission -- no platform
legitimately can, and every output says so. The spec's richer form is a
locality-sensitive hash over free-text reports; RedPilot's findings are discrete,
pre-registered oracle CLASSES, so a normalized structured key is both sufficient
and more reliable than fuzzy hashing here (ZR-036: the smallest reasonable
decision, stated).

Stdlib only; pure.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from app.testing.integrity.findings import EngineResult

SCOPE_NOTE = ("own-history dedup only (Section 7.2): this never claims novelty against another "
              "researcher's private/undisclosed submission -- no platform can know that.")


@dataclass(frozen=True)
class FindingFingerprint:
    issue_class: str
    flow: str
    target: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"issue_class": self.issue_class, "flow": self.flow, "target": self.target, "digest": self.digest}


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def fingerprint(issue_class: str | None, flow: str | None, target: str | None) -> FindingFingerprint:
    ic, fl, tg = _norm(issue_class), _norm(flow) or "unspecified_flow", _norm(target) or "unspecified_target"
    digest = hashlib.sha256(f"{ic}|{fl}|{tg}".encode("utf-8")).hexdigest()
    return FindingFingerprint(ic, fl, tg, digest)


def fingerprint_of(finding: Any, target: str) -> FindingFingerprint:
    return fingerprint(getattr(finding, "p0_class", None), getattr(finding, "affected_flow", None), target)


@dataclass(frozen=True)
class Novelty:
    digest: str
    is_novel: bool
    times_seen: int       # in this platform's OWN history, before this assessment
    novelty_score: float  # 1.0 if never seen; diminishing with each prior sighting
    scope_note: str = SCOPE_NOTE

    def to_dict(self) -> dict[str, Any]:
        return {"digest": self.digest, "is_novel": self.is_novel, "times_seen": self.times_seen,
                "novelty_score": round(self.novelty_score, 4), "scope_note": self.scope_note}


class NoveltyRegister:
    """The platform's own finding-history index (local, single-writer)."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def assess(self, fp: FindingFingerprint) -> Novelty:
        seen = self._seen.get(fp.digest, 0)
        return Novelty(fp.digest, is_novel=seen == 0, times_seen=seen, novelty_score=1.0 / (1 + seen))

    def register(self, fp: FindingFingerprint) -> None:
        self._seen[fp.digest] = self._seen.get(fp.digest, 0) + 1

    def dedup_run(self, result: EngineResult, target: str) -> dict[str, Any]:
        """Assess every finding against own history, then register them. Returns
        which hypotheses are novel-for-this-target vs. already-known duplicates."""
        novel: list[str] = []
        duplicate: list[str] = []
        assessments: list[dict[str, Any]] = []
        for f in result.findings:
            fp = fingerprint_of(f, target)
            nov = self.assess(fp)
            (novel if nov.is_novel else duplicate).append(f.hypothesis_id)
            assessments.append({"hypothesis_id": f.hypothesis_id, **nov.to_dict()})
            self.register(fp)
        return {"target": target, "novel": novel, "duplicate_of_own_history": duplicate,
                "assessments": assessments, "scope_note": SCOPE_NOTE}
