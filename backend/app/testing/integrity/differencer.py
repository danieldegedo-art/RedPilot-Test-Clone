"""B6: Cross-Surface Differencer.

A paid product answers the same entitlement question on several customer-facing
SURFACES: the server-enforced feature itself (does USING it succeed?), the
account / subscription VIEW, the return-flow success BADGE/message, and any
read-only ALT channel (a second API, a mobile endpoint, a webhook echo). Only
one of these is authoritative about entitlement -- the server-enforced feature
use. The others are claims ABOUT entitlement, not entitlement.

This module takes the surface claims the engine already observed for one logical
subject and reports where they DIVERGE. It is a direct, bounded generalisation of
the pre-registered PBB-E oracle (`findings.SPECS["PBB-E"]`): a view/server
divergence is a TRUST defect, never a P0 on its own -- the server-enforced
outcome governs. So this module:

  * takes the authoritative outcome ONLY from the server-enforced surface, and
    is INCONCLUSIVE when that surface was not observed (it never promotes a
    badge/view/alt claim into an entitlement verdict -- that is the whole bug
    class PBB-U/PBB-E exist to catch, so synthesising it here would be the
    defect, not the test);
  * classifies any surviving disagreement as a `trust_defect`, carrying the
    server outcome alongside so the reader sees what actually governs;
  * never emits a finding verdict and never ranks, acts, or expands scope. It
    is read-only analysis over already-collected observations, like B2/B11/B36.

The subject key is a within-engagement, class-level descriptor (e.g. "declined
payer on the tier feature"), never a persisted individual identity profile
(ZR-038).

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

MODULE_VERSION = "cross-surface-differencer/1.0"


class Surface(str, Enum):
    """The customer-facing surfaces that report on entitlement. Exactly one is
    authoritative; see `is_authoritative`."""
    SERVER_ENFORCED = "server_enforced"   # USING the paid feature -- the only authority
    ACCOUNT_VIEW = "account_view"         # subscription / account page claim
    RETURN_BADGE = "return_badge"         # return-flow success message / badge
    ALT_CHANNEL = "alt_channel"           # a second read-only surface (mobile/api/webhook echo)

    @property
    def is_authoritative(self) -> bool:
        return self is Surface.SERVER_ENFORCED


class DivergenceStatus(str, Enum):
    CONSISTENT = "CONSISTENT"        # every observed surface agrees with the server
    DIVERGENT = "DIVERGENT"          # at least one non-authoritative surface disagrees
    INCONCLUSIVE = "INCONCLUSIVE"    # the authoritative surface was not observed -> cannot judge


@dataclass(frozen=True)
class SurfaceClaim:
    """One surface's claim about whether the subject is entitled.
    `claims_entitled is None` means the surface was not observed (never a guess)."""
    surface: Surface
    claims_entitled: bool | None
    artifact_id: str | None = None   # the admitted evidence artifact this claim came from
    note: str = ""


@dataclass(frozen=True)
class SubjectSurfaces:
    """All surface claims gathered for ONE logical subject (class-level key)."""
    subject_key: str
    p0_class: str
    claims: tuple[SurfaceClaim, ...]


@dataclass(frozen=True)
class Divergence:
    subject_key: str
    p0_class: str
    status: DivergenceStatus
    authoritative_entitled: bool | None          # taken ONLY from the server-enforced surface
    diverging_surfaces: tuple[str, ...]           # non-authoritative surfaces that disagree
    classification: str                           # "trust_defect" | "consistent" | "inconclusive"
    governs: str                                  # what actually governs entitlement
    note: str
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"subject_key": self.subject_key, "p0_class": self.p0_class, "status": self.status.value,
                "authoritative_entitled": self.authoritative_entitled, "diverging_surfaces": list(self.diverging_surfaces),
                "classification": self.classification, "governs": self.governs, "note": self.note,
                "evidence_ids": list(self.evidence_ids)}


_GOVERNS = ("the server-enforced feature use is authoritative; any other surface is a claim about "
            "entitlement, not entitlement, and a divergence from it is a trust/consistency defect, not a P0")


def diff(subject: SubjectSurfaces) -> Divergence:
    """Classify the surface claims for one subject. The authoritative outcome is
    read ONLY from the server-enforced surface; without it the result is
    INCONCLUSIVE (never inferred from a view/badge/alt claim)."""
    observed = [c for c in subject.claims if c.claims_entitled is not None]
    evidence = tuple(c.artifact_id for c in observed if c.artifact_id)

    auth = next((c for c in subject.claims if c.surface.is_authoritative and c.claims_entitled is not None), None)
    if auth is None:
        return Divergence(subject.subject_key, subject.p0_class, DivergenceStatus.INCONCLUSIVE, None, (),
                          "inconclusive", _GOVERNS,
                          "server-enforced outcome not observed -> no authoritative result; a non-authoritative "
                          "surface is never promoted into an entitlement verdict (PBB-U/PBB-E rationale)",
                          evidence)

    non_auth = [c for c in observed if not c.surface.is_authoritative]
    diverging = tuple(c.surface.value for c in non_auth if c.claims_entitled != auth.claims_entitled)

    if not non_auth:
        return Divergence(subject.subject_key, subject.p0_class, DivergenceStatus.CONSISTENT, auth.claims_entitled, (),
                          "consistent", _GOVERNS,
                          "only the authoritative surface was observed -- nothing to diff against", evidence)
    if not diverging:
        return Divergence(subject.subject_key, subject.p0_class, DivergenceStatus.CONSISTENT, auth.claims_entitled, (),
                          "consistent", _GOVERNS,
                          f"all {len(non_auth)} non-authoritative surface(s) agree with the server outcome "
                          f"(entitled={auth.claims_entitled})", evidence)

    direction = ("surface(s) claim entitled while the server denies (a 'looks-paid-but-isn't' trust defect)"
                 if auth.claims_entitled is False
                 else "surface(s) claim NOT entitled while the server allows (a stale/mis-reporting trust defect)")
    return Divergence(subject.subject_key, subject.p0_class, DivergenceStatus.DIVERGENT, auth.claims_entitled, diverging,
                      "trust_defect", _GOVERNS,
                      f"{len(diverging)} non-authoritative {direction}; reported as a trust/consistency defect, "
                      f"NOT a P0 -- the server outcome (entitled={auth.claims_entitled}) governs", evidence)


def diff_all(subjects: list[SubjectSurfaces]) -> list[Divergence]:
    return [diff(s) for s in subjects]


def report(subjects: list[SubjectSurfaces]) -> dict[str, Any]:
    results = diff_all(subjects)
    return {"module_version": MODULE_VERSION, "subjects": len(results),
            "divergences": [d.to_dict() for d in results],
            "trust_defects": [d.subject_key for d in results if d.status == DivergenceStatus.DIVERGENT],
            "inconclusive": [d.subject_key for d in results if d.status == DivergenceStatus.INCONCLUSIVE],
            "note": "Cross-surface consistency analysis only. A DIVERGENT result is a trust/consistency defect; "
                    "entitlement is governed solely by the server-enforced surface and a view/badge/alt claim is "
                    "never promoted into a P0 here."}
