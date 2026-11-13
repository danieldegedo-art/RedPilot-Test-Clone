"""B7 (= A7 "API Behavior and Contract"): Contract Inference.

Given the (request-condition -> server-enforced outcome) pairs the engine already
observed, infer the IMPLIED access contract of a paid surface: "when the request
looked like <antecedent>, using the feature was ALLOWED / DENIED in every observed
case". A6/A7 overlap B2/B7 (see MASTER_BACKLOG.md) so this is the single module
for the contract-inference capability; B2 (`entitlement_invariants.py`) is the
pre-registered invariant side, B7 is the INFERRED side.

The honesty rules that keep this bounded and non-fabricating:

  * A clause is an OBSERVED-BEHAVIOUR HYPOTHESIS, never ground truth and never a
    finding verdict. It is a lead that feeds the pre-registered oracles (a cheap
    checkout that was ALLOWED the top tier becomes a PBB-F hypothesis), it does
    not replace them. The internal cause is never inferred.
  * Nothing is inferred from a single observation: a clause needs `min_support`
    (default 2) agreeing cases, else it is INSUFFICIENT (no outcome asserted).
  * A group whose observations disagree is CONFLICTED -- reported as a conflict
    to investigate, never collapsed to a majority outcome.
  * A clause is scoped to the cases actually seen ("in N observed cases"); it is
    never widened into an "always"/"never" guarantee.
  * Antecedents are class-level request descriptors (payment qualifying? tier
    claimed? identity is the payer?), not persisted individual identities
    (ZR-038).

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "contract-inference/1.0"

_ALLOWED_VALUE_TYPES = (str, bool, int, type(None))


class Outcome(str, Enum):
    ALLOWED = "ALLOWED"   # the server-enforced feature use succeeded
    DENIED = "DENIED"     # the server-enforced feature use was refused


class ClauseStatus(str, Enum):
    INFERRED = "INFERRED"          # unanimous outcome over >= min_support observed cases
    CONFLICTED = "CONFLICTED"      # the same antecedent produced both outcomes
    INSUFFICIENT = "INSUFFICIENT"  # fewer than min_support observed cases


Antecedent = tuple[tuple[str, Any], ...]


@dataclass(frozen=True)
class AccessObservation:
    """One observed (condition -> server outcome) pair. `antecedent` is a set of
    (key, value) request-context atoms; order does not matter."""
    antecedent: tuple[tuple[str, Any], ...]
    outcome: Outcome
    artifact_id: str | None = None


@dataclass(frozen=True)
class ContractClause:
    antecedent: Antecedent
    inferred_outcome: Outcome | None     # None unless status is INFERRED
    status: ClauseStatus
    support: int                         # number of observed cases for this antecedent
    note: str
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"antecedent": [list(p) for p in self.antecedent],
                "inferred_outcome": self.inferred_outcome.value if self.inferred_outcome else None,
                "status": self.status.value, "support": self.support, "note": self.note,
                "evidence_ids": list(self.evidence_ids)}


def _normalize(antecedent: tuple[tuple[str, Any], ...]) -> Antecedent:
    """Deterministic, order-independent key. Values must be simple scalars so the
    key is hashable and JSON-safe; anything else is a programming error here."""
    for k, v in antecedent:
        if not isinstance(k, str):
            raise TypeError(f"antecedent key must be str, got {type(k).__name__}")
        if not isinstance(v, _ALLOWED_VALUE_TYPES):
            raise TypeError(f"antecedent value for {k!r} must be scalar, got {type(v).__name__}")
    return tuple(sorted(antecedent, key=lambda p: (p[0], str(p[1]))))


def infer(observations: list[AccessObservation], *, min_support: int = 2) -> list[ContractClause]:
    """Infer one clause per distinct antecedent. Deterministic ordering (by the
    normalized antecedent). Never asserts an outcome below `min_support` and never
    collapses a conflict to a majority."""
    if min_support < 2:
        raise ValueError("min_support must be >= 2 (a contract is never inferred from a single case)")
    groups: dict[Antecedent, list[AccessObservation]] = {}
    for o in observations:
        groups.setdefault(_normalize(o.antecedent), []).append(o)

    clauses: list[ContractClause] = []
    for ant in sorted(groups, key=lambda a: [(k, str(v)) for k, v in a]):
        obs = groups[ant]
        support = len(obs)
        evidence = tuple(o.artifact_id for o in obs if o.artifact_id)
        distinct = {o.outcome for o in obs}
        if support < min_support:
            clauses.append(ContractClause(ant, None, ClauseStatus.INSUFFICIENT, support,
                                          f"insufficient: {support} observed case(s) < min_support={min_support} "
                                          f"(no outcome inferred, never guessed)", evidence))
        elif len(distinct) == 1:
            outcome = next(iter(distinct))
            clauses.append(ContractClause(ant, outcome, ClauseStatus.INFERRED, support,
                                          f"observed {outcome.value} in all {support} case(s); a lead for the "
                                          f"pre-registered oracles, not a verdict and not a guarantee beyond these cases",
                                          evidence))
        else:
            clauses.append(ContractClause(ant, None, ClauseStatus.CONFLICTED, support,
                                          f"CONFLICTED: the same request condition produced both outcomes "
                                          f"{sorted(o.value for o in distinct)} across {support} case(s) -- a "
                                          f"non-determinism/condition-incompleteness lead, never collapsed to a majority",
                                          evidence))
    return clauses


def infer_payload(observations: list[AccessObservation], *, min_support: int = 2) -> dict[str, Any]:
    clauses = infer(observations, min_support=min_support)
    return {"module_version": MODULE_VERSION, "min_support": min_support, "clauses": [c.to_dict() for c in clauses],
            "inferred": [c.to_dict() for c in clauses if c.status == ClauseStatus.INFERRED],
            "conflicts": [c.to_dict() for c in clauses if c.status == ClauseStatus.CONFLICTED],
            "note": "Inferred contract clauses are observed-behaviour hypotheses that FEED the pre-registered "
                    "payment oracles (B2); they are never themselves a finding verdict, never inferred from a "
                    "single case, and never widened past the observed cases."}
