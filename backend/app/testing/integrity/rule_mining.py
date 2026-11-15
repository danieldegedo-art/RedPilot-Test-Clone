"""B8: Rule Mining.

Mines recurring "antecedent => consequent" association rules from the engine's
OWN corpus of prior findings/outcomes, so the planner can prioritise where a
known pattern tends to recur (e.g. "in our history, a cross-tenant class with a
tenant-claimed-at-return attribute was CONFIRMED_P0 in every one of N cases").

This is deliberately NOT an open-ended pattern synthesiser. Three bounds keep it
inside the pre-registered payment-oracle domain and make its safety intrinsic
(not reliant on the fail-open control layer):

  1. The caller MUST declare `consequent_keys` -- the attribute keys that may
     appear on the right-hand side of a rule (e.g. {"verdict"}). Nothing is
     mined toward an undeclared target, so the miner cannot wander off into
     arbitrary correlations.
  2. Antecedents are conjunctions capped at `max_antecedent_size` (default 2) --
     bounded, never an unbounded conjunction search (ZR-036).
  3. A rule needs at least `min_cases` (default 3, hard floor 3) INDEPENDENT
     cases and at least `min_confidence` (default 1.0) -- a pattern seen once or
     twice, or that only "usually" holds, is not asserted.

Honesty, matching B11/B36:

  * The corpus is OUR own engagement history (spec §7.2). A mined rule claims
    recurrence in that history, never a universal truth and never novelty versus
    anyone else's private data.
  * A rule is a LEAD / prior (ZR-036), never proof, never a finding verdict; the
    pre-registered oracles still have to confirm anything it points at.
  * Everything is class-level (ZR-038): antecedents/consequents are class-level
    attribute atoms, never a persisted individual identity.

Stdlib only; pure.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any

MODULE_VERSION = "rule-mining/1.0"
MIN_CASES_FLOOR = 3

Atom = tuple[str, Any]
_ALLOWED_VALUE_TYPES = (str, bool, int, type(None))


@dataclass(frozen=True)
class Case:
    """One historical case, described by class-level attribute atoms (including
    its outcome atom, e.g. ("verdict", "CONFIRMED_P0")). `case_id` is a
    class-level/engagement reference, never an individual identity (ZR-038)."""
    case_id: str
    attributes: tuple[Atom, ...]


@dataclass(frozen=True)
class Rule:
    antecedent: tuple[Atom, ...]
    consequent: Atom
    support: int               # cases matching antecedent AND consequent
    antecedent_support: int    # cases matching the antecedent
    confidence: float          # support / antecedent_support
    cases: tuple[str, ...]     # ids of the supporting cases
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"antecedent": [list(a) for a in self.antecedent], "consequent": list(self.consequent),
                "support": self.support, "antecedent_support": self.antecedent_support,
                "confidence": round(self.confidence, 6), "cases": list(self.cases), "note": self.note}


def _atoms(case: Case) -> set[Atom]:
    out: set[Atom] = set()
    for k, v in case.attributes:
        if not isinstance(k, str):
            raise TypeError(f"attribute key must be str, got {type(k).__name__}")
        if not isinstance(v, _ALLOWED_VALUE_TYPES):
            raise TypeError(f"attribute value for {k!r} must be scalar, got {type(v).__name__}")
        out.add((k, v))
    return out


def mine(cases: list[Case], *, consequent_keys: set[str], min_cases: int = MIN_CASES_FLOOR,
         min_confidence: float = 1.0, max_antecedent_size: int = 2) -> list[Rule]:
    if not consequent_keys:
        raise ValueError("consequent_keys is required (nothing is mined toward an undeclared target)")
    if min_cases < MIN_CASES_FLOOR:
        raise ValueError(f"min_cases must be >= {MIN_CASES_FLOOR} (a recurring rule needs independent cases)")
    if max_antecedent_size < 1:
        raise ValueError("max_antecedent_size must be >= 1")
    if not 0.0 <= min_confidence <= 1.0:
        raise ValueError("min_confidence must be in [0, 1]")

    case_atoms = [(c.case_id, _atoms(c)) for c in cases]
    consequents = sorted({a for _, atoms in case_atoms for a in atoms if a[0] in consequent_keys},
                         key=lambda a: (a[0], str(a[1])))
    antecedent_atoms = sorted({a for _, atoms in case_atoms for a in atoms if a[0] not in consequent_keys},
                              key=lambda a: (a[0], str(a[1])))

    rules: list[Rule] = []
    for size in range(1, max_antecedent_size + 1):
        for antecedent in itertools.combinations(antecedent_atoms, size):
            # never allow two atoms with the same key in one antecedent (contradictory conjunction)
            if len({k for k, _ in antecedent}) != size:
                continue
            ant_set = set(antecedent)
            ant_cases = [(cid, atoms) for cid, atoms in case_atoms if ant_set <= atoms]
            ant_support = len(ant_cases)
            if ant_support < min_cases:
                continue
            for cons in consequents:
                supporting = tuple(cid for cid, atoms in ant_cases if cons in atoms)
                support = len(supporting)
                if support < min_cases:
                    continue
                confidence = support / ant_support
                if confidence < min_confidence:
                    continue
                rules.append(Rule(
                    tuple(sorted(antecedent, key=lambda a: (a[0], str(a[1])))), cons, support, ant_support,
                    confidence, supporting,
                    f"LEAD only (ZR-036): in our own history (§7.2) this antecedent coincided with "
                    f"{cons[0]}={cons[1]!r} in {support}/{ant_support} case(s); a prior for planning, never proof "
                    f"and never a verdict -- the pre-registered oracles still have to confirm it."))
    rules.sort(key=lambda r: (-r.support, -r.confidence, [(k, str(v)) for k, v in r.antecedent],
                              (r.consequent[0], str(r.consequent[1]))))
    return rules


def mine_payload(cases: list[Case], *, consequent_keys: set[str], min_cases: int = MIN_CASES_FLOOR,
                 min_confidence: float = 1.0, max_antecedent_size: int = 2) -> dict[str, Any]:
    rules = mine(cases, consequent_keys=consequent_keys, min_cases=min_cases,
                 min_confidence=min_confidence, max_antecedent_size=max_antecedent_size)
    return {"module_version": MODULE_VERSION, "cases": len(cases), "min_cases": min_cases,
            "min_confidence": min_confidence, "max_antecedent_size": max_antecedent_size,
            "rules": [r.to_dict() for r in rules],
            "note": "Mined rules are LEADS/priors over our OWN engagement history (§7.2), bounded to declared "
                    "consequent keys and a capped antecedent size (ZR-036); each is class-level (ZR-038), never "
                    "proof, never a verdict, and never a claim about anyone else's data."}
