"""B41: Symbolic Constraint Solver over Contract Models.

A bounded, dependency-free finite-domain model-finder. Given a contract MODEL --
a handful of variables with small finite domains (the request-condition atoms a
B7 contract is written over) plus implication constraints (an inferred clause
"antecedent => outcome" is one) -- it searches for assignments that satisfy the
contract yet match a VIOLATION pattern (e.g. "entitled while qualifying_payment is
False"). Each such assignment is a candidate counterexample: a concrete set of
request conditions worth probing with the real oracle.

No SMT/SAT dependency is available here (and none is needed): the domain is small
and finite, so the solver enumerates the assignment space directly with the
stdlib. The bounds that keep it from becoming an open-ended search/synthesis tool:

  * Finite, declared domain only (ZR-036): it solves over the variables and
    domains the caller passes -- the pre-registered / inferred payment-contract
    model -- never an open variable space.
  * HARD search-space cap (`max_space`): if the product of the domains exceeds the
    cap, it returns BOUNDED_EXCEEDED and enumerates nothing. It never does an
    unbounded or heuristic search.
  * Its output is CANDIDATE test conditions (leads), never findings and never
    proof. A satisfying assignment says "this input combination is worth trying
    against the real target", which the real server-enforced oracle then has to
    confirm (ZR-017).
  * Deterministic enumeration and a capped number of returned counterexamples.

Stdlib only; pure.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "symbolic-solver/1.0"
DEFAULT_MAX_SPACE = 4096
DEFAULT_MAX_RESULTS = 64

Atom = tuple[str, Any]
_ALLOWED_VALUE_TYPES = (str, bool, int, type(None))


class SolveStatus(str, Enum):
    SOLVED = "SOLVED"                      # >=1 contract-consistent assignment matches the violation
    NO_COUNTEREXAMPLE = "NO_COUNTEREXAMPLE"  # the violation is unreachable under the contract
    BOUNDED_EXCEEDED = "BOUNDED_EXCEEDED"  # the model is too large for the cap -> nothing enumerated


@dataclass(frozen=True)
class Variable:
    name: str
    domain: tuple[Any, ...]


@dataclass(frozen=True)
class Implication:
    """If every atom in `antecedent` holds, `consequent` must hold."""
    antecedent: tuple[Atom, ...]
    consequent: Atom


@dataclass(frozen=True)
class SolveResult:
    status: SolveStatus
    counterexamples: tuple[dict[str, Any], ...]
    space: int
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "counterexamples": [dict(c) for c in self.counterexamples],
                "space": self.space, "note": self.note}


def _validate(variables: list[Variable]) -> None:
    seen: set[str] = set()
    for v in variables:
        if not isinstance(v.name, str) or not v.name:
            raise ValueError("variable name must be a non-empty string")
        if v.name in seen:
            raise ValueError(f"duplicate variable {v.name!r}")
        seen.add(v.name)
        if len(v.domain) == 0:
            raise ValueError(f"variable {v.name!r} has an empty domain")
        for val in v.domain:
            if not isinstance(val, _ALLOWED_VALUE_TYPES):
                raise TypeError(f"domain value for {v.name!r} must be scalar, got {type(val).__name__}")


def _holds(assignment: dict[str, Any], atom: Atom) -> bool:
    return atom[0] in assignment and assignment[atom[0]] == atom[1]


def _consistent(assignment: dict[str, Any], implications: list[Implication]) -> bool:
    for imp in implications:
        if all(_holds(assignment, a) for a in imp.antecedent) and not _holds(assignment, imp.consequent):
            return False
    return True


def solve_for_violation(variables: list[Variable], implications: list[Implication], *,
                        violation: tuple[Atom, ...], max_space: int = DEFAULT_MAX_SPACE,
                        max_results: int = DEFAULT_MAX_RESULTS) -> SolveResult:
    """Find contract-consistent assignments that also satisfy every `violation`
    atom. Returns BOUNDED_EXCEEDED (enumerating nothing) when the space exceeds
    `max_space`."""
    _validate(variables)
    if not violation:
        raise ValueError("a violation pattern is required (nothing is 'solved' toward an unstated target)")
    space = 1
    for v in variables:
        space *= len(v.domain)
    if space > max_space:
        return SolveResult(SolveStatus.BOUNDED_EXCEEDED, (), space,
                           f"model space {space} exceeds max_space={max_space}; refusing to enumerate "
                           f"(bounded by design, never an unbounded search)")

    names = [v.name for v in variables]
    domains = [v.domain for v in variables]
    counterexamples: list[dict[str, Any]] = []
    for combo in itertools.product(*domains):
        assignment = dict(zip(names, combo))
        if not _consistent(assignment, implications):
            continue
        if all(_holds(assignment, a) for a in violation):
            counterexamples.append(dict(sorted(assignment.items())))
            if len(counterexamples) >= max_results:
                break

    if counterexamples:
        return SolveResult(SolveStatus.SOLVED, tuple(counterexamples), space,
                           f"{len(counterexamples)} candidate counterexample(s) over a {space}-assignment space; "
                           f"each is a test condition to probe with the real oracle (a lead, never a finding/proof)")
    return SolveResult(SolveStatus.NO_COUNTEREXAMPLE, (), space,
                       "no contract-consistent assignment matches the violation pattern within this model "
                       "(absence of a model-level counterexample is not proof the real target is safe)")


def solve_payload(variables: list[Variable], implications: list[Implication], *, violation: tuple[Atom, ...],
                  max_space: int = DEFAULT_MAX_SPACE, max_results: int = DEFAULT_MAX_RESULTS) -> dict[str, Any]:
    res = solve_for_violation(variables, implications, violation=violation, max_space=max_space, max_results=max_results)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "note": "Bounded finite-domain model-finding over a declared contract model (ZR-036); counterexamples "
                    "are candidate test conditions/leads for the real oracle, never findings or proof, and the "
                    "search is hard-capped so it is never unbounded."}
