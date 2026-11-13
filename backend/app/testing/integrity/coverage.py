"""ZR-006 / B18: multi-dimensional coverage tracking over the bounded payment-oracle set.

`gaps.py` reports coverage along ONE axis (the p0 class). ZR-006 adds the other
axes a payment-integrity engagement is measured on, so a run can show *where*
coverage is thin, not only which classes were reached:

    hypothesis_class  <- Finding.p0_class      (the ten PBB experiment classes)
    flow_type         <- Finding.affected_flow  (payment FLOW family: checkout/payment/
                                                  subscription/refund/entitlement)
    test_scope        <- SCOPE_BY_HYPOTHESIS     (single-identity / cross-tenant /
                                                  cross-identity / unrelated-identity / ...)

plus a raw verdict tally. Every cell uses the SAME honest vocabulary as gaps.py
(`Coverage`: COVERED / PARTIALLY_COVERED / UNKNOWN / BLOCKED -- never 'passed'),
and every axis is derived only from what the findings actually concluded:
nothing is inferred about states that were not exercised. A cell is COVERED
only when EVERY contributing experiment was conclusive (CONFIRMED_P0 or
RULED_OUT); otherwise it takes the *least-covered* contributor, so an
unknown/blocked probe can never be averaged away into a "covered" flow.

Stdlib only; pure (no engine/httpx import -- it reads finished findings)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from app.testing.integrity.findings import SCOPE_BY_HYPOTHESIS, EngineResult
from app.testing.purity.taxonomy import Coverage, Verdict

# A finding's verdict -> the coverage it contributes to every cell it belongs to.
_VERDICT_COVERAGE: dict[Verdict, Coverage] = {
    Verdict.CONFIRMED_P0: Coverage.COVERED,   # conclusive: the class IS covered (a real P0 was proven)
    Verdict.RULED_OUT: Coverage.COVERED,      # conclusive: covered (ruled out with a discriminating oracle)
    Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE: Coverage.PARTIALLY_COVERED,
    Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE: Coverage.PARTIALLY_COVERED,
    Verdict.UNKNOWN: Coverage.UNKNOWN,
    Verdict.BLOCKED: Coverage.BLOCKED,
}
_COVERAGE_RANK: dict[Coverage, int] = {Coverage.COVERED: 3, Coverage.PARTIALLY_COVERED: 2, Coverage.UNKNOWN: 1, Coverage.BLOCKED: 0}


def _aggregate(coverages: Iterable[Coverage]) -> Coverage:
    """Least-covered-wins: a cell is COVERED only if EVERY contributor is COVERED.
    Empty (nothing exercised the cell) -> UNKNOWN, never COVERED."""
    ranks = [_COVERAGE_RANK[c] for c in coverages]
    if not ranks:
        return Coverage.UNKNOWN
    worst = min(ranks)
    return next(c for c, r in _COVERAGE_RANK.items() if r == worst)


@dataclass(frozen=True)
class CoverageCell:
    dimension: str
    value: str
    coverage: Coverage
    experiments: tuple[str, ...]
    verdict_counts: dict[str, int]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"dimension": self.dimension, "value": self.value, "coverage": self.coverage.value,
                "experiments": list(self.experiments), "verdict_counts": dict(sorted(self.verdict_counts.items())), "reason": self.reason}


def _cells_for(dimension: str, grouped: dict[str, list[Any]]) -> list[CoverageCell]:
    cells: list[CoverageCell] = []
    for value in sorted(grouped):
        findings = grouped[value]
        cov = _aggregate(_VERDICT_COVERAGE[f.verdict] for f in findings)
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.verdict.value] = counts.get(f.verdict.value, 0) + 1
        exps = tuple(sorted(f.hypothesis_id for f in findings))
        summary = ", ".join(f"{n}x {v}" for v, n in sorted(counts.items()))
        cells.append(CoverageCell(dimension, value, cov, exps, counts, f"{len(findings)} experiment(s) [{summary}] -> {cov.value}"))
    return cells


@dataclass
class CoverageMatrix:
    cells: list[CoverageCell] = field(default_factory=list)
    verdict_tally: dict[str, int] = field(default_factory=dict)

    def by_dimension(self, dimension: str) -> list[CoverageCell]:
        return [c for c in self.cells if c.dimension == dimension]

    def uncovered(self) -> list[CoverageCell]:
        """Every cell that is not fully COVERED -- the honest 'where is coverage thin' list."""
        return [c for c in self.cells if c.coverage != Coverage.COVERED]

    def dimensions(self) -> list[str]:
        out: list[str] = []
        for c in self.cells:
            if c.dimension not in out:
                out.append(c.dimension)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"verdict_tally": dict(sorted(self.verdict_tally.items())),
                "cells": [c.to_dict() for c in self.cells],
                "uncovered": [c.to_dict() for c in self.uncovered()]}


def coverage_matrix(result: EngineResult) -> CoverageMatrix:
    """Coverage across three axes, each derived from the findings themselves
    (p0_class, affected_flow, test scope) plus a raw verdict tally. Nothing about
    untested states is inferred."""
    findings = list(result.findings)
    by_class: dict[str, list[Any]] = {}
    by_flow: dict[str, list[Any]] = {}
    by_scope: dict[str, list[Any]] = {}
    tally: dict[str, int] = {}
    for f in findings:
        by_class.setdefault(f.p0_class, []).append(f)
        by_flow.setdefault(f.affected_flow or "unspecified", []).append(f)
        by_scope.setdefault(SCOPE_BY_HYPOTHESIS.get(f.hypothesis_id, "unspecified"), []).append(f)
        tally[f.verdict.value] = tally.get(f.verdict.value, 0) + 1
    cells = _cells_for("hypothesis_class", by_class) + _cells_for("flow_type", by_flow) + _cells_for("test_scope", by_scope)
    return CoverageMatrix(cells=cells, verdict_tally=tally)
