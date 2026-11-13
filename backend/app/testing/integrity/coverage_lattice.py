"""B18 / ZR-007: the Coverage Lattice -- the multi-axis cross-product object.

ZR-006's CoverageMatrix (`coverage.py`) tracks each axis SEPARATELY (coverage by
hypothesis_class, by flow_type, by test_scope). B18's remaining slice is the LATTICE:
the cross-product of the three axes, so a gap like "cross-tenant scope on the refund
flow was never exercised for the retention class" is visible as a single uncovered
cell rather than hidden behind three individually-covered axes.

A cell is one (hypothesis_class, flow_type, test_scope) triple. An observation marks a
cell covered (with a count). `missing()` reports the cells of a declared universe that
were never exercised; `density()` is covered/total over that universe. Pure and
deterministic -- the durable (SQLAlchemy) persistence of a lattice is `app/db/
coverage_store.py`; this module is the lattice logic itself.

Stdlib only; pure.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any

MODULE_VERSION = "coverage-lattice/1.0"

Cell = tuple[str, str, str]   # (hypothesis_class, flow_type, test_scope)


@dataclass(frozen=True)
class LatticeCell:
    hypothesis_class: str
    flow_type: str
    test_scope: str
    count: int

    @property
    def key(self) -> Cell:
        return (self.hypothesis_class, self.flow_type, self.test_scope)

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_class": self.hypothesis_class, "flow_type": self.flow_type,
                "test_scope": self.test_scope, "count": self.count}


class CoverageLattice:
    """Cross-product coverage over the three axes. Observations accumulate counts;
    nothing is covered until it is actually observed (no cell is assumed)."""

    def __init__(self) -> None:
        self._counts: dict[Cell, int] = {}

    def observe(self, hypothesis_class: str, flow_type: str, test_scope: str, *, count: int = 1) -> None:
        if count < 0:
            raise ValueError("count must be >= 0")
        if count == 0:
            return
        key = (hypothesis_class, flow_type, test_scope)
        self._counts[key] = self._counts.get(key, 0) + count

    def is_covered(self, hypothesis_class: str, flow_type: str, test_scope: str) -> bool:
        return self._counts.get((hypothesis_class, flow_type, test_scope), 0) > 0

    def covered_cells(self) -> list[LatticeCell]:
        return [LatticeCell(c, f, s, n) for (c, f, s), n in
                sorted(self._counts.items(), key=lambda kv: kv[0])]

    def universe(self, classes: list[str], flows: list[str], scopes: list[str]) -> list[Cell]:
        return [(c, f, s) for c, f, s in itertools.product(sorted(set(classes)), sorted(set(flows)), sorted(set(scopes)))]

    def missing(self, classes: list[str], flows: list[str], scopes: list[str]) -> list[Cell]:
        """Cells of the declared universe that were never exercised (least-covered-wins
        targeting input for the planner)."""
        return [cell for cell in self.universe(classes, flows, scopes) if self._counts.get(cell, 0) == 0]

    def density(self, classes: list[str], flows: list[str], scopes: list[str]) -> float:
        uni = self.universe(classes, flows, scopes)
        if not uni:
            return 0.0
        covered = sum(1 for cell in uni if self._counts.get(cell, 0) > 0)
        return covered / len(uni)

    def to_dict(self, classes: list[str] | None = None, flows: list[str] | None = None,
                scopes: list[str] | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"module_version": MODULE_VERSION, "covered": [c.to_dict() for c in self.covered_cells()]}
        if classes is not None and flows is not None and scopes is not None:
            out["density"] = round(self.density(classes, flows, scopes), 6)
            out["missing"] = [list(cell) for cell in self.missing(classes, flows, scopes)]
        return out


def lattice_from_observations(observations: list[Cell]) -> CoverageLattice:
    """Build a lattice from a list of (class, flow, scope) triples that were exercised."""
    lat = CoverageLattice()
    for c, f, s in observations:
        lat.observe(c, f, s)
    return lat
