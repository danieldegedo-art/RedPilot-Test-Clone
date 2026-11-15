"""ZR-007 / B18: the durable half of the coverage lattice. Persists a CoverageLattice
(the class×flow×scope cross-product) to the coverage_cells table and reloads it, so
coverage accrues across runs rather than resetting each run.

NOT EXECUTED IN THE SANDBOX THIS WAS WRITTEN IN (no sqlalchemy) -- same status as
app/db/pesm_store.py. The lattice LOGIC is tested in test_coverage_lattice.py; this
class persists it. Short-lived-session-per-method pattern matches pesm_store.py. The
table is NEW (create_all picks it up).

A re-save is idempotent: the lattice's prior cells are deleted and rewritten. Loading
replays each stored cell's count through CoverageLattice.observe, so the reloaded
lattice is structurally identical to the saved one.
"""
from __future__ import annotations

from sqlalchemy import delete, select

from app.db.models import CoverageCellRecord
from app.db.session import SessionLocal
from app.testing.integrity.coverage_lattice import CoverageLattice


class SQLAlchemyCoverageStore:
    """No in-process state; every method opens its own session."""

    async def save_lattice(self, lattice_id: str, lattice: CoverageLattice) -> None:
        async with SessionLocal() as session:
            await session.execute(delete(CoverageCellRecord).where(CoverageCellRecord.lattice_id == lattice_id))
            for cell in lattice.covered_cells():
                session.add(CoverageCellRecord(lattice_id=lattice_id, hypothesis_class=cell.hypothesis_class,
                                               flow_type=cell.flow_type, test_scope=cell.test_scope, count=cell.count))
            await session.commit()

    async def load_lattice(self, lattice_id: str) -> CoverageLattice:
        stmt = select(CoverageCellRecord).where(CoverageCellRecord.lattice_id == lattice_id)
        async with SessionLocal() as session:
            rows = (await session.execute(stmt)).scalars().all()
        lattice = CoverageLattice()
        for r in rows:
            lattice.observe(r.hypothesis_class, r.flow_type, r.test_scope, count=r.count)
        return lattice

    async def saved_lattice_ids(self) -> frozenset[str]:
        async with SessionLocal() as session:
            rows = (await session.execute(select(CoverageCellRecord.lattice_id).distinct())).scalars().all()
        return frozenset(rows)
