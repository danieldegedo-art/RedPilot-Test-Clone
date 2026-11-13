"""ZR-007: the database-backed row source for app/testing/run_memory.py.

NOT EXECUTED IN THE SANDBOX THIS WAS WRITTEN IN (no sqlalchemy, no Postgres), the
same status _persist_result_db (api/v1/runs.py) had when it was written. What IS
tested is everything on the far side of this function -- run_memory's reducer is
exercised against rows produced by the real finding-writer, round-tripped through
JSON. What needs confirming against a real database, once: that the JSON-index
filter below behaves on your dialect (it uses SQLAlchemy's portable
JSON.as_string(), supported on PostgreSQL, SQLite and MySQL), and that a run's
findings written by TestRunner._emit_result are visible to this query from a
fresh process -- which is the actual "state survives process restart" claim.

The WHERE on brief_fingerprint exists so one target's rows can't crowd another's
out of the LIMIT window; it is not what keeps targets apart. run_memory re-checks
the fingerprint on every row regardless, so a mistake here costs coverage, never
isolation.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.db.models import TestResultRecord
from app.db.session import SessionLocal
from app.testing.enums import TestCategory
from app.testing.run_memory import RowSource


async def fetch_payment_integrity_rows(brief_fingerprint: str, *, limit: int = 2000) -> list[dict[str, Any]]:
    stmt = (
        select(TestResultRecord)
        .where(TestResultRecord.category == TestCategory.PAYMENT_INTEGRITY.value)
        .where(TestResultRecord.input_parameters["brief_fingerprint"].as_string() == brief_fingerprint)
        .order_by(TestResultRecord.finished_at.desc())
        .limit(limit)
    )
    async with SessionLocal() as session:
        records = (await session.execute(stmt)).scalars().all()
    return [
        {"run_id": r.run_id, "category": r.category, "input_parameters": r.input_parameters, "finished_at": r.finished_at}
        for r in records
    ]


def row_source_for(brief_fingerprint: str) -> RowSource:
    async def source() -> list[dict[str, Any]]:
        return await fetch_payment_integrity_rows(brief_fingerprint)
    return source
