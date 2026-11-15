#!/usr/bin/env python3
"""Execute the durable (SQLAlchemy) persistence path and prove it matches the
already-tested in-memory logic.

WHY THIS EXISTS
---------------
The SQLAlchemy stores (`app/db/pesm_store.py`, `evidence_store.py`,
`coverage_store.py`) were, by the authors' own note, "NOT EXECUTED IN THE SANDBOX
THIS WAS WRITTEN IN (no sqlalchemy)" -- only compile-checked, with the in-memory
counterparts carrying the tested logic. This harness is the executable proof that
was missing: it runs the real `SQLAlchemyPESMStore` against a real database and
asserts, operation for operation, that it behaves identically to the tested
`InMemoryPESMStore` (register / idempotent re-register / append-only states /
latest-state-by-time, including the `before=` cutoff).

It is SELF-SKIPPING: with no sqlalchemy installed (the CI/analysis sandbox) it
reports `skipped` and exits 0, so it is safe to run anywhere. Run it in an
environment that HAS the durable layer -- e.g. the project's own docker-compose
postgres, or any DB via `QA_DATABASE_URL` -- to actually exercise the SQL:

    # bring the database up first (docker compose up -d db), then:
    QA_DATABASE_URL=postgresql+asyncpg://qa_user:qa_password@localhost:5433/payment_qa \\
        python3 backend/scripts/verify_durable_persistence.py

    # or against a throwaway async sqlite (needs `pip install aiosqlite`):
    QA_DATABASE_URL=sqlite+aiosqlite:///./_verify.db \\
        python3 backend/scripts/verify_durable_persistence.py

Exit code: 0 on `passed` or `skipped`, 1 on `failed`. Stdlib-only at import; the
durable imports happen inside the function, after the availability check, so this
module imports cleanly without sqlalchemy (that is what lets the skip path be
unit-tested).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def sqlalchemy_available() -> bool:
    try:
        import sqlalchemy  # noqa: F401
        return True
    except Exception:
        return False


def run_verification() -> dict[str, Any]:
    """Returns {"status": "skipped"|"passed"|"failed", "detail": str}. Never raises
    for an expected condition (missing dep, unreachable DB) -- those are reported."""
    if not sqlalchemy_available():
        return {"status": "skipped",
                "detail": "sqlalchemy is not installed here; run this in an environment with the durable layer "
                          "(the docker-compose postgres, or an async sqlite via QA_DATABASE_URL) to execute the SQL path."}

    import asyncio
    from datetime import datetime, timedelta, timezone

    try:
        from app.core.config import settings
        from app.db.session import engine, init_db
        from app.db.pesm_store import SQLAlchemyPESMStore
        from app.testing.pesm import EntitlementState, EntitlementStatus, Feature, InMemoryPESMStore
    except Exception as exc:  # a driver dialect missing, etc.
        return {"status": "skipped", "detail": f"durable layer present but not importable here ({exc!r}); run in the full backend env."}

    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    t1 = t0 + timedelta(hours=1)
    fid, idn, ten = "feat-verify", "subject-A", None

    async def _exercise(store: Any) -> dict[str, Any]:
        await store.register_feature(Feature(feature_id=fid, name="Verify feature", discovered_via="harness", registered_at=t0))
        await store.register_feature(Feature(feature_id=fid, name="Verify feature (refined)", discovered_via="harness2", registered_at=t0))  # idempotent upsert
        await store.record_state(EntitlementState(fid, idn, ten, EntitlementStatus.NEVER_GRANTED, t0, "harness"))
        await store.record_state(EntitlementState(fid, idn, ten, EntitlementStatus.ACTIVE, t1, "harness"))  # append-only; later wins
        latest = await store.latest_state(fid, idn, ten)
        at_t0 = await store.latest_state(fid, idn, ten, before=t0)  # the before= cutoff must see only the earlier state
        return {
            "is_registered": await store.is_registered(fid),
            "latest_status": latest.status.value if latest else None,
            "status_before_t0": at_t0.status.value if at_t0 else None,
        }

    async def _go() -> dict[str, Any]:
        await init_db()  # Base.metadata.create_all picks up the PESM tables
        try:
            sql_result = await _exercise(SQLAlchemyPESMStore())
        finally:
            await engine.dispose()
        mem_result = await _exercise(InMemoryPESMStore())
        return {"sql": sql_result, "mem": mem_result}

    try:
        out = asyncio.run(_go())
    except Exception as exc:  # most commonly: DB unreachable
        return {"status": "failed",
                "detail": f"could not execute against {settings.database_url!r}: {exc!r}. Bring the database up "
                          f"(e.g. `docker compose up -d db`) or point QA_DATABASE_URL at a reachable DB, then retry."}

    if out["sql"] != out["mem"]:
        return {"status": "failed",
                "detail": f"SQLAlchemy store diverged from the tested in-memory store: SQL={out['sql']} vs IN-MEMORY={out['mem']}"}
    expected = {"is_registered": True, "latest_status": "active", "status_before_t0": "never_granted"}
    if out["sql"] != expected:
        return {"status": "failed", "detail": f"round-trip result {out['sql']} != expected {expected}"}
    return {"status": "passed",
            "detail": f"SQLAlchemyPESMStore matches InMemoryPESMStore on register/idempotent-upsert/append-only/"
                      f"latest-state(+before=), against {settings.database_url!r}. Result: {out['sql']}."}


def main(argv: list[str] | None = None) -> int:
    result = run_verification()
    print(f"[{result['status'].upper()}] durable persistence verification: {result['detail']}")
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
