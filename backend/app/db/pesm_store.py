"""ZR-002: the durable half of PESM. Implements app.testing.pesm.PESMStore
against the tables in app/db/models.py (FeatureRecord,
EntitlementStateRecord, EntitlementTransitionRecord).

NOT EXECUTED IN THE SANDBOX THIS WAS WRITTEN IN (no sqlalchemy) -- same
status every other app/db/*.py module in this project had when it was
written (app/db/memory.py, _persist_result_db). What IS tested is
app.testing.pesm's own InMemoryPESMStore, which this class is a drop-in
replacement for (both satisfy the same Protocol structurally -- see
pesm.py's PESMStore, no explicit inheritance needed); that test suite
exercises the *logic* this class also needs to get right (append-only
states/transitions, idempotent feature registration, latest-state-by-time
queries). What needs confirming against a real database, once, is that this
SQL actually implements that same logic.

The two new tables this writes (FeatureRecord / EntitlementStateRecord /
EntitlementTransitionRecord -- three, not two) are NEW tables, not new
columns on an existing one, so Base.metadata.create_all picks them up
automatically on next startup -- unlike SettingsRecord's new column (see
CHANGELOG.md), no manual ALTER TABLE is needed for these specifically.

Each method opens its own short-lived session (same per-unit-of-work pattern
as api/v1/runs.py's _persist_result_db and provenance.py's flush_pending --
never a session reused across an await boundary it didn't open).

WIRED (this session): modules/payment_integrity.py's build_feature_registry()
constructs a SQLAlchemyPESMStore (lazy import, fail-safe fallback to the
in-memory store) and sets it as context.feature_registry, so the run's
record_oracle_observations writes through it. The fallback path is tested
(test_feature_registry_wiring.py); this durable path is compile-checked, NOT
executed (no sqlalchemy here). The models it targets were also de-duplicated
this session -- models.py had defined the 3 PESM tables twice; the kept block
is the one whose column names match this store (evidence_artifact_ids).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from app.db.models import EntitlementStateRecord, EntitlementTransitionRecord, FeatureRecord
from app.db.session import SessionLocal
from app.testing.pesm import EntitlementState, EntitlementStatus, EntitlementTransition, Feature


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class SQLAlchemyPESMStore:
    """No in-process state of its own -- cheap to construct, safe to share
    across concurrent callers (every method opens its own session)."""

    async def register_feature(self, feature: Feature) -> None:
        async with SessionLocal() as session:
            existing = await session.get(FeatureRecord, feature.feature_id)
            if existing is None:
                session.add(FeatureRecord(feature_id=feature.feature_id, name=feature.name,
                                          discovered_via=feature.discovered_via, registered_at=_utc(feature.registered_at)))
            else:
                # Same upsert semantics as InMemoryPESMStore.register_feature:
                # re-registering refines name/discovered_via as more surface is mapped.
                existing.name, existing.discovered_via, existing.registered_at = feature.name, feature.discovered_via, _utc(feature.registered_at)
            await session.commit()

    async def is_registered(self, feature_id: str) -> bool:
        async with SessionLocal() as session:
            return await session.get(FeatureRecord, feature_id) is not None

    async def registered_feature_ids(self) -> frozenset[str]:
        async with SessionLocal() as session:
            rows = (await session.execute(select(FeatureRecord.feature_id))).scalars().all()
        return frozenset(rows)

    async def record_state(self, state: EntitlementState) -> None:
        async with SessionLocal() as session:
            session.add(EntitlementStateRecord(
                feature_id=state.feature_id, identity_alias=state.identity_alias, tenant_alias=state.tenant_alias,
                status=state.status.value, observed_at=_utc(state.observed_at), source=state.source,
                evidence_artifact_ids=list(state.evidence_artifact_ids),
            ))
            await session.commit()

    async def record_transition(self, transition: EntitlementTransition) -> None:
        async with SessionLocal() as session:
            session.add(EntitlementTransitionRecord(
                feature_id=transition.feature_id, identity_alias=transition.identity_alias, tenant_alias=transition.tenant_alias,
                from_status=transition.from_status.value, to_status=transition.to_status.value, trigger=transition.trigger,
                occurred_at=_utc(transition.occurred_at), evidence_artifact_ids=list(transition.evidence_artifact_ids),
            ))
            await session.commit()

    async def latest_state(
        self, feature_id: str, identity_alias: str, tenant_alias: str | None, *, before: datetime | None = None,
    ) -> EntitlementState | None:
        stmt = (
            select(EntitlementStateRecord)
            .where(EntitlementStateRecord.feature_id == feature_id, EntitlementStateRecord.identity_alias == identity_alias,
                   EntitlementStateRecord.tenant_alias == tenant_alias)
            .order_by(EntitlementStateRecord.observed_at.desc())
            .limit(1)
        )
        if before is not None:
            stmt = stmt.where(EntitlementStateRecord.observed_at <= _utc(before))
        async with SessionLocal() as session:
            row = (await session.execute(stmt)).scalars().first()
        return None if row is None else self._to_state(row)

    @staticmethod
    def _to_state(row: EntitlementStateRecord) -> EntitlementState:
        return EntitlementState(feature_id=row.feature_id, identity_alias=row.identity_alias, tenant_alias=row.tenant_alias,
                                status=EntitlementStatus(row.status), observed_at=row.observed_at, source=row.source,
                                evidence_artifact_ids=tuple(row.evidence_artifact_ids or ()))

    async def transitions_for(
        self, feature_id: str, identity_alias: str, tenant_alias: str | None,
    ) -> tuple[EntitlementTransition, ...]:
        stmt = select(EntitlementTransitionRecord).where(
            EntitlementTransitionRecord.feature_id == feature_id, EntitlementTransitionRecord.identity_alias == identity_alias,
            EntitlementTransitionRecord.tenant_alias == tenant_alias,
        ).order_by(EntitlementTransitionRecord.occurred_at)
        async with SessionLocal() as session:
            rows = (await session.execute(stmt)).scalars().all()
        return tuple(self._to_transition(r) for r in rows)

    async def all_transitions(self) -> tuple[EntitlementTransition, ...]:
        async with SessionLocal() as session:
            rows = (await session.execute(select(EntitlementTransitionRecord).order_by(EntitlementTransitionRecord.occurred_at))).scalars().all()
        return tuple(self._to_transition(r) for r in rows)

    @staticmethod
    def _to_transition(row: EntitlementTransitionRecord) -> EntitlementTransition:
        return EntitlementTransition(feature_id=row.feature_id, identity_alias=row.identity_alias, tenant_alias=row.tenant_alias,
                                     from_status=EntitlementStatus(row.from_status), to_status=EntitlementStatus(row.to_status),
                                     trigger=row.trigger, occurred_at=row.occurred_at, evidence_artifact_ids=tuple(row.evidence_artifact_ids or ()))
