"""SQLAlchemy 2.0 async ORM models. Schema is created via
Base.metadata.create_all on backend startup for this delivery -- swap in
Alembic migrations before pointing this at a shared/production Postgres
instance (see README roadmap)."""
from __future__ import annotations

from app.testing.module_defaults import DEFAULT_ENABLED_MODULES

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class RunRecord(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    environment_url: Mapped[str] = mapped_column(String(2048))
    scope: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cognitive_snapshot_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Populated only when TestRunner.execute() itself raised (a bug outside
    # any single module/analyzer's own try/except -- see runner.py and
    # api/v1/runs.py's _execute_and_persist). Before this fix, that case left
    # the row stuck at its last-persisted status forever with no visible
    # error anywhere outside backend logs; now `status` becomes "failed"
    # (see enums.RunStatus.FAILED, already defined but never actually set
    # before this pass) and this column carries why.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    results: Mapped[list["TestResultRecord"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class TestResultRecord(Base):
    __tablename__ = "test_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    test_case_id: Mapped[str] = mapped_column(String(48))
    category: Mapped[str] = mapped_column(String(48))
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    input_parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    expected: Mapped[str] = mapped_column(Text)
    actual: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))
    request_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[float] = mapped_column(Float)

    run: Mapped["RunRecord"] = relationship(back_populates="results")


class SettingsRecord(Base):
    __tablename__ = "settings"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="default")
    timeout_seconds: Mapped[float] = mapped_column(Float, default=30.0)
    proxy_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    custom_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    user_agent: Mapped[str] = mapped_column(String(256), default="PaymentQA-Suite/1.0")
    enabled_modules: Mapped[list] = mapped_column(
        JSON,
        default=lambda: list(DEFAULT_ENABLED_MODULES),
    )
    discovery_layer_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # See RunSettings.prioritize_experiments (context.py). New column -- see
    # this session's notes on the migration this needs on an existing database.
    prioritize_experiments: Mapped[bool] = mapped_column(Boolean, default=False)
    endpoint_overrides: Mapped[dict] = mapped_column(JSON, default=dict)
    session_cookies: Mapped[dict] = mapped_column(JSON, default=dict)
    # list[{"method": ..., "path": ...}] -- see SettingsSchema.manual_routes.
    manual_routes: Mapped[list] = mapped_column(JSON, default=list)
    # See SettingsSchema's matching fields for what each controls.
    http_max_retries: Mapped[int] = mapped_column(Integer, default=2)
    http_retry_base_delay_seconds: Mapped[float] = mapped_column(Float, default=0.5)
    http_circuit_breaker_threshold: Mapped[int] = mapped_column(Integer, default=5)
    http_circuit_breaker_cooldown_seconds: Mapped[float] = mapped_column(Float, default=20.0)
    module_concurrency: Mapped[int] = mapped_column(Integer, default=4)
    # list[{"provider_id":..., "display_name":..., "method":..., "path":..., "signature_header":...}]
    # -- see SettingsSchema.additional_webhook_providers.
    additional_webhook_providers: Mapped[list] = mapped_column(JSON, default=list)


class FeatureRecord(Base):
    """ZR-002: a registered paid/protected capability (see app/testing/pesm.py's
    Feature). New table -- create_all picks this up without a manual migration."""

    __tablename__ = "pesm_features"

    feature_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    discovered_via: Mapped[str] = mapped_column(String(300))
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EntitlementStateRecord(Base):
    """ZR-002: one immutable entitlement snapshot (see pesm.py's EntitlementState).
    Append-only -- rows are never updated, only inserted; id is a surrogate key,
    not a natural one, specifically because the snapshot itself has none."""

    __tablename__ = "pesm_entitlement_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    feature_id: Mapped[str] = mapped_column(String(200), index=True)
    identity_alias: Mapped[str] = mapped_column(String(200), index=True)
    tenant_alias: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(50))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(300))
    evidence_artifact_ids: Mapped[list] = mapped_column(JSON, default=list)


class EntitlementTransitionRecord(Base):
    """ZR-002: one lifecycle transition (see pesm.py's EntitlementTransition). Append-only."""

    __tablename__ = "pesm_entitlement_transitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    feature_id: Mapped[str] = mapped_column(String(200), index=True)
    identity_alias: Mapped[str] = mapped_column(String(200), index=True)
    tenant_alias: Mapped[str | None] = mapped_column(String(200), nullable=True)
    from_status: Mapped[str] = mapped_column(String(50))
    to_status: Mapped[str] = mapped_column(String(50))
    trigger: Mapped[str] = mapped_column(String(300))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    evidence_artifact_ids: Mapped[list] = mapped_column(JSON, default=list)


class EvidenceNodeRecord(Base):
    """ZR-007: durable mirror of one evidence_graph.EvidenceNode, keyed by the graph it
    belongs to (one graph per confirmed finding/run). New table; create_all picks it up.
    NOT EXECUTED in the sandbox this was written in (no sqlalchemy) -- the graph LOGIC is
    tested in test_evidence_graph.py; this persists it."""

    __tablename__ = "evidence_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    graph_id: Mapped[str] = mapped_column(String(200), index=True)
    node_id: Mapped[str] = mapped_column(String(200), index=True)
    kind: Mapped[str] = mapped_column(String(50))
    reference_id: Mapped[str] = mapped_column(String(200))
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvidenceEdgeRecord(Base):
    """ZR-007: durable mirror of one evidence_graph.EvidenceEdge (open relationship
    vocabulary)."""

    __tablename__ = "evidence_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    graph_id: Mapped[str] = mapped_column(String(200), index=True)
    from_node: Mapped[str] = mapped_column(String(200))
    to_node: Mapped[str] = mapped_column(String(200))
    relationship_kind: Mapped[str] = mapped_column(String(100))


class CoverageCellRecord(Base):
    """ZR-007 / B18: durable mirror of one coverage_lattice.LatticeCell -- a
    (hypothesis_class, flow_type, test_scope) triple with its observed count, keyed by
    the lattice/run it belongs to. Append/upsert on count. New table."""

    __tablename__ = "coverage_cells"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    lattice_id: Mapped[str] = mapped_column(String(200), index=True)
    hypothesis_class: Mapped[str] = mapped_column(String(100), index=True)
    flow_type: Mapped[str] = mapped_column(String(100))
    test_scope: Mapped[str] = mapped_column(String(100))
    count: Mapped[int] = mapped_column(Integer, default=0)
