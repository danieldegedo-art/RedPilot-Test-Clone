"""ZR-007: factories that wire the durable evidence/coverage stores.

Same fail-safe, optional-capability pattern as payment_integrity.build_prioritizer /
build_feature_registry: each factory lazy-imports its SQLAlchemy store (so this module
stays importable without sqlalchemy) and returns `None` when the durable layer is
unavailable -- in which case the caller keeps using the in-memory graph/lattice object
and simply doesn't persist it. Durable persistence is strictly additive; a missing
database never affects a run's findings.

The in-memory evidence graph (evidence_graph.py) and coverage lattice
(coverage_lattice.py) are the tested logic; these factories only decide whether a
durable mirror is attached. The None-fallback branch is the one exercised in a sandbox
without sqlalchemy (see test_persistence_factories.py). Stdlib only at module import.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def build_evidence_store():
    """Return a durable evidence store, or None when sqlalchemy/the DB is unavailable."""
    try:
        from app.db.evidence_store import SQLAlchemyEvidenceStore
        return SQLAlchemyEvidenceStore()
    except Exception as exc:  # ImportError (no sqlalchemy) or any construction fault
        logger.warning("durable evidence store unavailable (%s); evidence graph stays in-memory only", exc)
        return None


def build_coverage_store():
    """Return a durable coverage-lattice store, or None when sqlalchemy/the DB is unavailable."""
    try:
        from app.db.coverage_store import SQLAlchemyCoverageStore
        return SQLAlchemyCoverageStore()
    except Exception as exc:
        logger.warning("durable coverage store unavailable (%s); coverage lattice stays in-memory only", exc)
        return None
