"""ZR-007: tests for the durable-store factories' fail-safe fallback.

The SQLAlchemy stores can't execute without sqlalchemy; what's executable here is that
each factory returns None (in-memory only) instead of raising when the durable layer is
absent. Stdlib only.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.persistence import build_coverage_store, build_evidence_store  # noqa: E402


def test_evidence_store_factory_falls_back_to_none_without_sqlalchemy():
    assert build_evidence_store() is None


def test_coverage_store_factory_falls_back_to_none_without_sqlalchemy():
    assert build_coverage_store() is None


def test_factories_never_raise():
    # the whole point of the fail-safe pattern: construction never takes a run down
    build_evidence_store()
    build_coverage_store()
