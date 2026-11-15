"""Regression tests for CoverageMapper:

1. It was imported into CognitiveEngine but never instantiated at all --
   completely dead code despite being a fully-built, 876-line component.
   Now wired in via CognitiveEngine.__init__'s coverage_db_path param.
2. Even once wired in and persisting to SQLite correctly, a fresh
   instance never read that data back on startup -- writes accumulated
   in the database but every new run started from an empty in-memory
   graph regardless. Fixed by _load_existing_coverage().
"""
from __future__ import annotations

from app.testing.cognition.coverage_mapper import CoverageMapper


def test_coverage_accumulates_across_instances(tmp_path):
    """A fresh CoverageMapper pointed at a path with existing data must
    see the FULL cumulative picture, not just start empty -- this is the
    reload-from-DB fix specifically."""
    db_path = tmp_path / "qa_cognition" / "target" / "coverage.db"

    mapper1 = CoverageMapper(db_path=str(db_path))
    for i in range(3):
        mapper1.add_endpoint(f"/api/v1/subscriptions/{i}", "PATCH")
        mapper1.record_test(path=f"/api/v1/subscriptions/{i}", method="PATCH", check_type="role_based_access", detected=False)
    report1 = mapper1.calculate_coverage()
    assert report1.total_endpoints == 3
    mapper1.conn.close()

    mapper2 = CoverageMapper(db_path=str(db_path))
    report2_before_new = mapper2.calculate_coverage()
    assert report2_before_new.total_endpoints == 3, "fresh instance against the same path must reload the prior 3 endpoints"

    for i in range(3, 5):
        mapper2.add_endpoint(f"/api/v1/subscriptions/{i}", "PATCH")
        mapper2.record_test(path=f"/api/v1/subscriptions/{i}", method="PATCH", check_type="role_based_access", detected=False)
    report2 = mapper2.calculate_coverage()
    assert report2.total_endpoints == 5, "3 reloaded + 2 new = 5"
    assert report2.tested_endpoints == 5
    mapper2.conn.close()


def test_in_memory_only_mode_still_works():
    """db_path=None (the default) should keep working exactly as before
    -- no persistence, no crash."""
    mapper = CoverageMapper(db_path=None)
    mapper.add_endpoint("/api/v1/x", "GET")
    mapper.record_test(path="/api/v1/x", method="GET", check_type="processing_integrity", detected=False)
    report = mapper.calculate_coverage()
    assert report.total_endpoints == 1
    assert mapper.conn is None
