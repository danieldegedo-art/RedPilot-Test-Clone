"""Regression tests for the data-layer hardening pass:

1. PersistentMemoryStore/CoverageMapper now use WAL journal mode instead
   of the SQLite default -- readers (get_statistics(), query_episodic(),
   calculate_coverage()) must not block behind an in-flight
   asyncio.to_thread-offloaded write.
2. episodic_memories was missing an index on `timestamp`, the column
   query_episodic() sorts by -- harmless while cross-session accumulation
   was broken (every run started empty), but a real cost now that it
   works.
3. CoverageMapper._load_existing_coverage() used to load the ENTIRE
   test_history table into a Python list on every construction purely to
   support len(...) in get_statistics(); nothing else ever read a row's
   contents. Replaced with a plain counter reconstructed via COUNT(*).
4. Both stores accumulate forever by design; prune_episodic_older_than /
   prune_test_history_older_than give an operator an explicit,
   configurable way to bound that growth (never called automatically by
   either class).
"""
from __future__ import annotations

import time

from app.testing.cognition.coverage_mapper import CoverageMapper
from app.testing.cognition.persistent_memory import PersistentMemoryStore


class TestPersistentMemoryHardening:
    def test_wal_mode_is_active(self, tmp_path):
        store = PersistentMemoryStore(storage_path=str(tmp_path / "target" / "memory"))
        mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

    def test_timestamp_index_exists(self, tmp_path):
        store = PersistentMemoryStore(storage_path=str(tmp_path / "target" / "memory"))
        index_names = {row[0] for row in store._conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_episodic_timestamp" in index_names

    def test_prune_episodic_older_than_removes_only_old_rows(self, tmp_path):
        store = PersistentMemoryStore(storage_path=str(tmp_path / "target" / "memory"))
        old_memory = store.store_episodic(memory_type="ambiguous_case_resolution", content={"x": 1}, outcome="critical", tags=["t"])
        store._conn.execute(
            "UPDATE episodic_memories SET timestamp = ? WHERE id = ?", (time.time() - 999_999, old_memory.id)
        )
        store._conn.commit()
        new_memory = store.store_episodic(memory_type="ambiguous_case_resolution", content={"x": 2}, outcome="critical", tags=["t"])

        deleted = store.prune_episodic_older_than(max_age_seconds=3600)

        assert deleted == 1
        remaining = store.query_episodic(memory_type="ambiguous_case_resolution", limit=10)
        assert [m.id for m in remaining] == [new_memory.id]


class TestCoverageMapperHardening:
    def test_wal_mode_is_active(self, tmp_path):
        mapper = CoverageMapper(db_path=str(tmp_path / "target" / "coverage.db"))
        mode = mapper.conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

    def test_test_history_is_a_counter_not_a_loaded_list(self, tmp_path):
        """The old `self.test_history: list` is gone entirely -- verified
        (repo-wide grep) that nothing outside this class ever read its
        contents, only its length."""
        mapper = CoverageMapper(db_path=str(tmp_path / "target" / "coverage.db"))
        assert not hasattr(mapper, "test_history")
        for i in range(5):
            mapper.add_endpoint(f"/api/v1/x/{i}", "GET")
            mapper.record_test(path=f"/api/v1/x/{i}", method="GET", check_type="role_based_access", detected=False)
        assert mapper._test_history_count == 5
        assert mapper.get_statistics()["total_tests_recorded"] == 5
        mapper.conn.close()

    def test_reload_reconstructs_the_counter_via_count_not_a_full_load(self, tmp_path):
        db_path = str(tmp_path / "target" / "coverage.db")
        mapper1 = CoverageMapper(db_path=db_path)
        for i in range(7):
            mapper1.add_endpoint(f"/api/v1/x/{i}", "GET")
            mapper1.record_test(path=f"/api/v1/x/{i}", method="GET", check_type="role_based_access", detected=False)
        mapper1.conn.close()

        mapper2 = CoverageMapper(db_path=db_path)
        assert mapper2._test_history_count == 7
        mapper2.add_endpoint("/api/v1/x/new", "GET")
        mapper2.record_test(path="/api/v1/x/new", method="GET", check_type="role_based_access", detected=False)
        assert mapper2._test_history_count == 8
        mapper2.conn.close()

    def test_prune_test_history_leaves_endpoint_coverage_untouched(self, tmp_path):
        mapper = CoverageMapper(db_path=str(tmp_path / "target" / "coverage.db"))
        for i in range(4):
            mapper.add_endpoint(f"/api/v1/x/{i}", "GET")
            mapper.record_test(path=f"/api/v1/x/{i}", method="GET", check_type="role_based_access", detected=False)

        deleted = mapper.prune_test_history_older_than(max_age_seconds=0)

        assert deleted == 4
        assert mapper._test_history_count == 0
        report = mapper.calculate_coverage()
        assert report.total_endpoints == 4, "endpoint_coverage is a separate table from the event log and must survive pruning it"
        mapper.conn.close()
