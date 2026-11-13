"""Regression tests for the two Wissensspeicher bugs found in this audit:

1. storage_path was scoped by run_id, so every run got a brand-new, empty
   database -- "cross-session knowledge accumulation" was never actually
   happening despite every docstring in this package describing it. Fixed
   by scoping storage by app.testing.url_utils.target_identity_key
   instead (see runner.py).
2. Once record_outcome()/learn_from_execution() were made to offload
   their SQLite writes via asyncio.to_thread (to stop blocking the event
   loop), the connection needed check_same_thread=False and a lock, or it
   crashed/could corrupt state under real concurrent access.
"""
from __future__ import annotations

import asyncio

import pytest

from app.testing.cognition.persistent_memory import PersistentMemoryStore


def test_cross_session_accumulation(tmp_path):
    """Two separate PersistentMemoryStore instances pointed at the same
    storage_path -- exactly what two separate runs against the same
    target now produce -- must see each other's data."""
    storage_path = tmp_path / "qa_cognition" / "shared-target"

    store1 = PersistentMemoryStore(storage_path=str(storage_path))
    store1.start_session({"run_id": "run-1"})
    for i in range(5):
        store1.store_episodic(
            memory_type="test_result",
            content={"i": i},
            context={"endpoint": f"/x/{i}"},
            outcome="pass",
        )
    store1.end_session({"total_results": 5})
    store1.close()

    store2 = PersistentMemoryStore(storage_path=str(storage_path))
    stats = store2.get_statistics()
    assert stats["total_episodic"] == 5, "second instance against the same path should see the first instance's data"
    assert stats["total_sessions"] == 1

    store2.start_session({"run_id": "run-2"})
    for i in range(3):
        store2.store_episodic(
            memory_type="test_result",
            content={"i": i},
            context={"endpoint": f"/x/{i}"},
            outcome="pass",
        )
    store2.end_session({"total_results": 3})

    stats = store2.get_statistics()
    assert stats["total_episodic"] == 8, "episodic count should accumulate (5 + 3), not reset per session"
    assert stats["total_sessions"] == 2
    store2.close()


def test_different_targets_stay_isolated(tmp_path):
    """Two DIFFERENT storage paths (i.e. two different targets) must not
    see each other's data -- accumulation is per-target, not global."""
    store_a = PersistentMemoryStore(storage_path=str(tmp_path / "qa_cognition" / "target-a"))
    store_a.store_episodic(memory_type="test_result", content={}, context={}, outcome="pass")
    store_a.close()

    store_b = PersistentMemoryStore(storage_path=str(tmp_path / "qa_cognition" / "target-b"))
    assert store_b.get_statistics()["total_episodic"] == 0
    store_b.close()


@pytest.mark.asyncio
async def test_concurrent_writes_do_not_crash(tmp_path):
    """The exact scenario that would crash without check_same_thread=False
    + a lock: many concurrent asyncio.to_thread-offloaded writes against
    one store, from the kind of concurrent load a live dashboard polling
    a run in progress could plausibly produce."""
    store = PersistentMemoryStore(storage_path=str(tmp_path / "qa_cognition" / "concurrency-target"))

    async def write_one(i: int) -> None:
        await asyncio.to_thread(
            store.store_episodic,
            memory_type="test_result",
            content={"i": i},
            context={"endpoint": f"/x/{i}"},
            outcome="pass",
        )

    await asyncio.gather(*[write_one(i) for i in range(30)])

    stats = store.get_statistics()
    assert stats["total_episodic"] == 30, "all 30 concurrent writes should have landed, none lost or crashed"
    store.close()
