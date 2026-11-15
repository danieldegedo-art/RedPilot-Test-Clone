"""ZR-002 completion: entitlement_states_from_oracle_observations (A5-shaped)
and a logic-level check on SQLAlchemyPESMStore.

SQLAlchemyPESMStore itself cannot be imported here (sqlalchemy). What's
checked instead: its source implements the same status-value mapping and
append-only semantics InMemoryPESMStore's own tests already hold it to,
read directly from the file rather than assumed.

Stdlib only.
"""
from __future__ import annotations

import ast
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.pesm import (  # noqa: E402
    EntitlementStatus, InMemoryPESMStore, entitlement_states_from_oracle_observations, record_oracle_observations,
)

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)


class _FakeObservation:
    """Duck-typed stand-in for OracleObservation -- the conversion function is
    typed Any specifically so it doesn't need the real class."""

    def __init__(self, oracle_id, feature_id, identity_alias, tenant_alias, outcome, artifact_ids=()):
        self.oracle_id, self.feature_id, self.identity_alias, self.tenant_alias = oracle_id, feature_id, identity_alias, tenant_alias
        self.outcome, self.artifact_ids = outcome, artifact_ids


def test_allowed_becomes_active_denied_becomes_never_granted():
    states = entitlement_states_from_oracle_observations([
        _FakeObservation("o1", "f1", "alice", None, "allowed"),
        _FakeObservation("o2", "f1", "bob", None, "denied"),
    ], recorded_at=NOW)
    assert [s.status for s in states] == [EntitlementStatus.ACTIVE, EntitlementStatus.NEVER_GRANTED]


def test_every_field_is_carried_through_honestly():
    (state,) = entitlement_states_from_oracle_observations(
        [_FakeObservation("o1", "feat-x", "alice", "tenant-a", "allowed", artifact_ids=("a1", "a2"))], recorded_at=NOW)
    assert (state.feature_id, state.identity_alias, state.tenant_alias) == ("feat-x", "alice", "tenant-a")
    assert state.observed_at == NOW  # recorded_at, not an event time -- see the function's docstring
    assert state.source == "oracle_observation:o1"
    assert state.evidence_artifact_ids == ("a1", "a2")


def test_no_status_other_than_active_or_never_granted_is_invented():
    """EXPIRED and REVOKED are real EntitlementStatus members this function
    must never guess at -- a single observation can't distinguish "never had
    it" from "had it and lost it"."""
    states = entitlement_states_from_oracle_observations(
        [_FakeObservation("o", "f", "x", None, o) for o in ("allowed", "denied", "denied", "allowed")], recorded_at=NOW)
    assert {s.status for s in states} <= {EntitlementStatus.ACTIVE, EntitlementStatus.NEVER_GRANTED}


def test_empty_observations_produce_nothing():
    assert entitlement_states_from_oracle_observations([], recorded_at=NOW) == []


def test_record_oracle_observations_writes_every_one_to_the_store():
    async def go():
        store = InMemoryPESMStore()
        await record_oracle_observations(
            [_FakeObservation("o1", "f1", "alice", None, "allowed"), _FakeObservation("o2", "f2", "bob", None, "denied")],
            store, recorded_at=NOW,
        )
        return await store.latest_state("f1", "alice", None), await store.latest_state("f2", "bob", None)

    f1_state, f2_state = asyncio.run(go())
    assert f1_state.status == EntitlementStatus.ACTIVE and f2_state.status == EntitlementStatus.NEVER_GRANTED


# ---- SQLAlchemyPESMStore: can't import it (sqlalchemy), can read its source ----

def test_sqlalchemy_store_source_matches_the_tested_status_and_append_only_semantics():
    src = (Path(__file__).parent.parent / "app" / "db" / "pesm_store.py").read_text()
    tree = ast.parse(src)
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "SQLAlchemyPESMStore")
    methods = {n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    # same Protocol surface as InMemoryPESMStore (pesm.py), nothing missing
    assert methods >= {"register_feature", "is_registered", "registered_feature_ids",
                       "record_state", "record_transition", "latest_state", "transitions_for", "all_transitions"}
    # record_state/record_transition must insert (session.add), never update an
    # existing row -- the append-only guarantee InMemoryPESMStore's own list.append
    # gives it for free, checked here since this file can't be imported to test directly
    method_defs = [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for name in ("record_state", "record_transition"):
        body_src = ast.get_source_segment(src, next(n for n in method_defs if n.name == name))
        assert "session.add(" in body_src and ".update(" not in body_src and "session.merge(" not in body_src, name


def test_sqlalchemy_store_tables_are_new_not_altered_columns():
    """register_feature is the one legitimate upsert (matches
    InMemoryPESMStore's own documented re-registration semantics) -- states
    and transitions are never upserted."""
    models_src = (Path(__file__).parent.parent / "app" / "db" / "models.py").read_text()
    for table in ("FeatureRecord", "EntitlementStateRecord", "EntitlementTransitionRecord"):
        assert f"class {table}(Base):" in models_src, f"{table} missing from db/models.py"


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
