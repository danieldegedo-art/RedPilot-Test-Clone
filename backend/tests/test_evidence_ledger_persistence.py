"""ZR-009, the evidence-artifact layer: EvidenceLedger.accepted was a plain
in-memory dict with no durability path at all -- a Finding's artifact_ids
(now durably saved as part of TestResultRecord, see
test_write_through_persistence.py) pointed to EvidenceArtifact objects that
vanished the moment the run's EvidenceLedger instance was garbage collected.
This is the layer runner.py's fix didn't reach: a TestResult/Finding
*summary* surviving is not the same as the *evidence it's built from*
surviving, and ZR-015 (replay bundles -- "a third party reproduces a finding
from the bundle alone") needs the latter.

Mirrors test_write_through_persistence.py's structure exactly (fake
persist function, no real DB needed) -- same reasoning applies: try_admit()
is synchronous (many existing callers throughout integrity/ depend on
that), so artifacts are buffered there and only actually written through by
the async flush_pending(), which a caller invokes periodically.

Stdlib only.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import EvidenceClass, build_artifact  # noqa: E402
from app.enterprise_controls.provenance import EvidenceLedger, _noop_persist_artifact  # noqa: E402


def _artifact(sequence: int = 0, identity: str = "clean-id"):
    return build_artifact(
        payload={"status": 200, "body": {"ok": True}}, source_type="http_response",
        classification=EvidenceClass.EXTERNAL_BROWSER, identity_alias=identity, tenant_alias=None,
        target="https://shop.example.test/api/checkout", session_isolation_id=f"s{sequence}",
        authorization_ref="auth-1", sequence=sequence,
    )


def _ledger(persist_artifact=None) -> EvidenceLedger:
    return EvidenceLedger(authorization_ref="auth-1", approved_identity_aliases=["clean-id"], persist_artifact=persist_artifact)


def test_default_construction_is_backward_compatible_noop():
    ledger = _ledger()
    assert ledger._persist_artifact is _noop_persist_artifact
    ok, reasons = ledger.try_admit(_artifact(0))
    assert ok and not reasons
    asyncio.run(ledger.flush_pending())  # must not raise
    assert ledger.persist_failures == []


def test_try_admit_buffers_flush_pending_writes_through():
    written = []

    async def fake_persist(artifact):
        written.append(artifact.artifact_id)

    ledger = _ledger(persist_artifact=fake_persist)
    art = _artifact(0)
    ok, _ = ledger.try_admit(art)
    assert ok
    assert written == [], "must not be written before flush_pending runs"
    assert art.artifact_id in ledger.accepted, "usable within the run immediately, independent of durability"

    asyncio.run(ledger.flush_pending())
    assert written == [art.artifact_id]


def test_a_crash_between_experiments_leaves_everything_flushed_so_far_durable():
    """The actual scenario: PureBlackBoxEngine.run() flushes after every
    experiment (engine.py), not only once at the end. Simulates that loop
    directly: admit evidence for experiment 1, flush, admit evidence for
    experiment 2, then crash before experiment 2's flush."""
    durable = []

    async def fake_persist(artifact):
        durable.append(artifact.artifact_id)

    exp1_artifact_id = None

    async def two_experiments_then_crash():
        nonlocal exp1_artifact_id
        ledger = _ledger(persist_artifact=fake_persist)
        exp1 = _artifact(0)
        exp1_artifact_id = exp1.artifact_id
        ledger.try_admit(exp1)
        await ledger.flush_pending()  # "experiment 1" finished normally
        ledger.try_admit(_artifact(1))
        raise RuntimeError("simulated crash mid experiment-2, before its flush")

    try:
        asyncio.run(two_experiments_then_crash())
        raise AssertionError("expected the simulated crash to propagate")
    except RuntimeError:
        pass

    assert durable == [exp1_artifact_id], "only experiment 1's artifact should be durable"


def test_flush_pending_is_idempotent_nothing_double_flushed():
    calls = []

    async def fake_persist(artifact):
        calls.append(artifact.artifact_id)

    async def go():
        ledger = _ledger(persist_artifact=fake_persist)
        art = _artifact(0)
        ledger.try_admit(art)
        await ledger.flush_pending()
        await ledger.flush_pending()  # nothing new pending -- must not re-persist
        return calls, art.artifact_id

    result, expected_id = asyncio.run(go())
    assert result == [expected_id]


def test_a_persist_failure_is_caught_logged_and_recorded_not_raised():
    async def always_fails(artifact):
        raise ConnectionError("simulated transient DB error")

    ledger = _ledger(persist_artifact=always_fails)
    art = _artifact(0)
    ledger.try_admit(art)
    asyncio.run(ledger.flush_pending())  # must not raise

    assert ledger.persist_failures == [art.artifact_id]
    assert art.artifact_id in ledger.accepted  # still usable within the run


def test_rejected_artifacts_are_never_buffered_for_persistence():
    """An artifact that fails provenance validation never reaches
    try_admit's success path -- must never reach the persist buffer either."""
    written = []

    async def fake_persist(artifact):
        written.append(artifact.artifact_id)

    ledger = _ledger(persist_artifact=fake_persist)
    bad = _artifact(0, identity="not-an-approved-identity")  # not in approved_identity_aliases
    ok, reasons = ledger.try_admit(bad)
    assert not ok and reasons

    asyncio.run(ledger.flush_pending())
    assert written == []


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
