"""B16: tests for app/testing/integrity/feedback_loop.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.feedback_loop import (  # noqa: E402
    FeedbackEvent, Signal, apply, fold, fold_payload, initial_state,
)


def test_conclusive_signal_lowers_uncertainty():
    s = apply(initial_state("PBB-U"), FeedbackEvent("e1", "PBB-U", Signal.DENIED))
    assert s.probes == 1 and s.uncertainty == 0.5 and s.last_signal == "DENIED"
    s2 = apply(s, FeedbackEvent("e2", "PBB-U", Signal.DENIED))
    assert s2.uncertainty == 0.25


def test_inconclusive_is_not_treated_as_evidence():
    s = apply(initial_state("PBB-U"), FeedbackEvent("e1", "PBB-U", Signal.INCONCLUSIVE))
    assert s.probes == 1 and s.uncertainty == 1.0       # unchanged: a non-result is not evidence


def test_ruled_out_demotes_monotonically_and_never_removes():
    s = apply(initial_state("PBB-G"), FeedbackEvent("e1", "PBB-G", Signal.RULED_OUT))
    assert s.ruled_out is True and s.uncertainty == 1.0   # demote flag set; not treated as a conclusive lower
    s2 = apply(s, FeedbackEvent("e2", "PBB-G", Signal.ALLOWED))
    assert s2.ruled_out is True                           # monotonic -- stays ruled_out
    # the hypothesis state still exists (never skipped/removed)
    res = fold({}, [FeedbackEvent("e1", "PBB-G", Signal.RULED_OUT)], registered={"PBB-G"})
    assert "PBB-G" in res.states


def test_apply_rejects_a_mismatched_hypothesis():
    try:
        apply(initial_state("PBB-U"), FeedbackEvent("e1", "PBB-F", Signal.DENIED))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_fold_rejects_an_unregistered_hypothesis():
    try:
        fold({}, [FeedbackEvent("e1", "PBB-NEW", Signal.ALLOWED)], registered={"PBB-U"})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_fold_is_idempotent_per_event_id():
    events = [FeedbackEvent("dup", "PBB-U", Signal.DENIED), FeedbackEvent("dup", "PBB-U", Signal.DENIED)]
    res = fold({}, events, registered={"PBB-U"})
    assert res.applied == ["dup"] and res.skipped_duplicates == ["dup"]
    assert res.states["PBB-U"].probes == 1


def test_fold_order_buckets_and_json_safe():
    events = [FeedbackEvent("e1", "PBB-U", Signal.DENIED), FeedbackEvent("e2", "PBB-F", Signal.ALLOWED),
              FeedbackEvent("e3", "PBB-U", Signal.INCONCLUSIVE)]
    res = fold({}, events, registered={"PBB-U", "PBB-F"})
    assert res.applied == ["e1", "e2", "e3"]
    assert res.states["PBB-U"].probes == 2 and res.states["PBB-F"].probes == 1
    payload = fold_payload({}, events, registered={"PBB-U", "PBB-F"})
    assert json.loads(json.dumps(payload)) == payload
