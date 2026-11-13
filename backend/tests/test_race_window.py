"""B12: tests for app/testing/integrity/race_window.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.race_window import (  # noqa: E402
    Operation, RaceStatus, detect, detect_payload, suggest_probe_concurrency,
)


def _ops(*spans):
    return [Operation(f"op{i}", s, e) for i, (s, e) in enumerate(spans)]


def test_window_found_when_concurrent_grants_exceed_quota():
    r = detect(_ops((0, 10), (0, 10), (0, 10)), quota=1)
    assert r.status == RaceStatus.WINDOW_FOUND and r.max_concurrent == 3
    assert set(r.overlapping) == {"op0", "op1", "op2"}


def test_no_window_when_operations_are_sequential():
    r = detect(_ops((0, 1), (2, 3), (4, 5)), quota=1)
    assert r.status == RaceStatus.NO_WINDOW and r.max_concurrent == 1


def test_touching_intervals_count_as_concurrent():
    r = detect(_ops((0, 5), (5, 10)), quota=1)
    assert r.status == RaceStatus.WINDOW_FOUND and r.max_concurrent == 2


def test_quota_boundary_is_strict_greater_than():
    assert detect(_ops((0, 10), (0, 10)), quota=2).status == RaceStatus.NO_WINDOW   # 2 not > 2
    assert detect(_ops((0, 10), (0, 10), (0, 10)), quota=2).status == RaceStatus.WINDOW_FOUND  # 3 > 2


def test_suggest_probe_concurrency_is_bounded_and_capped():
    assert suggest_probe_concurrency(1) == 3
    assert suggest_probe_concurrency(5) == 7
    assert suggest_probe_concurrency(100, cap=16) == 16


def test_validation_rejects_bad_inputs():
    try:
        detect(_ops((0, 10)), quota=0)
        assert False, "expected ValueError (quota)"
    except ValueError:
        pass
    try:
        detect([Operation("bad", 10, 5)], quota=1)
        assert False, "expected ValueError (end<start)"
    except ValueError:
        pass
    try:
        detect(_ops((0, 1), (0, 1), (0, 1)), quota=1, max_ops=2)
        assert False, "expected ValueError (cap)"
    except ValueError:
        pass


def test_empty_and_payload_json_safe():
    r = detect([], quota=1)
    assert r.status == RaceStatus.NO_WINDOW and r.max_concurrent == 0
    payload = detect_payload(_ops((0, 10), (0, 10), (0, 10)), quota=1)
    assert payload["suggested_probe_concurrency"] == 3
    assert json.loads(json.dumps(payload)) == payload
