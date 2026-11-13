"""ZR-029/RP-003: tests for app/testing/integrity/reconciliation.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.reconciliation import (  # noqa: E402
    ReconStatus, blocked, blocked_ids, is_fully_closed, summary,
)


def test_blocked_points_are_exactly_the_five_backlog_ids():
    assert blocked_ids() == (1, 5, 16, 18, 19)
    assert {p.point_id for p in blocked()} == {1, 5, 16, 18, 19}


def test_every_blocked_point_cites_the_unavailable_source():
    for p in blocked():
        assert p.status is ReconStatus.BLOCKED_SOURCE_UNAVAILABLE
        assert "UNAVAILABLE" in p.source


def test_blocked_points_do_not_fabricate_content():
    # honesty: the point content is explicitly recorded as undefined, never invented
    for p in blocked():
        assert "NOT fabricated" in p.note


def test_closure_is_honestly_not_full():
    assert is_fully_closed() is False


def test_summary_reports_reconciled_against_code_and_is_json_safe():
    s = summary()
    assert s["reconciled_against_code"] is True and s["fully_closed"] is False
    assert s["blocked_ids"] == [1, 5, 16, 18, 19]
    assert json.loads(json.dumps(s)) == s
