"""B19: tests for app/testing/integrity/shadow_ledger.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.shadow_ledger import (  # noqa: E402
    ShadowLedgerStatus, cross_check, cross_check_payload,
)


def test_inconsistent_grant_is_the_strong_signal():
    r = cross_check("denied", "allowed")   # ledger: no charge; app: access
    assert r.status == ShadowLedgerStatus.INCONSISTENT_GRANT and r.is_lead
    assert "14.1" in r.note and "ZR-017" in r.note


def test_inconsistent_deny():
    r = cross_check("allowed", "denied")
    assert r.status == ShadowLedgerStatus.INCONSISTENT_DENY and r.is_lead


def test_consistent_when_both_agree():
    assert cross_check("allowed", "allowed").status == ShadowLedgerStatus.CONSISTENT
    assert cross_check("denied", "denied").status == ShadowLedgerStatus.CONSISTENT
    assert cross_check("allowed", "allowed").is_lead is False


def test_indeterminate_when_either_side_unknown():
    assert cross_check("indeterminate", "allowed").status == ShadowLedgerStatus.INDETERMINATE
    assert cross_check("denied", "indeterminate").status == ShadowLedgerStatus.INDETERMINATE


def test_invalid_outcome_is_rejected():
    try:
        cross_check("maybe", "allowed")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_is_lead_only_for_inconsistencies():
    assert cross_check("denied", "allowed").is_lead and cross_check("allowed", "denied").is_lead
    assert not cross_check("allowed", "allowed").is_lead
    assert not cross_check("indeterminate", "denied").is_lead


def test_payload_json_safe():
    payload = cross_check_payload("denied", "allowed")
    assert payload["status"] == "INCONSISTENT_GRANT" and payload["is_lead"] is True
    assert json.loads(json.dumps(payload)) == payload
