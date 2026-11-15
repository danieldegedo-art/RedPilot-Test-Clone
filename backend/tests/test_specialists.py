"""A21-A24: tests for app/testing/integrity/specialists.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.specialists import (  # noqa: E402
    SPECIALISTS, by_sub_domain, focus, get, roster_payload,
)
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402


def test_all_specialists_reference_only_registered_classes():
    valid = set(EXPERIMENT_CLASSES.values())
    for s in SPECIALISTS:
        assert set(s.oracle_classes) <= valid, s.agent_id
        assert s.oracle_classes  # each focuses on at least one class


def test_webhook_specialist_notes_forgery_is_blocked():
    a22 = get("A22")
    assert "BLOCKED" in a22.note and a22.oracle_classes == ("unconfirmed_payment_grants_access",)


def test_coupon_specialist_focuses_on_price_and_currency():
    a23 = get("A23")
    assert set(a23.oracle_classes) == {"plan_or_price_binding", "currency_binding"}


def test_subscription_specialist_focus():
    a24 = get("A24")
    assert "retention_after_refund" in a24.oracle_classes and "duplicate_value_via_return_flow_repetition" in a24.oracle_classes


def test_get_and_by_sub_domain():
    assert get("A21").name == "Payment-Provider Specialist"
    assert by_sub_domain("coupon_promo").agent_id == "A23"
    assert get("A99") is None and by_sub_domain("nope") is None


def test_focus_rejects_unknown_and_is_a_lead():
    try:
        focus("A99")
        assert False, "expected KeyError"
    except KeyError:
        pass
    assert "never a finding" in focus("A21")["note"]


def test_roster_payload_json_safe_and_ids_unique():
    ids = [s.agent_id for s in SPECIALISTS]
    assert ids == ["A21", "A22", "A23", "A24"] and len(set(ids)) == 4
    assert json.loads(json.dumps(roster_payload())) == roster_payload()
