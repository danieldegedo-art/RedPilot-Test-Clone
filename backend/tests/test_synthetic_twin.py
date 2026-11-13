"""B29: tests for app/testing/integrity/synthetic_twin.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.synthetic_twin import SyntheticTwin  # noqa: E402


def test_own_qualifying_payment_entitles_only_the_payer():
    t = SyntheticTwin()
    t.pay("S")
    assert t.expected("S") is True and t.use("S") is True
    assert t.expected("K") is False            # never paid


def test_non_qualifying_payment_entitles_no_one():
    t = SyntheticTwin()
    t.pay("S", qualifying=False)
    assert t.expected("S") is False


def test_refund_revokes_entitlement():
    t = SyntheticTwin()
    t.pay("V")
    assert t.expected("V") is True
    t.refund("V")
    assert t.expected("V") is False


def test_naming_a_beneficiary_grants_nothing():
    t = SyntheticTwin()
    t.pay("S")
    t.name_beneficiary("S", "B")
    assert t.expected("B") is False             # correct cross-identity binding holds
    assert ["S", "B"] in t.snapshot()["beneficiary_claims"]


def test_compare_flags_unexpected_access_as_a_lead_not_a_finding():
    t = SyntheticTwin()                          # K never paid -> expected False
    c = t.compare("K", observed_entitled=True)
    assert c.diverges is True and c.expected is False
    assert "LEAD" in c.note and "never a finding" in c.note
    assert t.compare("K", observed_entitled=False).diverges is False   # matches expectation


def test_identity_must_be_a_nonempty_synthetic_token():
    t = SyntheticTwin()
    for bad in ("", None):
        try:
            t.expected(bad)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_snapshot_is_deterministic_and_json_safe():
    t = SyntheticTwin()
    t.pay("S"); t.pay("K", qualifying=False); t.refund("S")
    s1, s2 = t.snapshot(), t.snapshot()
    assert s1 == s2                              # deterministic
    assert s1["payments"]["S"] == {"qualifying": True, "refunded": True}
    assert json.loads(json.dumps(s1)) == s1
