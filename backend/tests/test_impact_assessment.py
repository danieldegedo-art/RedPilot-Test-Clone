"""A13 + A28: tests for app/testing/integrity/impact_assessment.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.impact_assessment import Severity, assess, assess_all  # noqa: E402


def _f(cls, verdict, hid="PBB-?"):
    return {"hypothesis_id": hid, "p0_class": cls, "verdict": verdict}


def test_confirmed_open_access_is_critical():
    a = assess(_f("paid_feature_open_to_unpaid", "CONFIRMED_P0"))
    assert a.severity == Severity.CRITICAL and a.impact != "no confirmed entitlement impact"


def test_ruled_out_is_severity_none():
    a = assess(_f("cross_tenant_binding", "RULED_OUT"))
    assert a.severity == Severity.NONE and a.impact == "no confirmed entitlement impact"


def test_view_divergence_is_capped_low_even_if_confirmed():
    a = assess(_f("ui_vs_server_divergence", "CONFIRMED_P0"))
    assert a.severity == Severity.LOW   # never high, however the verdict is labelled


def test_partially_validated_is_one_step_below_class_severity():
    a = assess(_f("unconfirmed_payment_grants_access", "PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE"))
    assert a.severity == Severity.MEDIUM   # class base HIGH -> one step down


def test_unknown_verdict_is_informational():
    assert assess(_f("cross_tenant_binding", "UNKNOWN")).severity == Severity.INFORMATIONAL


def test_off_catalog_class_is_rejected():
    try:
        assess(_f("totally_made_up_class", "CONFIRMED_P0"))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_no_fabricated_figures_and_assess_all_json_safe():
    findings = [_f("paid_feature_open_to_unpaid", "CONFIRMED_P0", "PBB-OPEN"),
                _f("currency_binding", "RULED_OUT", "PBB-H")]
    out = assess_all(findings)
    for a in out["assessments"]:
        assert "$" not in a["impact"] and "$" not in a["rationale"]
    assert out["severity_counts"] == {"critical": 1, "none": 1}
    assert json.loads(json.dumps(out)) == out
