"""ZR-008 / B23: tests for app/testing/integrity/commercial_context.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.commercial_context import (  # noqa: E402
    CommercialContext, commercial_context_by_hypothesis, commercial_context_payload, parse_commercial_context,
)


class _F:
    def __init__(self, hid, commercial_context):
        self.hypothesis_id = hid
        self.commercial_context = commercial_context


class _Result:
    def __init__(self, findings):
        self.findings = findings


def test_plan_and_top_plan_synonyms_map_to_typed_fields():
    cc = parse_commercial_context("cheapest_plan=basic, top_plan=enterprise")
    assert cc.plan == "basic" and cc.top_plan == "enterprise"
    assert parse_commercial_context("plan=pro").plan == "pro"


def test_currency_and_price_are_structured():
    cc = parse_commercial_context("alternative_currency=EUR, public_price=9.99")
    assert cc.currency == "EUR" and cc.public_price == "9.99"


def test_quota_cap_is_coerced_to_int_and_sla_to_float():
    cc = parse_commercial_context("plan=basic, quota_cap=5, declared_sla_s=3600")
    assert cc.quota_cap == 5 and isinstance(cc.quota_cap, int)
    assert cc.declared_sla_s == 3600.0 and isinstance(cc.declared_sla_s, float)


def test_unknown_keys_are_kept_verbatim_not_dropped():
    cc = parse_commercial_context("plan=basic, promo_code=SPRING")
    assert cc.plan == "basic" and cc.dimensions["promo_code"] == "SPRING"


def test_a_bad_typed_value_is_kept_raw_not_invented():
    cc = parse_commercial_context("quota_cap=unbounded")
    assert cc.quota_cap is None and cc.dimensions["quota_cap"] == "unbounded"  # no fabricated number


def test_non_keyvalue_text_is_preserved_as_a_note():
    cc = parse_commercial_context("free trial active")
    assert cc.dimensions["_note"] == "free trial active"


def test_empty_is_empty():
    assert parse_commercial_context(None).is_empty() and parse_commercial_context("").is_empty()
    assert not parse_commercial_context("plan=basic").is_empty()


def test_per_finding_structured_context_and_payload_is_json_safe():
    r = _Result([_F("PBB-F", "cheapest_plan=basic, top_plan=enterprise"), _F("PBB-H", "alternative_currency=EUR, public_price=9.99")])
    by_hyp = commercial_context_by_hypothesis(r)
    assert by_hyp["PBB-F"].top_plan == "enterprise" and by_hyp["PBB-H"].currency == "EUR"
    payload = commercial_context_payload(r)
    assert json.loads(json.dumps(payload)) == payload
    assert set(payload["commercial_context"]) == {"PBB-F", "PBB-H"}
