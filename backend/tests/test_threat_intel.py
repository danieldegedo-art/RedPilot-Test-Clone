"""B40 (in-scope half): tests for app/testing/integrity/threat_intel.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.threat_intel import ADVISORY_MAP, ingest, ingest_payload  # noqa: E402
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402


def test_map_only_targets_registered_classes():
    valid = set(EXPERIMENT_CLASSES.values())
    for cats in ADVISORY_MAP.values():
        assert set(cats) <= valid


def test_ingest_biases_prior_toward_disclosed_categories():
    r = ingest(["coupon_abuse", "coupon_abuse", "currency_mismatch"])
    assert r.prior["plan_or_price_binding"] > r.prior["currency_binding"] > r.prior["cross_tenant_binding"]


def test_unknown_category_is_unmapped_not_invented():
    r = ingest(["totally_unknown_threat"])
    assert r.unmapped == ("totally_unknown_threat",) and r.ingested == 0
    # with nothing ingested the prior is uniform (Laplace), never guessing a class
    assert all(abs(v - 1.0 / len(EXPERIMENT_CLASSES)) < 1e-9 for v in r.prior.values())


def test_every_class_keeps_nonzero_weight_and_prior_sums_to_one():
    r = ingest(["open_access"])
    assert all(v > 0 for v in r.prior.values())
    assert abs(sum(r.prior.values()) - 1.0) < 1e-9


def test_multi_class_advisory_credits_both():
    r = ingest(["price_tampering"])
    assert r.ingested == 2   # price_tampering -> plan_or_price_binding + currency_binding
    assert r.prior["plan_or_price_binding"] == r.prior["currency_binding"] > r.prior["cross_tenant_binding"]


def test_payload_json_safe_and_notes_scope():
    payload = ingest_payload(["coupon_abuse"])
    assert "No weaponization" in payload["note"]
    assert json.loads(json.dumps(payload)) == payload
