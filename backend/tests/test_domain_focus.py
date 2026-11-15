"""Domain-pack focus capability: tests for app/testing/integrity/domain_focus.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.domain_focus import DOMAIN_PACKS, focus, get, roster_payload  # noqa: E402
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402


def test_exactly_six_packs_a31_through_a36():
    assert set(DOMAIN_PACKS) == {"A31", "A32", "A33", "A34", "A35", "A36"}


def test_every_referenced_class_is_pre_registered():
    valid = set(EXPERIMENT_CLASSES.values())
    for p in DOMAIN_PACKS.values():
        assert set(p.oracle_classes) <= valid


def test_scope_mirrors_the_roster_decisions():
    assert get("A31").scope == "out_of_scope" and get("A32").scope == "out_of_scope"
    assert get("A33").scope == "in_scope" and get("A34").scope == "in_scope" and get("A35").scope == "in_scope"
    assert get("A36").scope == "narrowed"


def test_every_pack_names_an_excluded_offensive_capability():
    for p in DOMAIN_PACKS.values():
        assert len(p.excluded) >= 1 and all(isinstance(x, str) and x for x in p.excluded)


def test_osint_pack_exercises_no_oracle_class():
    assert get("A36").oracle_classes == ()


def test_contract_auditor_focus_is_entitlement_only_and_excludes_exploitation():
    f = focus("A33")
    assert "unconfirmed_payment_grants_access" in f["oracle_classes"]
    assert any("exploitation" in x for x in f["excluded"])
    assert "never a finding" in f["note"]


def test_focus_rejects_unknown_pack():
    try:
        focus("A99")
    except KeyError:
        return
    raise AssertionError("focus() must raise KeyError for an unknown pack, never invent one")


def test_roster_payload_json_safe():
    payload = roster_payload()
    assert len(payload["domain_packs"]) == 6
    assert json.loads(json.dumps(payload)) == payload
