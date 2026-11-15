"""B8: tests for app/testing/integrity/rule_mining.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.rule_mining import Case, mine, mine_payload  # noqa: E402


def test_mines_a_unanimous_recurring_rule():
    corpus = [Case(f"c{i}", (("p0_class", "cross_tenant"), ("tenant_claimed", True), ("verdict", "CONFIRMED_P0")))
              for i in range(3)]
    rules = mine(corpus, consequent_keys={"verdict"})          # default size 2 -> 2 singles + 1 pair
    assert len(rules) == 3
    assert all(r.consequent == ("verdict", "CONFIRMED_P0") and r.confidence == 1.0 and r.support == 3 for r in rules)


def test_a_pattern_seen_only_twice_is_not_mined():
    pat = (("p0_class", "x"), ("verdict", "CONFIRMED_P0"))
    assert mine([Case("c1", pat), Case("c2", pat)], consequent_keys={"verdict"}) == []


def test_confidence_below_threshold_is_dropped_unless_lowered():
    corpus = [Case("c1", (("a", "1"), ("verdict", "P0"))),
              Case("c2", (("a", "1"), ("verdict", "P0"))),
              Case("c3", (("a", "1"), ("verdict", "P0"))),
              Case("c4", (("a", "1"), ("verdict", "RULED_OUT")))]   # a=1 -> P0 in 3/4 = 0.75
    assert mine(corpus, consequent_keys={"verdict"}, max_antecedent_size=1) == []   # < default 1.0
    lowered = mine(corpus, consequent_keys={"verdict"}, min_confidence=0.5, max_antecedent_size=1)
    assert len(lowered) == 1 and abs(lowered[0].confidence - 0.75) < 1e-9 and lowered[0].support == 3


def test_consequent_keys_is_required():
    try:
        mine([Case("c1", (("a", "1"), ("verdict", "P0")))], consequent_keys=set())
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_min_cases_floor_is_enforced():
    try:
        mine([Case("c1", (("a", "1"), ("verdict", "P0")))], consequent_keys={"verdict"}, min_cases=2)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_antecedent_size_cap_gates_a_conjunction_only_rule():
    # neither single atom reaches conf 1.0 at support>=3; only their conjunction does.
    corpus = [
        Case("c1", (("p0_class", "cross_tenant"), ("tenant_claimed", True), ("verdict", "CONFIRMED_P0"))),
        Case("c2", (("p0_class", "cross_tenant"), ("tenant_claimed", True), ("verdict", "CONFIRMED_P0"))),
        Case("c3", (("p0_class", "cross_tenant"), ("tenant_claimed", True), ("verdict", "CONFIRMED_P0"))),
        Case("c4", (("p0_class", "cross_tenant"), ("tenant_claimed", False), ("verdict", "RULED_OUT"))),
        Case("c5", (("p0_class", "cross_identity"), ("tenant_claimed", True), ("verdict", "RULED_OUT"))),
    ]
    assert mine(corpus, consequent_keys={"verdict"}, max_antecedent_size=1) == []
    size2 = mine(corpus, consequent_keys={"verdict"}, max_antecedent_size=2)
    assert len(size2) == 1
    assert len(size2[0].antecedent) == 2 and size2[0].confidence == 1.0 and size2[0].support == 3


def test_deterministic_order_no_consequent_in_antecedent_and_json_safe():
    corpus = ([Case(f"a{i}", (("a", "1"), ("verdict", "P0"))) for i in range(4)] +
              [Case(f"b{i}", (("b", "2"), ("verdict", "P0"))) for i in range(3)])
    rules = mine(corpus, consequent_keys={"verdict"}, max_antecedent_size=1)
    assert [r.support for r in rules] == [4, 3]                               # sorted by -support
    assert all("verdict" not in {k for k, _ in r.antecedent} for r in rules)  # target never on the left
    assert "LEAD" in rules[0].note
    payload = mine_payload(corpus, consequent_keys={"verdict"}, max_antecedent_size=1)
    assert json.loads(json.dumps(payload)) == payload
