"""B36 (bounded): tests for app/testing/integrity/knowledge_graph.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.knowledge_graph import (  # noqa: E402
    LEAD_STATUS, KGEdgeKind, KGNodeKind, KnowledgeGraph, leads_payload,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402


class _F:
    """Carries individual-level fields on purpose, to prove B36 never stores them."""

    def __init__(self, hid, verdict, p0_class):
        self.hypothesis_id = hid
        self.verdict = verdict
        self.p0_class = p0_class
        self.identity_tenant_dimension = "subject SECRET_ALIAS / tenant SECRET_TENANT"
        self.payment_state = "declined"
        self.summary = "SECRET payload detail"


class _Result:
    def __init__(self, findings):
        self.findings = findings


def _confirmed(hid, p0_class):
    return _F(hid, Verdict.CONFIRMED_P0, p0_class)


def test_schema_is_bounded_to_six_node_kinds_and_five_edge_kinds():
    assert len(list(KGNodeKind)) == 6 and len(list(KGEdgeKind)) == 5


def test_ingest_records_confirmed_weakness_classes_and_ignores_the_rest():
    kg = KnowledgeGraph()
    kg.ingest_engagement("fpA", _Result([_confirmed("PBB-U", "unconfirmed_payment_grants_access"),
                                         _F("PBB-F", Verdict.RULED_OUT, "plan_or_price_binding")]))
    labels = {n.label for n in kg.nodes.values()}
    assert "unconfirmed_payment_grants_access" in labels and "PBB-U" in labels and "fpA" in labels
    assert "plan_or_price_binding" not in labels  # RULED_OUT is not cross-engagement knowledge
    kinds = {(e.relationship) for e in kg.edges}
    assert KGEdgeKind.WEAKNESS_OF in kinds and KGEdgeKind.FOUND_VIA in kinds


def test_class_level_only_no_individual_data_ever_enters_the_graph():
    kg = KnowledgeGraph()
    kg.ingest_engagement("fpA", _Result([_confirmed("PBB-G", "cross_tenant_binding")]))
    blob = json.dumps(kg.to_dict())
    assert "SECRET_ALIAS" not in blob and "SECRET_TENANT" not in blob and "SECRET payload" not in blob and "declined" not in blob
    # every node exposes exactly the class-level field set -- widening it must be deliberate
    for n in kg.nodes.values():
        assert set(n.to_dict()) == {"node_id", "kind", "label", "confidence"}


def test_a_resembling_target_gets_the_confirmed_class_as_an_unconfirmed_lead():
    kg = KnowledgeGraph()
    kg.ingest_engagement("fpA", _Result([_confirmed("PBB-U", "unconfirmed_payment_grants_access")]))
    kg.resemble("fpA", "fpB")
    leads = kg.leads_for("fpB")
    assert len(leads) == 1
    lead = leads[0]
    assert lead.weakness_class == "unconfirmed_payment_grants_access" and lead.technique == "PBB-U"
    assert lead.source_targets == ("fpA",) and lead.status == LEAD_STATUS and lead.confidence == 1.0


def test_leads_never_resuggest_a_class_the_target_already_has():
    kg = KnowledgeGraph()
    kg.ingest_engagement("fpA", _Result([_confirmed("PBB-U", "unconfirmed_payment_grants_access")]))
    kg.ingest_engagement("fpB", _Result([_confirmed("PBB-U", "unconfirmed_payment_grants_access")]))
    kg.resemble("fpA", "fpB")
    assert kg.leads_for("fpB") == []  # B already has this weakness class -> not a new lead


def test_no_resemblance_means_no_cross_target_leads():
    kg = KnowledgeGraph()
    kg.ingest_engagement("fpA", _Result([_confirmed("PBB-U", "unconfirmed_payment_grants_access")]))
    assert kg.leads_for("fpC") == []  # unrelated target, no RESEMBLES edge


def test_edge_provenance_traces_to_the_source_engagement():
    kg = KnowledgeGraph()
    kg.ingest_engagement("fpA", _Result([_confirmed("PBB-G", "cross_tenant_binding")]))
    weakness_of = [e for e in kg.edges if e.relationship == KGEdgeKind.WEAKNESS_OF]
    assert weakness_of and weakness_of[0].source_engagements == ("fpA",)


def test_leads_payload_is_json_safe_and_states_the_never_proof_rule():
    kg = KnowledgeGraph()
    kg.ingest_engagement("fpA", _Result([_confirmed("PBB-U", "unconfirmed_payment_grants_access")]))
    kg.resemble("fpA", "fpB")
    payload = leads_payload(kg, "fpB")
    assert json.loads(json.dumps(payload)) == payload
    assert "never proof" in payload["note"] and payload["leads"][0]["weakness_class"] == "unconfirmed_payment_grants_access"
