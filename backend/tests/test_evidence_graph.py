"""ZR-005 / B9: app/testing/integrity/evidence_graph.py. Stdlib only."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

import json  # noqa: E402

from app.core.control_port.contract import EvidenceClass, build_artifact  # noqa: E402
from app.testing.integrity.evidence_graph import (  # noqa: E402
    EvidenceEdge, EvidenceGraph, EvidenceNode, EvidenceNodeKind, GraphCycleError, UnknownNodeError,
    artifact_timestamps_from_ledger, build_evidence_graph, evidence_graph_for_finding,
)
from app.testing.pesm import EntitlementStatus, EntitlementTransition  # noqa: E402

T0 = datetime(2026, 10, 26, tzinfo=timezone.utc)


def _node(i: str, kind=EvidenceNodeKind.REQUEST_RESPONSE) -> EvidenceNode:
    return EvidenceNode(i, kind, i)


class _Obs:
    def __init__(self, oracle_id, artifact_ids):
        self.oracle_id, self.artifact_ids = oracle_id, tuple(artifact_ids)


# ---- DAG invariants ------------------------------------------------------------

def test_a_linear_chain_is_a_dag_and_orders_topologically():
    g = EvidenceGraph("H")
    for n in "abc":
        g.add_node(_node(n))
    g.add_edge(EvidenceEdge("a", "b", "precedes"))
    g.add_edge(EvidenceEdge("b", "c", "precedes"))
    assert g.is_dag() and g.topological_order() == ["a", "b", "c"]


def test_a_diamond_is_a_valid_dag_one_artifact_can_back_two_results():
    g = EvidenceGraph("H")
    for n in ("shared", "r1", "r2"):
        g.add_node(_node(n))
    g.add_edge(EvidenceEdge("shared", "r1", "confirms"))
    g.add_edge(EvidenceEdge("shared", "r2", "confirms"))
    assert g.is_dag()
    order = g.topological_order()
    assert order.index("shared") < order.index("r1") and order.index("shared") < order.index("r2")


def test_a_self_loop_is_rejected():
    g = EvidenceGraph("H")
    g.add_node(_node("a"))
    try:
        g.add_edge(EvidenceEdge("a", "a", "x"))
        raise AssertionError("expected GraphCycleError")
    except GraphCycleError:
        pass


def test_a_back_edge_closing_a_multi_hop_cycle_is_rejected_and_leaves_the_graph_intact():
    g = EvidenceGraph("H")
    for n in "abcd":
        g.add_node(_node(n))
    for a, b in (("a", "b"), ("b", "c"), ("c", "d")):
        g.add_edge(EvidenceEdge(a, b, "precedes"))
    before_edges = list(g.edges)
    try:
        g.add_edge(EvidenceEdge("d", "a", "precedes"))  # closes a -> b -> c -> d -> a
        raise AssertionError("expected GraphCycleError")
    except GraphCycleError:
        pass
    assert g.edges == before_edges and g.is_dag(), "a rejected edge must not be left half-applied"


def test_edges_to_unknown_nodes_are_rejected():
    g = EvidenceGraph("H")
    g.add_node(_node("a"))
    for edge in (EvidenceEdge("a", "ghost", "x"), EvidenceEdge("ghost", "a", "x")):
        try:
            g.add_edge(edge)
            raise AssertionError("expected UnknownNodeError")
        except UnknownNodeError:
            pass


def test_add_node_is_idempotent():
    g = EvidenceGraph("H")
    g.add_node(_node("a"))
    g.add_node(_node("a"))
    assert len(g.nodes) == 1


def test_topological_order_itself_detects_a_cycle_independent_of_add_edge():
    """Defense in depth: corrupt the adjacency directly (bypassing add_edge's
    own check) and confirm the second line of defense actually fires."""
    g = EvidenceGraph("H")
    for n in "ab":
        g.add_node(_node(n))
    g._adj["a"].add("b")
    g._adj["b"].add("a")
    assert not g.is_dag()
    try:
        g.topological_order()
        raise AssertionError("expected GraphCycleError")
    except GraphCycleError:
        pass


def test_topological_order_is_deterministic():
    def build():
        g = EvidenceGraph("H")
        for n in ("z", "m", "a"):
            g.add_node(_node(n))
        g.add_edge(EvidenceEdge("z", "a", "x"))
        g.add_edge(EvidenceEdge("m", "a", "x"))
        return g.topological_order()
    assert build() == build() == ["m", "z", "a"]  # roots sorted alphabetically, then a


# ---- ancestors: the evidence chain behind a result --------------------------------

def test_ancestors_returns_the_full_upstream_chain_and_nothing_else():
    g = EvidenceGraph("H")
    for n in ("root", "mid", "leaf", "unrelated"):
        g.add_node(_node(n))
    g.add_edge(EvidenceEdge("root", "mid", "x"))
    g.add_edge(EvidenceEdge("mid", "leaf", "x"))
    assert g.ancestors("leaf") == {"root", "mid"}
    assert g.ancestors("root") == set()
    assert g.ancestors("unrelated") == set()


# ---- construction from real-shaped data -------------------------------------------------

def test_build_links_each_observations_own_artifacts_with_confirms_edges():
    g = build_evidence_graph("PBB-U", observations=[_Obs("o1", ["a1", "a2"]), _Obs("o2", ["a2"])])
    assert {n.kind for n in g.nodes.values()} == {EvidenceNodeKind.REQUEST_RESPONSE, EvidenceNodeKind.ORACLE_RESULT}
    assert g.ancestors("or:o1") == {"rr:a1", "rr:a2"}
    assert g.ancestors("or:o2") == {"rr:a2"}, "a2 backs both results; o2 must not inherit a1"
    assert all(e.relationship == "confirms" for e in g.edges) and len(g.edges) == 3
    assert g.is_dag()


def test_artifact_timestamps_are_carried_onto_their_nodes():
    g = build_evidence_graph("H", observations=[_Obs("o1", ["a1"])], artifact_timestamps={"a1": T0})
    assert g.nodes["rr:a1"].occurred_at == T0


def test_state_transitions_become_nodes_but_are_never_auto_linked():
    """The module's own stated limit, held as a test: no edge is invented
    between a transition and an oracle result without evidence for it."""
    tr = EntitlementTransition("f1", "alice", None, EntitlementStatus.NEVER_GRANTED, EntitlementStatus.ACTIVE, "payment_confirmed", T0)
    g = build_evidence_graph("H", observations=[_Obs("o1", ["a1"])], transitions=[tr])
    transition_nodes = [n for n in g.nodes.values() if n.kind == EvidenceNodeKind.STATE_TRANSITION]
    assert len(transition_nodes) == 1 and transition_nodes[0].occurred_at == T0
    assert all(transition_nodes[0].node_id not in (e.from_node, e.to_node) for e in g.edges)
    assert g.completeness() == 2 / 3  # a1 + o1 connected, the transition not


def test_completeness_edge_cases():
    assert EvidenceGraph("H").completeness() == 1.0  # nothing to be incomplete about
    one = EvidenceGraph("H")
    one.add_node(_node("lonely"))
    assert one.completeness() == 1.0 and one.unlinked_nodes() == [], "a single artifact has no gap in its chain"
    two = EvidenceGraph("H")
    two.add_node(_node("a"))
    two.add_node(_node("b"))
    assert two.completeness() == 0.0 and two.unlinked_nodes() == ["a", "b"]


def test_a_caller_can_add_an_evidenced_correlation_explicitly():
    tr = EntitlementTransition("f1", "alice", None, EntitlementStatus.NEVER_GRANTED, EntitlementStatus.ACTIVE, "payment_confirmed", T0)
    g = build_evidence_graph("H", observations=[_Obs("o1", ["a1"])], transitions=[tr])
    transition_id = next(n.node_id for n in g.nodes.values() if n.kind == EvidenceNodeKind.STATE_TRANSITION)
    g.add_edge(EvidenceEdge(transition_id, "or:o1", "precedes"))
    assert transition_id in g.ancestors("or:o1") and g.is_dag() and g.completeness() == 1.0


# ---- per-hypothesis isolation -------------------------------------------------------------

def test_two_hypotheses_graphs_share_no_state():
    g1 = build_evidence_graph("PBB-U", observations=[_Obs("o1", ["a1"])])
    g2 = build_evidence_graph("PBB-F", observations=[_Obs("o9", ["a9"])])
    assert set(g1.nodes) == {"rr:a1", "or:o1"} and set(g2.nodes) == {"rr:a9", "or:o9"}
    g1.add_node(_node("only-in-g1"))
    assert "only-in-g1" not in g2.nodes and "only-in-g1" not in g2._adj


# ---- the per-finding chain (ZR-005's acceptance criterion) -------------------------------------

def test_finding_graph_chains_artifacts_in_ledger_admission_order_and_confirms_oracle_results():
    obs = [_Obs("o1", ["a2"])]
    g = evidence_graph_for_finding("PBB-U", ["a3", "a1", "a2"], observations=obs, admission_order=["a1", "a2", "a3"])
    precedes = {(e.from_node, e.to_node) for e in g.edges if e.relationship == "precedes"}
    assert precedes == {("rr:a1", "rr:a2"), ("rr:a2", "rr:a3")}, "chain follows admission order, not the order the finding listed them"
    # ancestors are transitive: a2 confirms o1, a1 was admitted before a2; a3 came after, so it is NOT upstream of o1
    assert g.ancestors("or:o1") == {"rr:a1", "rr:a2"}
    assert "rr:a1" in g.ancestors("rr:a3") and g.is_dag() and g.completeness() == 1.0 and g.unlinked_nodes() == []


def test_finding_graph_ignores_observations_belonging_to_other_findings():
    mine, theirs = _Obs("o-mine", ["a1"]), _Obs("o-theirs", ["zzz"])
    g = evidence_graph_for_finding("PBB-U", ["a1"], observations=[mine, theirs], admission_order=["a1", "zzz"])
    assert "or:o-mine" in g.nodes and "or:o-theirs" not in g.nodes and "rr:zzz" not in g.nodes


def test_artifacts_cited_but_unknown_to_the_ledger_stay_unlinked_not_guessed_into_place():
    g = evidence_graph_for_finding("PBB-U", ["a1", "a2", "ghost"], observations=[], admission_order=["a1", "a2"])
    assert g.unlinked_nodes() == ["rr:ghost"] and g.completeness() == 2 / 3


def test_a_payment_artifact_that_is_not_an_oracle_observation_is_still_evidence_in_the_chain():
    """The payment-creation call is evidence but never an OracleObservation --
    it must be in the graph (admitted earlier) not silently dropped."""
    g = evidence_graph_for_finding("PBB-U", ["pay", "use"], observations=[_Obs("o1", ["use"])], admission_order=["pay", "use"])
    assert "rr:pay" in g.ancestors("or:o1"), "the payment evidence precedes the artifact that confirms the oracle result"


def test_to_dict_is_json_safe_deterministic_and_self_consistent():
    obs = [_Obs("o1", ["a1", "a2"])]
    build = lambda: evidence_graph_for_finding("PBB-U", ["a2", "a1"], observations=obs, admission_order=["a1", "a2"], artifact_timestamps={"a1": T0})  # noqa: E731
    d1, d2 = build().to_dict(), build().to_dict()
    assert d1 == d2 and json.loads(json.dumps(d1)) == d1
    assert d1["order"].index("rr:a1") < d1["order"].index("rr:a2") < d1["order"].index("or:o1")
    assert d1["completeness"] == 1.0 and d1["unlinked"] == []
    a1 = next(n for n in d1["nodes"] if n["id"] == "rr:a1")
    assert a1["at"] == T0.isoformat()


def test_to_dict_does_not_depend_on_the_order_things_were_inserted():
    """Two runs that cite the same artifacts in a different order must persist
    identical graphs -- otherwise "did the evidence change?" can't be answered
    by comparing stored rows."""
    # the observation's own artifact order differs too -- it is what inserts the artifact nodes first
    one = evidence_graph_for_finding("H", ["a1", "a2"], observations=[_Obs("o1", ["a1", "a2"])], admission_order=["a1", "a2"])
    two = evidence_graph_for_finding("H", ["a2", "a1"], observations=[_Obs("o1", ["a2", "a1"])], admission_order=["a1", "a2"])
    assert list(one.nodes) != list(two.nodes), "test setup: node insertion order must actually differ, or this proves nothing"
    assert one.to_dict() == two.to_dict()


def test_artifact_timestamps_from_ledger_reads_provenance_and_skips_what_it_cannot_parse():
    class P:
        def __init__(self, ts):
            self.timestamp = ts

    class A:
        def __init__(self, ts):
            self.provenance = P(ts)
    got = artifact_timestamps_from_ledger({"good": A(T0.isoformat()), "bad": A("not-a-date"), "none": A(None), "noprov": object()})
    assert got == {"good": T0}


def test_the_graph_survives_the_real_writer_the_real_redaction_and_a_json_round_trip():
    """Writer -> persistence normalization -> JSON column -> reader, with
    REAL artifact ids (build_artifact) -- id-shaped strings are exactly what a
    value-based secret masker might mistake for tokens."""
    from app.testing.integrity.engine import EXPERIMENT_CLASSES, SPECS, TITLES
    from app.testing.integrity.findings import Finding
    from app.testing.modules.payment_integrity import PaymentIntegrityModule
    from app.testing.purity.taxonomy import Verdict
    from app.testing.redaction import normalize_result_for_persistence
    from app.testing.run_memory import prior_findings_from_rows

    arts = [build_artifact(payload={"n": i}, source_type="http_response", classification=EvidenceClass.EXTERNAL_BROWSER, identity_alias="clean-id",
                           tenant_alias=None, target="https://shop.example.test/x", session_isolation_id=f"s{i}", authorization_ref="auth-1", sequence=i) for i in range(3)]
    ids = [a.artifact_id for a in arts]
    finding = Finding(hypothesis_id="PBB-U", p0_class=EXPERIMENT_CLASSES["PBB-U"], title=TITLES["PBB-U"], verdict=Verdict.RULED_OUT, confidence="medium",
                      summary="x", spec=SPECS["PBB-U"], artifact_ids=ids)
    graph = evidence_graph_for_finding("PBB-U", ids, observations=[_Obs("o1", [ids[2]])], admission_order=ids)

    module = PaymentIntegrityModule.__new__(PaymentIntegrityModule)
    result = module._finding_result(finding, "fp-A", graph)
    fields = normalize_result_for_persistence({
        "test_case_id": result.test_case_id, "name": result.name, "input_parameters": result.input_parameters, "actual": result.actual,
        "expected": result.expected, "recommendation": result.recommendation, "description": result.description, "request_json": None, "response_json": None})
    stored = json.loads(json.dumps(fields["input_parameters"], default=str))

    assert stored["evidence_graph"] == graph.to_dict(), "redaction or serialization altered the persisted graph"
    assert {n["ref"] for n in stored["evidence_graph"]["nodes"] if n["kind"] == "request_response"} == set(ids)
    row = {"run_id": "r1", "category": "payment_integrity", "input_parameters": stored, "finished_at": T0}
    assert prior_findings_from_rows([row], brief_fingerprint="fp-A", now=T0).verdicts() == {"PBB-U": Verdict.RULED_OUT}, "the extra key must not break the reader"
    # and without a graph the row is exactly as before (graph is optional, additive)
    assert "evidence_graph" not in module._finding_result(finding, "fp-A").input_parameters


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
