"""ZR-005 / B9: Evidence Correlation Graph. "A graph ... linking every
request, response, timestamp, state transition, and oracle result into one
traceable DAG per hypothesis -- closing [the] gap ... evidence discarded
after engine.run() -- by making evidence a durably persisted graph node, not
an ephemeral artifact ID."

The "discarded after engine.run()" half is already closed (ZR-009, both
layers this session: TestResultRecord write-through, EvidenceLedger's
flush_pending). What ZR-005 adds on top is the GRAPH -- explicit edges, not
just a flat bag of artifact_ids on a Finding. This module builds that graph
from data this session's other work already produces:

    request_response nodes  <- EvidenceArtifact (provenance.py)
    state_transition nodes  <- EntitlementTransition (pesm.py, ZR-002)
    oracle_result nodes     <- OracleObservation (contract.py)

Edges are added only where the source data directly states the relationship
-- never inferred/guessed. Right now that's exactly one kind: an
OracleObservation's own artifact_ids says which request/response evidence
backs it, so a "confirms" edge from each of those artifact nodes to the
oracle_result node is added automatically. Matching state transitions to
oracle results by time/feature_id would need a heuristic window this module
does not invent; `add_edge` is public specifically so a caller with that
real correlation logic can add it explicitly, with evidence, rather than
this module guessing silently.

A graph that still has standalone state_transition nodes with no edges in
or out is correct, not broken, until that correlation step exists --
checked by `test_evidence_graph.py`'s own tests, not hidden.

Persistence: this module is the graph logic itself, in-memory, pure,
fully testable. A durable (SQLAlchemy-backed) store, following the exact
pattern pesm_store.py/db/memory.py already established, is the next
increment for this item -- not built this turn; see HANDOFF.md.

Stdlib only.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence


class EvidenceNodeKind(str, Enum):
    REQUEST_RESPONSE = "request_response"
    STATE_TRANSITION = "state_transition"
    ORACLE_RESULT = "oracle_result"


@dataclass(frozen=True)
class EvidenceNode:
    node_id: str
    kind: EvidenceNodeKind
    reference_id: str  # the underlying artifact_id / oracle_id / transition key this node represents
    occurred_at: datetime | None = None


@dataclass(frozen=True)
class EvidenceEdge:
    from_node: str
    to_node: str
    relationship: str  # e.g. "confirms", "precedes" -- open vocabulary, not a closed enum (see module docstring: new relationship kinds arrive with new correlation logic, not with a new enum member)


class GraphCycleError(Exception):
    """Raised by add_edge if the edge would make the graph not a DAG."""


class UnknownNodeError(Exception):
    """Raised by add_edge if either endpoint was never added via add_node."""


@dataclass
class EvidenceGraph:
    """Per-hypothesis (B9: "one traceable DAG per hypothesis" -- a graph is
    never shared across hypotheses, so a finding's evidence chain is always
    exactly this graph's reachable set, nothing more)."""

    hypothesis_id: str
    nodes: dict[str, EvidenceNode] = field(default_factory=dict)
    edges: list[EvidenceEdge] = field(default_factory=list)
    _adj: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_node(self, node: EvidenceNode) -> None:
        """Idempotent: adding the same node_id again is a no-op (the same
        artifact can legitimately back more than one oracle result)."""
        self.nodes.setdefault(node.node_id, node)
        self._adj.setdefault(node.node_id, set())

    def add_edge(self, edge: EvidenceEdge) -> None:
        if edge.from_node not in self.nodes:
            raise UnknownNodeError(f"from_node {edge.from_node!r} was never added")
        if edge.to_node not in self.nodes:
            raise UnknownNodeError(f"to_node {edge.to_node!r} was never added")
        if edge.from_node == edge.to_node:
            raise GraphCycleError(f"self-loop: {edge.from_node!r} -> itself")
        if self._reachable(edge.to_node, edge.from_node):
            raise GraphCycleError(f"{edge.from_node!r} -> {edge.to_node!r} would close a cycle "
                                  f"(a path {edge.to_node!r} -> ... -> {edge.from_node!r} already exists)")
        self._adj[edge.from_node].add(edge.to_node)
        self.edges.append(edge)

    def _reachable(self, start: str, target: str) -> bool:
        seen, stack = set(), [start]
        while stack:
            n = stack.pop()
            if n == target:
                return True
            if n in seen:
                continue
            seen.add(n)
            stack.extend(self._adj.get(n, ()))
        return False

    def topological_order(self) -> list[str]:
        """Kahn's algorithm. Raises GraphCycleError if the graph is somehow
        not a DAG despite add_edge's own checks (defense in depth, not
        reachable through this class's own public API alone)."""
        in_degree: dict[str, int] = {n: 0 for n in self.nodes}
        for targets in self._adj.values():
            for t in targets:
                in_degree[t] += 1
        queue = deque(sorted(n for n, d in in_degree.items() if d == 0))
        order: list[str] = []
        while queue:
            n = queue.popleft()
            order.append(n)
            for t in sorted(self._adj.get(n, ())):
                in_degree[t] -= 1
                if in_degree[t] == 0:
                    queue.append(t)
        if len(order) != len(self.nodes):
            raise GraphCycleError(f"graph for {self.hypothesis_id} is not a DAG: "
                                  f"{len(self.nodes) - len(order)} node(s) unreachable from any root")
        return order

    def is_dag(self) -> bool:
        try:
            self.topological_order()
            return True
        except GraphCycleError:
            return False

    def ancestors(self, node_id: str) -> set[str]:
        """Every node with a path TO node_id -- the full evidence chain
        behind one result (e.g. every artifact that confirms an oracle_result)."""
        rev: dict[str, set[str]] = defaultdict(set)
        for e in self.edges:
            rev[e.to_node].add(e.from_node)
        seen, stack = set(), [node_id]
        while stack:
            n = stack.pop()
            for p in rev.get(n, ()):
                if p not in seen:
                    seen.add(p)
                    stack.append(p)
        return seen

    def completeness(self) -> float:
        """Fraction of nodes that participate in at least one edge. A
        standalone node (no edge in or out) is evidence that's present but
        not yet correlated to anything -- see the module docstring on why
        state_transition nodes are often standalone today."""
        if len(self.nodes) <= 1:
            return 1.0  # nothing to be uncorrelated WITH: a single artifact has no gap in its chain
        connected = {n for e in self.edges for n in (e.from_node, e.to_node)}
        return len(connected) / len(self.nodes)

    def unlinked_nodes(self) -> list[str]:
        """Nodes with no edge in or out (empty for a graph of <= 1 node)."""
        if len(self.nodes) <= 1:
            return []
        connected = {n for e in self.edges for n in (e.from_node, e.to_node)}
        return sorted(n for n in self.nodes if n not in connected)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe and deterministic (sorted), so it can ride inside a
        persisted finding row (payment_integrity.py puts it in the finding's
        input_parameters -- durable via ZR-009's write-through, which is how
        "a durably persisted graph node, not an ephemeral artifact ID" is met
        without a separate store)."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "nodes": [{"id": n.node_id, "kind": n.kind.value, "ref": n.reference_id,
                       "at": n.occurred_at.isoformat() if n.occurred_at else None} for _, n in sorted(self.nodes.items())],
            "edges": [{"from": e.from_node, "to": e.to_node, "rel": e.relationship} for e in sorted(self.edges, key=lambda e: (e.from_node, e.to_node, e.relationship))],
            "order": self.topological_order(),
            "completeness": round(self.completeness(), 4),
            "unlinked": self.unlinked_nodes(),
        }


def _artifact_node_id(artifact_id: str) -> str:
    return f"rr:{artifact_id}"


def _oracle_node_id(oracle_id: str) -> str:
    return f"or:{oracle_id}"


def _transition_node_id(transition_key: str) -> str:
    return f"st:{transition_key}"


def artifact_timestamps_from_ledger(accepted: Mapping[str, Any]) -> dict[str, datetime]:
    """Duck-typed on EvidenceLedger.accepted: artifact_id -> an object with
    .provenance.timestamp (ISO string). Unparseable/absent timestamps are
    skipped, not guessed."""
    out: dict[str, datetime] = {}
    for aid, art in accepted.items():
        raw = getattr(getattr(art, "provenance", None), "timestamp", None)
        try:
            out[aid] = datetime.fromisoformat(raw) if raw else None  # type: ignore[assignment]
        except (TypeError, ValueError):
            out[aid] = None  # type: ignore[assignment]
    return {k: v for k, v in out.items() if v is not None}


def build_evidence_graph(
    hypothesis_id: str, *, observations: Iterable[Any] = (), transitions: Iterable[Any] = (),
    artifact_timestamps: dict[str, datetime] | None = None,
) -> EvidenceGraph:
    """Builds the DAG for one hypothesis from already-available data.
    `observations` duck-typed on .oracle_id/.artifact_ids (OracleObservation,
    contract.py); `transitions` duck-typed on .feature_id/.identity_alias/
    .tenant_alias/.occurred_at/.trigger (EntitlementTransition, pesm.py) --
    neither is imported directly, to keep this module independent of which
    concrete types a caller happens to be using (same reasoning as pesm.py's
    entitlement_states_from_oracle_observations).

    Edges added: one "confirms" edge per (artifact, oracle_result) pair
    named in an observation's own artifact_ids -- directly stated by the
    data, nothing inferred. State-transition nodes are added but NOT
    auto-linked to oracle results (see module docstring); a caller with a
    specific, evidenced correlation can call graph.add_edge(...) itself.
    """
    graph = EvidenceGraph(hypothesis_id)
    timestamps = artifact_timestamps or {}

    for obs in observations:
        oracle_node_id = _oracle_node_id(obs.oracle_id)
        graph.add_node(EvidenceNode(oracle_node_id, EvidenceNodeKind.ORACLE_RESULT, obs.oracle_id))
        for artifact_id in obs.artifact_ids:
            artifact_node_id = _artifact_node_id(artifact_id)
            graph.add_node(EvidenceNode(artifact_node_id, EvidenceNodeKind.REQUEST_RESPONSE, artifact_id, timestamps.get(artifact_id)))
            graph.add_edge(EvidenceEdge(artifact_node_id, oracle_node_id, "confirms"))

    for t in transitions:
        key = f"{t.feature_id}:{t.identity_alias}:{t.tenant_alias}:{t.trigger}:{t.occurred_at.isoformat()}"
        graph.add_node(EvidenceNode(_transition_node_id(key), EvidenceNodeKind.STATE_TRANSITION, key, t.occurred_at))

    return graph


def evidence_graph_for_finding(
    hypothesis_id: str, finding_artifact_ids: Iterable[str], *, observations: Iterable[Any],
    admission_order: Sequence[str], artifact_timestamps: Mapping[str, datetime] | None = None,
) -> EvidenceGraph:
    """ZR-005's per-finding chain: what backs ONE finding, as a DAG.

    - Oracle results: only observations whose own artifact_ids intersect the
      finding's cited artifacts (an observation from another experiment is
      not this finding's evidence); each gets "confirms" edges from the
      artifacts that back it (build_evidence_graph).
    - Every artifact the finding cites is a node, whether or not an
      observation links it -- e.g. the payment-creation calls, which are
      evidence but are not themselves oracle observations.
    - "precedes" edges chain the finding's artifacts in LEDGER ADMISSION
      ORDER (`admission_order` = list(ledger.accepted), dicts preserve
      insertion order). That ordering is stated by the ledger itself, not
      inferred; "precedes" claims only "admitted earlier in the same run",
      not causation. An artifact missing from admission_order stays unlinked
      and shows up in .unlinked_nodes() rather than being slotted in by guess.
    """
    ids = list(dict.fromkeys(finding_artifact_ids))
    cited = set(ids)
    relevant = [o for o in observations if cited & set(o.artifact_ids)]
    timestamps = dict(artifact_timestamps or {})
    graph = build_evidence_graph(hypothesis_id, observations=relevant, artifact_timestamps=timestamps)
    for aid in ids:
        graph.add_node(EvidenceNode(_artifact_node_id(aid), EvidenceNodeKind.REQUEST_RESPONSE, aid, timestamps.get(aid)))
    rank = {aid: i for i, aid in enumerate(admission_order)}
    chain = sorted((a for a in ids if a in rank), key=rank.__getitem__)
    for earlier, later in zip(chain, chain[1:]):
        graph.add_edge(EvidenceEdge(_artifact_node_id(earlier), _artifact_node_id(later), "precedes"))
    return graph
