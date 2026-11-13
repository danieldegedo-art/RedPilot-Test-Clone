"""ZR-007: the durable half of the evidence graph (B9/ZR-005). Persists an
EvidenceGraph to the evidence_nodes/evidence_edges tables and reloads it, so a
confirmed finding's evidence DAG survives across runs.

NOT EXECUTED IN THE SANDBOX THIS WAS WRITTEN IN (no sqlalchemy) -- same status as
app/db/pesm_store.py / memory.py. What IS tested is the graph logic itself
(test_evidence_graph.py); this class persists that already-tested structure. The
per-method short-lived-session pattern matches pesm_store.py exactly. The two tables
are NEW (create_all picks them up; no manual migration).

One graph per hypothesis (B9), so `graph_id` is the graph's hypothesis_id. A re-save
is idempotent: the graph's rows are deleted and rewritten in one unit of work.
"""
from __future__ import annotations

from sqlalchemy import delete, select

from app.db.models import EvidenceEdgeRecord, EvidenceNodeRecord
from app.db.session import SessionLocal
from app.testing.integrity.evidence_graph import EvidenceEdge, EvidenceGraph, EvidenceNode, EvidenceNodeKind


class SQLAlchemyEvidenceStore:
    """No in-process state; every method opens its own session (safe to share)."""

    async def save_graph(self, graph: EvidenceGraph) -> None:
        graph_id = graph.hypothesis_id
        async with SessionLocal() as session:
            # idempotent re-save: clear this graph's prior rows first
            await session.execute(delete(EvidenceNodeRecord).where(EvidenceNodeRecord.graph_id == graph_id))
            await session.execute(delete(EvidenceEdgeRecord).where(EvidenceEdgeRecord.graph_id == graph_id))
            for node in graph.nodes.values():
                session.add(EvidenceNodeRecord(graph_id=graph_id, node_id=node.node_id, kind=node.kind.value,
                                               reference_id=node.reference_id, occurred_at=node.occurred_at))
            for edge in graph.edges:
                session.add(EvidenceEdgeRecord(graph_id=graph_id, from_node=edge.from_node, to_node=edge.to_node,
                                               relationship_kind=edge.relationship))
            await session.commit()

    async def load_graph(self, graph_id: str) -> EvidenceGraph | None:
        node_stmt = select(EvidenceNodeRecord).where(EvidenceNodeRecord.graph_id == graph_id)
        edge_stmt = select(EvidenceEdgeRecord).where(EvidenceEdgeRecord.graph_id == graph_id)
        async with SessionLocal() as session:
            node_rows = (await session.execute(node_stmt)).scalars().all()
            edge_rows = (await session.execute(edge_stmt)).scalars().all()
        if not node_rows:
            return None
        graph = EvidenceGraph(hypothesis_id=graph_id)
        for r in node_rows:
            graph.add_node(EvidenceNode(node_id=r.node_id, kind=EvidenceNodeKind(r.kind),
                                        reference_id=r.reference_id, occurred_at=r.occurred_at))
        for r in edge_rows:  # the saved edges were acyclic when stored; re-adding preserves that
            graph.add_edge(EvidenceEdge(from_node=r.from_node, to_node=r.to_node, relationship=r.relationship_kind))
        return graph

    async def saved_graph_ids(self) -> frozenset[str]:
        async with SessionLocal() as session:
            rows = (await session.execute(select(EvidenceNodeRecord.graph_id).distinct())).scalars().all()
        return frozenset(rows)
