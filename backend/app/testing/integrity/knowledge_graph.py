"""B36 (Section 10.2, Tier 1): Cross-Engagement Attack Knowledge Graph -- bounded form.

B9's evidence graph (evidence_graph.py) is the PER-ENGAGEMENT evidence layer. B36
adds the KNOWLEDGE layer above it: a cross-engagement relationship graph so a new
engagement does not start cold -- it can ask "what is already known about targets,
flows and providers resembling this one" and prioritise from that answer.

Two boundaries are load-bearing and enforced here:

  * GENERATES LEADS, NEVER PROOF. A cross-engagement lead is an UNCONFIRMED prior
    that raises a hypothesis's priority; it must still pass the full validation
    pipeline (oracle + clean-session re-check) of the engagement it is tested in.
    A wrong node costs one refuted hypothesis (ZR-011), never a false finding --
    exactly the advisory-only discipline run_memory.py already applies to priors.
  * CLASS-LEVEL ONLY (ZR-038 + Section 11.2 session isolation). Nodes hold
    STRUCTURAL / technical knowledge -- a target's structural fingerprint, a
    weakness CLASS (p0_class), a technique id, a provider quirk -- never an
    engagement's session state, identities, tenants, payment ids or payloads.
    ingest_engagement reads only verdict / p0_class / hypothesis_id from a
    finding; a test pins the node field set so widening it is a deliberate act.

Schema is bounded exactly as the spec fixes it: SIX node kinds, FIVE edge kinds.
Nodes carry confidence metadata; every edge traces to the engagement fingerprints
that produced it. The durable (SQLAlchemy) store follows the established
PersistXFn pattern and is deferred (same sandbox dependency boundary as the PESM
and evidence-graph durable stores); this module is the pure, in-memory graph
logic. Stdlib only."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from app.testing.purity.taxonomy import Verdict

LEAD_STATUS = "UNCONFIRMED_LEAD: a cross-engagement prior only; must pass this engagement's full oracle + clean-session validation before belief"


class KGNodeKind(str, Enum):           # the six first-class node types (spec Section 10.2)
    TARGET = "target"                   # a STRUCTURAL fingerprint, never engagement data
    WEAKNESS_CLASS = "weakness_class"   # a confirmed weakness CLASS (p0_class)
    TECHNIQUE = "technique"             # the experiment/technique id that found it
    CHAIN = "chain"                     # B32 compositions (populated when B32 exists)
    TOOL = "tool"                       # B38 tool-bridge outputs (populated when B38 exists)
    PROVIDER_QUIRK = "provider_quirk"   # payment-provider behavioural quirk (sandbox latency, test-card behaviour, ...)


class KGEdgeKind(str, Enum):           # the five typed edge types (spec Section 10.2)
    WEAKNESS_OF = "weakness_of"
    CHAINS_INTO = "chains_into"
    FOUND_VIA = "found_via"
    RESEMBLES = "resembles"
    WORKS_AGAINST = "works_against"


@dataclass(frozen=True)
class KGNode:
    node_id: str
    kind: KGNodeKind
    label: str                 # class-level label only (fingerprint / p0_class / technique id / quirk name)
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "kind": self.kind.value, "label": self.label, "confidence": round(self.confidence, 4)}


@dataclass(frozen=True)
class KGEdge:
    src: str
    dst: str
    relationship: KGEdgeKind
    source_engagements: tuple[str, ...]  # fingerprints of the engagements that produced this edge (class-level provenance)

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "relationship": self.relationship.value, "source_engagements": list(self.source_engagements)}


@dataclass(frozen=True)
class Lead:
    weakness_class: str
    technique: str | None
    confidence: float
    source_targets: tuple[str, ...]
    status: str = LEAD_STATUS

    def to_dict(self) -> dict[str, Any]:
        return {"weakness_class": self.weakness_class, "technique": self.technique, "confidence": round(self.confidence, 4),
                "source_targets": list(self.source_targets), "status": self.status}


def _target_id(fp: str) -> str:
    return f"target:{fp}"


def _weakness_id(p0_class: str) -> str:
    return f"weakness:{p0_class}"


def _technique_id(hypothesis_id: str) -> str:
    return f"technique:{hypothesis_id}"


class KnowledgeGraph:
    """In-memory cross-engagement knowledge graph (single-writer, like B11's index)."""

    def __init__(self) -> None:
        self.nodes: dict[str, KGNode] = {}
        self.edges: list[KGEdge] = []

    # -- construction ----------------------------------------------------------------
    def add_node(self, node: KGNode) -> None:
        existing = self.nodes.get(node.node_id)
        if existing is None:
            self.nodes[node.node_id] = node
        elif node.confidence > existing.confidence:  # keep the strongest evidence for a class-level node
            self.nodes[node.node_id] = node

    def add_edge(self, src: str, dst: str, relationship: KGEdgeKind, source_engagement: str) -> None:
        for i, e in enumerate(self.edges):
            if e.src == src and e.dst == dst and e.relationship == relationship:
                if source_engagement not in e.source_engagements:  # merge provenance, never duplicate the edge
                    self.edges[i] = KGEdge(src, dst, relationship, tuple(sorted({*e.source_engagements, source_engagement})))
                return
        self.edges.append(KGEdge(src, dst, relationship, (source_engagement,)))

    def resemble(self, fingerprint_a: str, fingerprint_b: str, *, source_engagement: str = "manual") -> None:
        """Record that two targets are structurally similar (symmetric). In the full
        system this comes from B40's payment-stack fingerprinting; here a caller states it."""
        self.add_node(KGNode(_target_id(fingerprint_a), KGNodeKind.TARGET, fingerprint_a))
        self.add_node(KGNode(_target_id(fingerprint_b), KGNodeKind.TARGET, fingerprint_b))
        self.add_edge(_target_id(fingerprint_a), _target_id(fingerprint_b), KGEdgeKind.RESEMBLES, source_engagement)
        self.add_edge(_target_id(fingerprint_b), _target_id(fingerprint_a), KGEdgeKind.RESEMBLES, source_engagement)

    def ingest_engagement(self, target_fingerprint: str, result: Any) -> None:
        """Record what a finished engagement CONFIRMED, at the class level only.
        Reads nothing but verdict / p0_class / hypothesis_id from each finding."""
        self.add_node(KGNode(_target_id(target_fingerprint), KGNodeKind.TARGET, target_fingerprint))
        for f in result.findings:
            if f.verdict != Verdict.CONFIRMED_P0:
                continue  # only confirmed weakness CLASSES become knowledge (spec); unconfirmed stay per-engagement
            wid, tid = _weakness_id(f.p0_class), _technique_id(f.hypothesis_id)
            self.add_node(KGNode(wid, KGNodeKind.WEAKNESS_CLASS, f.p0_class, confidence=1.0))
            self.add_node(KGNode(tid, KGNodeKind.TECHNIQUE, f.hypothesis_id, confidence=1.0))
            self.add_edge(wid, _target_id(target_fingerprint), KGEdgeKind.WEAKNESS_OF, target_fingerprint)
            self.add_edge(wid, tid, KGEdgeKind.FOUND_VIA, target_fingerprint)

    # -- queries ---------------------------------------------------------------------
    def _resembling_targets(self, fingerprint: str) -> set[str]:
        tid = _target_id(fingerprint)
        return {e.dst for e in self.edges if e.relationship == KGEdgeKind.RESEMBLES and e.src == tid}

    def _weakness_classes_of(self, target_id: str) -> set[str]:
        return {self.nodes[e.src].label for e in self.edges
                if e.relationship == KGEdgeKind.WEAKNESS_OF and e.dst == target_id and e.src in self.nodes}

    def _technique_for(self, weakness_label: str, source_target_id: str) -> str | None:
        wid = _weakness_id(weakness_label)
        for e in self.edges:
            if e.relationship == KGEdgeKind.FOUND_VIA and e.src == wid and source_target_id in {_target_id(s) for s in e.source_engagements}:
                return self.nodes[e.dst].label if e.dst in self.nodes else None
        for e in self.edges:  # fall back to any technique recorded for this weakness class
            if e.relationship == KGEdgeKind.FOUND_VIA and e.src == wid and e.dst in self.nodes:
                return self.nodes[e.dst].label
        return None

    def leads_for(self, target_fingerprint: str) -> list[Lead]:
        """Cross-engagement leads for a (possibly new) target: weakness classes
        confirmed against structurally RESEMBLING targets that this target has not
        already been shown to have. Each is an UNCONFIRMED lead -- never proof."""
        own = self._weakness_classes_of(_target_id(target_fingerprint))
        by_class: dict[str, Lead] = {}
        for other in self._resembling_targets(target_fingerprint):
            if other == _target_id(target_fingerprint):
                continue
            for wlabel in self._weakness_classes_of(other):
                if wlabel in own:
                    continue  # already known for this target; not a new lead
                conf = self.nodes[_weakness_id(wlabel)].confidence if _weakness_id(wlabel) in self.nodes else 0.5
                existing = by_class.get(wlabel)
                sources = tuple(sorted({*(existing.source_targets if existing else ()), self.nodes[other].label}))
                if existing is None or conf > existing.confidence:
                    by_class[wlabel] = Lead(wlabel, self._technique_for(wlabel, other), conf, sources)
                elif existing is not None:
                    by_class[wlabel] = Lead(existing.weakness_class, existing.technique, existing.confidence, sources)
        return [by_class[k] for k in sorted(by_class)]

    def to_dict(self) -> dict[str, Any]:
        return {"node_kinds": [k.value for k in KGNodeKind], "edge_kinds": [k.value for k in KGEdgeKind],
                "nodes": [self.nodes[n].to_dict() for n in sorted(self.nodes)],
                "edges": [e.to_dict() for e in sorted(self.edges, key=lambda e: (e.src, e.dst, e.relationship.value))]}


def leads_payload(graph: KnowledgeGraph, target_fingerprint: str) -> dict[str, Any]:
    leads = graph.leads_for(target_fingerprint)
    return {"target_fingerprint": target_fingerprint, "leads": [l.to_dict() for l in leads],
            "note": "Leads are cross-engagement priors; each must pass this engagement's full oracle + clean-session validation before belief (B36: leads, never proof)."}
