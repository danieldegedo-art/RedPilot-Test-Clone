"""Payment-Flow Reachability Graph -- wider/deeper paywall discovery as a model.

The payment surface is rarely a single URL: it is reached through a multi-step
flow (landing -> button -> modal -> continue -> method -> payment-info), often
with no URL change and gated by account state. This module treats "where is the
paywall?" as a REACHABILITY problem over a state graph, not a URL-match:

  * nodes      = application states (pages, modals, backend states), each with the
                 observable signals seen there;
  * edges      = interactions (link, button, modal-open, option-select, form
                 submit, API call, redirect, deep link), each optionally gated by
                 an identity-state condition and optionally causing a backend
                 transition (cart/payment-intent created);
  * a payment surface = any node whose observed signals say "the user is being
                 asked to pay" (card fields, a provider SDK, a pricing display,
                 method selection, ...), regardless of whether it has a URL.

It then computes, per identity state (free / trial / paid / enterprise / region /
role), which payment surfaces are reachable and by what path, and emits the
flow-graph report.

Boundaries (why this is the bounded QA tool, not something broader):
  * It is a PURE MODEL + PLANNER: it drives nothing. The navigation-class steps map
    to the bounded browser-surface vocabulary (NAVIGATE/SUBMIT/READ); the click
    steps (button/modal/option) are performed by the real browser tools under the
    usual controls -- the same "plans, does not drive" split as browser_surface.py.
    The crawler's documented gap ("does NOT click buttons") is closed at the MODEL
    level here; execution stays with the controlled browser tools, pointed only at
    the authorized target / staging copy, observing only RedPilot's own test traffic.
  * Bounded and deterministic: node/edge/depth caps, sorted traversal, cycle-safe.
    It discovers and maps the surface; proving a flaw on it stays with the engine's
    oracle + the $0.00 test instrument. It adds no offensive capability.

Stdlib only; pure.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from app.testing.integrity.browser_surface import BrowserAction

MODULE_VERSION = "payment-flow-graph/1.0"
MAX_NODES = 512
MAX_EDGES = 4096
MAX_DEPTH = 32


class InteractionKind(str, Enum):
    LINK = "link"                     # <a href> navigation to a new URL
    REDIRECT = "redirect"             # 301/302/meta-refresh/JS redirect
    DEEP_LINK = "deep_link"           # restore app state to a payment-relevant point
    BUTTON = "button"                 # click that transitions state / may route
    MODAL_OPEN = "modal_open"         # click that opens a modal/drawer (no URL change)
    OPTION_SELECT = "option_select"   # choose a plan / quantity / payment method (no URL change)
    FORM_SUBMIT = "form_submit"       # submit a form (backend transition)
    API_CALL = "api_call"             # frontend-issued API call that reveals gated behaviour


_NAVIGATION_INTERACTIONS = frozenset({InteractionKind.LINK, InteractionKind.REDIRECT, InteractionKind.DEEP_LINK})
_CLICK_INTERACTIONS = frozenset({InteractionKind.BUTTON, InteractionKind.MODAL_OPEN, InteractionKind.OPTION_SELECT})


def browser_action_for(interaction: InteractionKind) -> BrowserAction | None:
    """Map a flow interaction to the bounded browser-surface action that drives it,
    or None for a click (button/modal/option) -- a click is not expressible in the
    fixed NAVIGATE/FILL/SUBMIT/READ vocabulary and is performed by the real browser
    tools under controls. This is exactly the crawler's "does NOT click" gap, made
    explicit at the model boundary rather than silently skipped."""
    if interaction in _NAVIGATION_INTERACTIONS:
        return BrowserAction.NAVIGATE
    if interaction is InteractionKind.FORM_SUBMIT:
        return BrowserAction.SUBMIT
    if interaction is InteractionKind.API_CALL:
        return BrowserAction.READ
    return None


# Observable signals that classify a node as a payment surface (the detection list
# from the wider/deeper paywall-discovery spec). Public, surface-level signals only.
PAYMENT_SIGNALS = frozenset({
    "payment_method_selection", "card_fields", "provider_sdk", "pricing_display",
    "billing_cycle_selection", "subscription_confirmation", "invoice_generation",
    "payment_intent_created", "order_or_cart_created", "purchase_completion",
})


@dataclass(frozen=True)
class SurfaceClassification:
    is_payment_surface: bool
    matched_signals: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"is_payment_surface": self.is_payment_surface, "matched_signals": list(self.matched_signals)}


def classify_payment_surface(signals: Iterable[str]) -> SurfaceClassification:
    """A node is a payment surface iff it exhibits at least one payment signal. URL
    is deliberately NOT a requirement (the whole point of flow-reachability)."""
    matched = tuple(sorted(set(signals) & PAYMENT_SIGNALS))
    return SurfaceClassification(bool(matched), matched)


@dataclass(frozen=True)
class FlowNode:
    node_id: str
    label: str = ""
    host: str | None = None
    signals: tuple[str, ...] = ()
    provider: str | None = None  # fingerprinted provider (recon lead), if known

    def classification(self) -> SurfaceClassification:
        return classify_payment_surface(self.signals)

    @property
    def is_payment_surface(self) -> bool:
        return self.classification().is_payment_surface


@dataclass(frozen=True)
class FlowEdge:
    src: str
    dst: str
    interaction: InteractionKind
    conditions: frozenset[str] = frozenset()   # identity-state labels this edge needs; empty = unconditional
    backend_transition: str | None = None       # e.g. "cart_created", "payment_intent_created" (observed via own API traffic)

    def available_under(self, identity_state: str) -> bool:
        return not self.conditions or identity_state in self.conditions


@dataclass(frozen=True)
class FlowStep:
    src: str
    dst: str
    interaction: str
    backend_transition: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "interaction": self.interaction, "backend_transition": self.backend_transition}


@dataclass(frozen=True)
class FlowPath:
    surface: str
    identity_state: str
    steps: tuple[FlowStep, ...]
    provider: str | None
    evidence: tuple[str, ...]

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def interaction_types(self) -> list[str]:
        return [s.interaction for s in self.steps]

    @property
    def backend_transitions(self) -> list[str]:
        return [s.backend_transition for s in self.steps if s.backend_transition]

    def to_dict(self) -> dict[str, Any]:
        return {"surface": self.surface, "identity_state": self.identity_state, "step_count": self.step_count,
                "steps": [s.to_dict() for s in self.steps], "interaction_types": self.interaction_types,
                "backend_transitions": self.backend_transitions, "provider": self.provider, "evidence": list(self.evidence)}


class FlowGraphError(ValueError):
    """Raised when a graph violates the bounded-model constraints (size caps,
    dangling edge, unknown entry point)."""


@dataclass
class PaymentFlowGraph:
    nodes: dict[str, FlowNode]
    edges: list[FlowEdge]
    entry_points: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.nodes) > MAX_NODES:
            raise FlowGraphError(f"{len(self.nodes)} nodes exceeds the cap of {MAX_NODES}")
        if len(self.edges) > MAX_EDGES:
            raise FlowGraphError(f"{len(self.edges)} edges exceeds the cap of {MAX_EDGES}")
        for e in self.edges:
            if e.src not in self.nodes or e.dst not in self.nodes:
                raise FlowGraphError(f"edge {e.src!r}->{e.dst!r} references an unknown node")
        for ep in self.entry_points:
            if ep not in self.nodes:
                raise FlowGraphError(f"entry point {ep!r} is not a node")

    def payment_surfaces(self) -> list[str]:
        return sorted(nid for nid, n in self.nodes.items() if n.is_payment_surface)


def reachable_payment_surfaces(graph: PaymentFlowGraph, *, identity_state: str, max_depth: int = MAX_DEPTH) -> list[FlowPath]:
    """Shortest path from any entry point to each payment surface reachable under
    `identity_state`. Deterministic (sorted adjacency + sorted entry points),
    cycle-safe (each node enqueued once, at its shortest depth), depth-capped."""
    adj: dict[str, list[FlowEdge]] = {}
    for e in sorted((e for e in graph.edges if e.available_under(identity_state)),
                    key=lambda e: (e.src, e.dst, e.interaction.value)):
        adj.setdefault(e.src, []).append(e)

    results: dict[str, FlowPath] = {}
    visited: dict[str, int] = {}
    queue: deque[tuple[str, tuple[FlowStep, ...]]] = deque()
    for ep in sorted(graph.entry_points):
        if ep not in visited:
            visited[ep] = 0
            queue.append((ep, ()))

    while queue:
        node_id, path = queue.popleft()
        node = graph.nodes[node_id]
        if node.is_payment_surface and node_id not in results:
            cls = node.classification()
            results[node_id] = FlowPath(node_id, identity_state, path, node.provider, cls.matched_signals)
        if len(path) >= max_depth:
            continue
        for e in adj.get(node_id, []):
            new_path = path + (FlowStep(e.src, e.dst, e.interaction.value, e.backend_transition),)
            if e.dst not in visited or visited[e.dst] > len(new_path):
                visited[e.dst] = len(new_path)
                queue.append((e.dst, new_path))
    return [results[k] for k in sorted(results)]


def explore(graph: PaymentFlowGraph, *, identity_states: Iterable[str], max_depth: int = MAX_DEPTH) -> dict[str, Any]:
    """The flow-graph report: for every payment surface, under which identity states
    it is reachable (with the exact path, interaction types, backend transitions and
    classifying evidence) and under which it is not -- never a single flattened claim."""
    states = sorted(dict.fromkeys(identity_states))
    per_state = {s: {p.surface: p for p in reachable_payment_surfaces(graph, identity_state=s, max_depth=max_depth)} for s in states}
    surfaces = []
    for surf in graph.payment_surfaces():
        reachable_under = [per_state[s][surf].to_dict() for s in states if surf in per_state[s]]
        not_reachable_under = [s for s in states if surf not in per_state[s]]
        surfaces.append({"surface": surf, "label": graph.nodes[surf].label, "provider": graph.nodes[surf].provider,
                         "reachable_under": reachable_under, "not_reachable_under": not_reachable_under})
    return {
        "module_version": MODULE_VERSION,
        "bounded": True,
        "identity_states": states,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "payment_surfaces_total": len(graph.payment_surfaces()),
        "surfaces": surfaces,
        "note": ("Flow-reachability model of the AUTHORIZED target's own payment surface. It plans and maps only; "
                 "the real browser tools perform the click-gated steps under controls, pointed at the authorized "
                 "target / staging copy and observing only RedPilot's own synthetic test traffic. Discovery maps the "
                 "surface; proving a flaw on it stays with the engine's oracle + the $0.00 test instrument."),
    }
