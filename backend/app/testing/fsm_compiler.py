"""B1 / ZR-001: Payment-Entitlement State Machine Compiler.

WHERE THIS SITS RELATIVE TO WHAT ALREADY EXISTS
-----------------------------------------------
app/testing/lifecycle_model.py holds the hand-specified, canonical lifecycle
(VALID_PAYMENT_TRANSITIONS / VALID_SUBSCRIPTION_TRANSITIONS) -- what SHOULD be
legal. app/testing/state_exploration.py runs graph algorithms over that
specification. This module is the complementary half: it compiles the machine
a SPECIFIC target actually exhibits, from observed transitions, so the two can
be compared (compare_with_spec). It deliberately reuses state_exploration's
TransitionMap shape and reachable_states() instead of re-implementing graph
traversal, so the observed machine and the specified machine go through the
same code.

WHAT IS IMPLEMENTED (B1's description, Master Specification Section 8)
----------------------------------------------------------------------
  * compile_fsm: observed (from_state, trigger, to_state) transitions ->
    segments per flow type (ZR-001's list), each transition carrying its
    support and a confidence. Confidence is a plain, inspectable function of
    support and consistency (see SUPPORT_PRIOR) -- the spec's "a model with
    confidence attached, never ground truth".
  * Versioning (FSMHistory): every compiled version is retained, immutable,
    addressable by model_version, so a downstream decision can be traced to
    the exact model it was made under. A new version is cut only when the
    model's content actually changes.
  * Empirical validation (validate): new observations are checked against the
    model's predictions -- confirmed / divergent / novel. Divergence or novelty
    means "recompile", reported, not silently absorbed.
  * Graph analysis (analyze) and comparison with the specified lifecycle
    (compare_with_spec). An observed transition the specification calls
    illegal is a HYPOTHESIS CANDIDATE, never a finding: nothing here can
    produce a CONFIRMED_P0. That still takes ConfirmationGate.evaluate().
  * Coverage (ZR-001's acceptance criterion): every flow type the engagement
    expects either has a segment or is listed in uncovered_flow_types. A flow
    type with no observations is reported as a gap, never fabricated.

WHAT IS NOT IMPLEMENTED (stated, not implied)
---------------------------------------------
  * Ingesting OpenAPI/GraphQL specs and webhook schemas -- B1 names them as
    inputs; this compiles from observed transitions only (PESM's
    EntitlementTransition via observed_from_entitlement_transitions, or any
    caller building ObservedTransition). Spec ingestion is a separate adapter.
  * Guards and constraint solving -- the FSM records which (state, trigger)
    led where and how consistently; it does not infer the conditions under
    which a transition fires. Nondeterminism (one (state, trigger) reaching
    several targets) is surfaced instead of being solved away.

Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from app.testing.pesm import EntitlementTransition, PESMStore
from app.testing.state_exploration import TransitionMap, reachable_states

# ZR-001's flow list. "webhook" and "provider-event" are one flow type here: a
# webhook is how a provider event is delivered.
FLOW_TYPES: tuple[str, ...] = (
    "payment", "checkout", "provider_event", "subscription", "trial", "renewal",
    "cancellation", "refund", "chargeback", "upgrade", "downgrade", "entitlement",
)
UNCLASSIFIED = "unclassified"

# Ordered: the FIRST rule that matches wins, so more specific vocabulary precedes
# the more general words it overlaps with ("chargeback" before "charge", "refund"
# before "payment", "webhook" before "payment" for "webhook_payment_succeeded").
# A needle matches only where a word BEGINS (after normalization, at the start or
# right after an underscore) and may be followed by anything -- "refund" matches
# "payment_refunded", but "trial" does NOT match "industrial_event" and "charge"
# does not match "discharge_complete", which plain substring matching would.
# Heuristic by nature: a trigger matching no rule is UNCLASSIFIED and reported as
# such, never forced into a flow type.
_FLOW_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("chargeback", ("chargeback", "dispute")),
    ("refund", ("refund",)),
    ("cancellation", ("cancel",)),
    ("downgrade", ("downgrade",)),
    ("upgrade", ("upgrade",)),
    ("trial", ("trial",)),
    ("renewal", ("renew", "recurring", "rebill")),
    ("provider_event", ("webhook", "provider_event")),
    ("checkout", ("checkout", "return_flow")),
    ("subscription", ("subscription", "plan_change", "pause", "resume")),
    ("payment", ("payment", "charge", "capture", "authoriz", "invoice")),
    ("entitlement", ("entitle", "grant", "revoke", "expire", "expiry", "lapse")),
)
_FLOW_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = tuple(
    (flow, re.compile(r"(?:^|_)(?:" + "|".join(re.escape(n) for n in needles) + ")"))
    for flow, needles in _FLOW_RULES
)

# confidence = observations_for_this_target / (observations_for_this_(state,trigger) + SUPPORT_PRIOR).
# Shrinks toward zero so one observation cannot read as certain (1 obs -> 0.33,
# 10 consistent obs -> 0.83) and splits across targets when the same
# (state, trigger) is observed reaching different states.
SUPPORT_PRIOR = 2.0
_MAX_EVIDENCE_IDS = 20  # references only; the artifacts live in the ledger / PESM, the model just points at them


def classify_flow(trigger: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", trigger.lower()).strip("_")
    for flow, pattern in _FLOW_PATTERNS:
        if pattern.search(normalized):
            return flow
    return UNCLASSIFIED


@dataclass(frozen=True)
class ObservedTransition:
    resource_type: str  # "payment" | "subscription" | "entitlement" | ...
    from_state: str
    trigger: str
    to_state: str
    observed_at: datetime | None = None
    evidence_artifact_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class FSMTransition:
    from_state: str
    trigger: str
    to_state: str
    flow_type: str
    observations: int
    confidence: float
    evidence_artifact_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class FSMSegment:
    flow_type: str
    transitions: tuple[FSMTransition, ...]

    @property
    def states(self) -> frozenset[str]:
        return frozenset(s for t in self.transitions for s in (t.from_state, t.to_state))

    @property
    def nondeterministic(self) -> tuple[tuple[str, str], ...]:
        """(from_state, trigger) pairs observed reaching MORE THAN ONE target --
        the same input producing different outcomes, itself worth a look."""
        targets: dict[tuple[str, str], set[str]] = defaultdict(set)
        for t in self.transitions:
            targets[(t.from_state, t.trigger)].add(t.to_state)
        return tuple(sorted(k for k, v in targets.items() if len(v) > 1))


@dataclass(frozen=True)
class CompiledFSM:
    resource_type: str
    version: int
    fingerprint: str  # content: structure + support + coverage claim
    structure_fingerprint: str  # structure only: did the SHAPE of the machine change, or just its support?
    segments: tuple[FSMSegment, ...]
    observation_count: int
    uncovered_flow_types: tuple[str, ...]

    @property
    def model_version(self) -> str:
        return f"{self.resource_type}@v{self.version}:{self.fingerprint[:12]}"

    def segment(self, flow_type: str) -> FSMSegment | None:
        return next((s for s in self.segments if s.flow_type == flow_type), None)

    def transitions(self) -> tuple[FSMTransition, ...]:
        return tuple(t for s in self.segments for t in s.transitions)

    def predict(self, from_state: str, trigger: str) -> tuple[tuple[str, float], ...]:
        out = [(t.to_state, t.confidence) for t in self.transitions() if t.from_state == from_state and t.trigger == trigger]
        return tuple(sorted(out, key=lambda x: (-x[1], x[0])))

    def as_transition_map(self) -> dict[str, set[str]]:
        """The shape state_exploration's algorithms already consume."""
        m: dict[str, set[str]] = {}
        for t in self.transitions():
            m.setdefault(t.from_state, set()).add(t.to_state)
            m.setdefault(t.to_state, set())
        return m


def _digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compile_fsm(
    observations: Iterable[ObservedTransition], *, resource_type: str,
    expected_flow_types: Iterable[str] = (), version: int = 1,
) -> CompiledFSM:
    expected = tuple(expected_flow_types)
    unknown = [f for f in expected if f not in FLOW_TYPES]
    if unknown:
        # A misspelled flow type would otherwise sit in uncovered_flow_types forever with no hint why.
        raise ValueError(f"unknown flow type(s) {unknown}; valid: {FLOW_TYPES}")

    obs = [o for o in observations if o.resource_type == resource_type]
    counts: dict[tuple[str, str, str], int] = defaultdict(int)
    evidence: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for o in obs:
        key = (o.from_state, o.trigger, o.to_state)
        counts[key] += 1
        evidence[key].update(o.evidence_artifact_ids)
    totals: dict[tuple[str, str], int] = defaultdict(int)
    for (f, t, _), c in counts.items():
        totals[(f, t)] += c

    by_flow: dict[str, list[FSMTransition]] = defaultdict(list)
    for (f, t, to), c in sorted(counts.items()):
        flow = classify_flow(t)
        by_flow[flow].append(FSMTransition(
            from_state=f, trigger=t, to_state=to, flow_type=flow, observations=c,
            confidence=round(c / (totals[(f, t)] + SUPPORT_PRIOR), 4),
            evidence_artifact_ids=tuple(sorted(evidence[(f, t, to)]))[:_MAX_EVIDENCE_IDS],
        ))
    segments = tuple(FSMSegment(flow, tuple(trs)) for flow, trs in sorted(by_flow.items()))
    uncovered = tuple(sorted(set(expected) - {s.flow_type for s in segments}))

    shape = [[t.from_state, t.trigger, t.to_state] for s in segments for t in s.transitions]
    return CompiledFSM(
        resource_type=resource_type, version=version,
        fingerprint=_digest([resource_type, [[*x, counts[tuple(x)]] for x in shape], list(uncovered)]),
        structure_fingerprint=_digest([resource_type, shape]),
        segments=segments, observation_count=len(obs), uncovered_flow_types=uncovered,
    )


class FSMHistory:
    """Every compiled version retained and immutable (CompiledFSM is frozen), so
    a decision recorded against model_version "entitlement@v3:ab12..." can
    always be traced back to exactly that model."""

    def __init__(self) -> None:
        self._versions: dict[str, list[CompiledFSM]] = {}

    def update(
        self, observations: Iterable[ObservedTransition], *, resource_type: str, expected_flow_types: Iterable[str] = (),
    ) -> CompiledFSM:
        prior = self.latest(resource_type)
        fsm = compile_fsm(observations, resource_type=resource_type, expected_flow_types=expected_flow_types,
                          version=(prior.version + 1) if prior else 1)
        if prior is not None and prior.fingerprint == fsm.fingerprint:
            return prior  # nothing changed -- no new version
        self._versions.setdefault(resource_type, []).append(fsm)
        return fsm

    def latest(self, resource_type: str) -> CompiledFSM | None:
        vs = self._versions.get(resource_type)
        return vs[-1] if vs else None

    def get(self, resource_type: str, version: int) -> CompiledFSM | None:
        return next((f for f in self._versions.get(resource_type, ()) if f.version == version), None)

    def versions(self, resource_type: str) -> tuple[CompiledFSM, ...]:
        return tuple(self._versions.get(resource_type, ()))


@dataclass(frozen=True)
class ValidationReport:
    model_version: str
    confirmed: int
    divergent: tuple[ObservedTransition, ...]  # (state, trigger) known, but it reached a state the model never saw it reach
    novel: tuple[ObservedTransition, ...]  # (state, trigger) the model has never seen at all

    @property
    def needs_recompile(self) -> bool:
        return bool(self.divergent or self.novel)


def validate(fsm: CompiledFSM, observations: Iterable[ObservedTransition]) -> ValidationReport:
    """Empirical validation (B1): check new observations against the model's predictions."""
    confirmed = 0
    divergent: list[ObservedTransition] = []
    novel: list[ObservedTransition] = []
    for o in observations:
        if o.resource_type != fsm.resource_type:
            continue
        predicted = {to for to, _ in fsm.predict(o.from_state, o.trigger)}
        if not predicted:
            novel.append(o)
        elif o.to_state in predicted:
            confirmed += 1
        else:
            divergent.append(o)
    return ValidationReport(fsm.model_version, confirmed, tuple(divergent), tuple(novel))


@dataclass(frozen=True)
class SpecComparison:
    illegal_observed: tuple[FSMTransition, ...]  # observed, and the specification says the (from -> to) edge is illegal: HYPOTHESIS CANDIDATES, not findings
    unobserved_legal: tuple[tuple[str, str], ...]  # specification-legal (from, to) edges never observed: coverage gaps
    unknown_states: frozenset[str]  # observed states the specification doesn't contain -- usually a vocabulary mismatch, NOT judged either way


def compare_with_spec(fsm: CompiledFSM, spec: TransitionMap) -> SpecComparison:
    spec_states = set(spec.keys()) | {s for targets in spec.values() for s in targets}
    illegal: list[FSMTransition] = []
    unknown: set[str] = set()
    observed_edges: set[tuple[str, str]] = set()
    for t in fsm.transitions():
        observed_edges.add((t.from_state, t.to_state))
        missing = {s for s in (t.from_state, t.to_state) if s not in spec_states}
        if missing:
            unknown |= missing  # can't judge legality against a vocabulary we don't have -- no guess either way
            continue
        if t.from_state == t.to_state:
            continue  # no state change (e.g. an idempotent duplicate delivery) is not a transition
        if t.to_state not in spec.get(t.from_state, ()):
            illegal.append(t)
    unobserved = sorted((a, b) for a, targets in spec.items() for b in targets if (a, b) not in observed_edges)
    return SpecComparison(tuple(illegal), tuple(unobserved), frozenset(unknown))


@dataclass(frozen=True)
class GraphAnalysis:
    states: frozenset[str]
    initial_states: frozenset[str]
    reachable: frozenset[str]
    unreachable: frozenset[str]
    dead_ends: frozenset[str]  # no outgoing transition observed (terminal, or just never seen leaving)


def analyze(fsm: CompiledFSM, initial_states: Iterable[str] | None = None) -> GraphAnalysis:
    tmap = fsm.as_transition_map()
    states = frozenset(tmap)
    if initial_states is None:
        has_incoming = {to for targets in tmap.values() for to in targets}
        initial = frozenset(s for s in states if s not in has_incoming)
        if not initial:
            initial = states  # every state sits on a cycle: nothing can be called unreachable, so claim nothing
    else:
        initial = frozenset(initial_states)
    reach: set[str] = set()
    for s in initial:
        reach |= reachable_states(tmap, s)
    dead_ends = frozenset(s for s, targets in tmap.items() if not (targets - {s}))
    return GraphAnalysis(states, initial, frozenset(reach), states - reach, dead_ends)


def observed_from_entitlement_transitions(transitions: Iterable[EntitlementTransition]) -> list[ObservedTransition]:
    return [
        ObservedTransition("entitlement", t.from_status.value, t.trigger, t.to_status.value, t.occurred_at, t.evidence_artifact_ids)
        for t in transitions
    ]


async def compile_from_pesm(store: PESMStore, history: FSMHistory, *, expected_flow_types: Iterable[str] = ()) -> CompiledFSM:
    """ZR-001 over what PESM (ZR-002) has recorded: the entitlement lifecycle."""
    return history.update(
        observed_from_entitlement_transitions(await store.all_transitions()),
        resource_type="entitlement", expected_flow_types=expected_flow_types,
    )
