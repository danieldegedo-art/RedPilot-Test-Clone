"""ZR-002: Persistent, machine-readable Payment-to-Entitlement State Model.

Schema source: Master Specification Section 3 (Payment and Entitlement Domain
Model), owned by A5 (Payment-Flow Modeling), A6 (Entitlement-Invariant), A7
(API Behavior and Contract) per the spec's own requirements table (ZR-002).
This module defines the shared vocabulary those three agents read from and
write to -- not a full implementation of each agent.

Three entities, directly off Section 3:
  Feature              -- a registered paid/protected capability (3.4, 3.8:
                           "the boundary is the server-side entitlement
                           record" -- NOT the feature flag, and nothing can
                           be evaluated as a finding against a feature that
                           was never registered here; see 3.8's "central
                           domain area" and oracle_gate.py's use of
                           registered_feature_ids, which closes ZR-025's
                           condition 1).
  EntitlementState      -- one identity/tenant's entitlement to one Feature
                           at one moment (3.4 "entitlement snapshot
                           before/after", 3.5 "entitlement state
                           before/after"). Immutable: a new state is a new
                           EntitlementState row, never a mutation of an old
                           one, so the append log IS the history
                           (ZR-007: run-spanning persistent memory).
  EntitlementTransition -- one lifecycle transition between two states (3.7
                           "full transition sequence with timestamps,
                           entitlement diffs"), always carrying what
                           triggered it so 3.5/3.7's flaw signals (grant on
                           an unverified client signal; access surviving a
                           refund/chargeback/cancellation) are directly
                           checkable facts instead of narrative.

PESMStore is the persistence boundary (ZR-007: must survive past a single
run, unlike ResultCollector -- see runner.py). InMemoryPESMStore is a real,
usable implementation (tests, and any caller that doesn't need cross-run
durability), not just a test double; a SQLAlchemy-backed store satisfying
the same Protocol is the natural next increment, following the exact
dependency-injection pattern ZR-009 already established (runner.py's
PersistResultFn / api/v1/runs.py's _persist_result_db) -- deliberately not
built in this pass, flagged rather than rushed.

Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Protocol


class EntitlementStatus(str, Enum):
    """3.4/3.7's possible entitlement states. NEVER_GRANTED is distinct from
    EXPIRED/REVOKED -- 3.5's invariant is about a transition INTO access, and
    "never had it" vs "had it and lost it" are different flaw-signal shapes
    (3.5 unverified-grant vs 3.5/3.7 access-survives-revocation)."""

    ACTIVE = "active"
    TRIAL = "trial"
    EXPIRED = "expired"
    REVOKED = "revoked"
    NEVER_GRANTED = "never_granted"


@dataclass(frozen=True)
class Feature:
    """A registered paid/protected capability. Registration is what makes
    "this is a defined paid/protected feature" (ZR-025 condition 1) a
    checkable fact instead of an unstated assumption baked into whichever
    agent happened to generate the hypothesis."""

    feature_id: str
    name: str
    discovered_via: str  # e.g. "A3 surface discovery", "A7 contract inference", "operator-declared in brief"
    registered_at: datetime


@dataclass(frozen=True)
class EntitlementState:
    """A snapshot, never a mutation (see module docstring). `source` must
    name a server-verified origin (3.5's invariant: "never an unverified
    client callback") -- this module doesn't enforce that string's content
    (that's ZR-024's blocklist / oracle_gate's job for the *access* decision);
    it just requires every snapshot to say where it came from."""

    feature_id: str
    identity_alias: str
    tenant_alias: str | None
    status: EntitlementStatus
    observed_at: datetime
    source: str
    evidence_artifact_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class EntitlementTransition:
    """One lifecycle transition (3.7). `trigger` is free text by design --
    the spec's own trigger vocabulary spans 3.5 (payment_confirmed, refund,
    chargeback, failed_capture) and 3.7 (plan_upgrade, plan_downgrade,
    pause, cancellation, expiry, recovery) and more may surface as agents
    are built; constraining it to a closed enum here would mean this module
    has to change every time a new lifecycle is modeled, which is exactly
    the kind of coupling ZR-002's "shared domain model" is supposed to
    avoid. (Codifying a closed vocabulary with real flaw-signal semantics
    per trigger, if later needed, belongs in a new B2-invariant-library
    entry that imports these types -- not in the type itself.)"""

    feature_id: str
    identity_alias: str
    tenant_alias: str | None
    from_status: EntitlementStatus
    to_status: EntitlementStatus
    trigger: str
    occurred_at: datetime
    evidence_artifact_ids: tuple[str, ...] = ()


class PESMStore(Protocol):
    """Persistence boundary -- async because the real implementation is a DB
    (ZR-007: must outlive a single run), same reasoning as runner.py's
    PersistResultFn. ConfirmationGate itself does NOT depend on this
    Protocol (see oracle_gate.py): evaluate() is synchronous and must stay
    that way (changing it would ripple into interface.py's
    ConfirmationGateHandle Protocol, control_adapter/adapter.py's guarded
    wrapper, and three existing tests this sandbox can't execute to
    re-verify) -- a resolved `frozenset[str]` of registered feature ids is
    what the gate actually needs, not a live store reference.
    """

    async def register_feature(self, feature: Feature) -> None: ...
    async def is_registered(self, feature_id: str) -> bool: ...
    async def registered_feature_ids(self) -> frozenset[str]: ...
    async def record_state(self, state: EntitlementState) -> None: ...
    async def record_transition(self, transition: EntitlementTransition) -> None: ...
    async def latest_state(
        self, feature_id: str, identity_alias: str, tenant_alias: str | None, *, before: datetime | None = None,
    ) -> EntitlementState | None: ...
    async def transitions_for(
        self, feature_id: str, identity_alias: str, tenant_alias: str | None,
    ) -> tuple[EntitlementTransition, ...]: ...
    async def all_transitions(self) -> tuple[EntitlementTransition, ...]: ...  # B1/ZR-001: the FSM compiler reads the whole lifecycle, not one identity's slice of it


@dataclass
class InMemoryPESMStore:
    """A real implementation, not just a test double -- usable anywhere
    cross-run durability isn't required. Append-only for states/transitions,
    matching the "snapshot, never a mutation" rule in the module docstring.
    """

    _features: dict[str, Feature] = field(default_factory=dict)
    _states: list[EntitlementState] = field(default_factory=list)
    _transitions: list[EntitlementTransition] = field(default_factory=list)

    async def register_feature(self, feature: Feature) -> None:
        # Idempotent: registering the same feature_id again is a no-op if
        # unchanged, and otherwise the newer registration wins (discovery
        # can refine `name`/`discovered_via` as more surface is mapped).
        self._features[feature.feature_id] = feature

    async def is_registered(self, feature_id: str) -> bool:
        return feature_id in self._features

    async def registered_feature_ids(self) -> frozenset[str]:
        return frozenset(self._features)

    async def record_state(self, state: EntitlementState) -> None:
        self._states.append(state)

    async def record_transition(self, transition: EntitlementTransition) -> None:
        self._transitions.append(transition)

    async def latest_state(
        self, feature_id: str, identity_alias: str, tenant_alias: str | None, *, before: datetime | None = None,
    ) -> EntitlementState | None:
        candidates = [
            s for s in self._states
            if s.feature_id == feature_id and s.identity_alias == identity_alias and s.tenant_alias == tenant_alias
            and (before is None or s.observed_at <= before)
        ]
        return max(candidates, key=lambda s: s.observed_at) if candidates else None

    async def transitions_for(
        self, feature_id: str, identity_alias: str, tenant_alias: str | None,
    ) -> tuple[EntitlementTransition, ...]:
        return tuple(
            t for t in self._transitions
            if t.feature_id == feature_id and t.identity_alias == identity_alias and t.tenant_alias == tenant_alias
        )

    async def all_transitions(self) -> tuple[EntitlementTransition, ...]:
        return tuple(self._transitions)


def entitlement_states_from_oracle_observations(observations: Iterable[Any], *, recorded_at: datetime) -> list[EntitlementState]:
    """ZR-002 / A5 (Payment-Flow Modeling): one EntitlementState snapshot per
    oracle observation from a completed PureBlackBoxEngine run
    (engine.oracle.observations -- app.testing.integrity.oracle.
    ProtectedFeatureOracle). `observations` is typed Any rather than
    OracleObservation to avoid coupling this pure testing-domain module to
    core.control_port.contract for a type hint alone; duck-typed on
    .outcome/.feature_id/.identity_alias/.tenant_alias/.oracle_id/.artifact_ids.

    Status mapping is a documented approximation, not a precise read of the
    target's actual entitlement record (which PESM cannot see -- this is a
    pure black-box platform): "allowed" becomes ACTIVE (some entitlement was
    in effect, whatever it actually was); "denied" becomes NEVER_GRANTED, the
    least specific of the three denial-shaped statuses (EXPIRED/REVOKED/
    NEVER_GRANTED), because a single observation cannot distinguish "never
    had it" from "had it and lost it" -- inventing that distinction would be
    exactly the fabrication this project's own standards forbid. `source`
    always names which oracle observation it came from, so the
    approximation is traceable, not silent.

    observed_at uses `recorded_at` (when this function runs), not an event
    time -- OracleObservation carries no timestamp of its own. Within one
    engine run this differs from the moment of observation by at most the
    run's own duration, stated here rather than left implicit.

    A6 (Entitlement-Invariant) and A7 (API Behavior and Contract) are
    deliberately not built as their own modules: A6 overlaps with B2
    (Entitlement Invariant Library, Phase 4) and A7 with B7 (Contract
    Inference, Phase 4) closely enough that a half-version of each now would
    leave two things to maintain later instead of one real one when those
    breakthroughs are built. See HANDOFF.md.
    """
    out: list[EntitlementState] = []
    for obs in observations:
        status = EntitlementStatus.ACTIVE if obs.outcome == "allowed" else EntitlementStatus.NEVER_GRANTED
        out.append(EntitlementState(
            feature_id=obs.feature_id, identity_alias=obs.identity_alias, tenant_alias=obs.tenant_alias,
            status=status, observed_at=recorded_at, source=f"oracle_observation:{obs.oracle_id}",
            evidence_artifact_ids=tuple(obs.artifact_ids),
        ))
    return out


async def record_oracle_observations(observations: Iterable[Any], store: PESMStore, *, recorded_at: datetime) -> None:
    for state in entitlement_states_from_oracle_observations(observations, recorded_at=recorded_at):
        await store.record_state(state)
