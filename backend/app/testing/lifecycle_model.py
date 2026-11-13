"""Canonical payment/subscription lifecycle state model.

Extracted from modules/state_transition_consistency.py, which originally
defined these tables inline. No behavior changes: same dict contents, same
state names, same case-insensitive lookup semantics as before -- this is a
pure relocation, done for one reason: state_transition_consistency.py
imports app.testing.base, which imports app.testing.context, which imports
QAHttpClient (httpx-backed). That is the right dependency chain for a
module that sends HTTP requests; it is the wrong one for a plain
`dict[str, set[str]]` that a pure graph algorithm (see state_exploration.py)
needs to import. A data table describing "what states exist and which
transitions between them are legal" should not require a web framework
and an HTTP client to be importable -- moving it here means it doesn't.

state_transition_consistency.py re-exports every name below unchanged
(`from app.testing.lifecycle_model import *`-equivalent, done explicitly)
so nothing importing FROM that module needs to change; grepped across the
codebase before this move to confirm nothing else already imported these
names directly from state_transition_consistency (see the commit message /
PR description for that grep). This module has zero third-party
dependencies -- stdlib only -- by design, so it can be imported in any
environment that can run Python at all, independent of which optional
extras (httpx, pydantic, fastapi, sklearn, ...) happen to be installed.
"""
from __future__ import annotations

# Valid state transition map for a typical payment lifecycle.
# Key: current state, Value: set of allowed next states.
VALID_PAYMENT_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"authorized", "cancelled", "failed", "expired"},
    "authorized": {"captured", "cancelled", "expired", "refunded"},
    "captured": {"refunded", "partially_refunded"},
    "partially_refunded": {"refunded"},
    "refunded": set(),  # terminal state
    "cancelled": set(),  # terminal state
    "failed": set(),  # terminal state
    "expired": set(),  # terminal state
}

# Valid state transition map for a typical subscription lifecycle.
VALID_SUBSCRIPTION_TRANSITIONS: dict[str, set[str]] = {
    "trialing": {"active", "cancelled", "expired", "past_due"},
    "active": {"cancelled", "past_due", "expired"},
    "past_due": {"active", "cancelled", "expired"},
    "cancelled": set(),  # terminal state
    "expired": set(),  # terminal state
}

# Terminal states that should never transition to another state.
TERMINAL_PAYMENT_STATES = {"refunded", "cancelled", "failed", "expired"}
TERMINAL_SUBSCRIPTION_STATES = {"cancelled", "expired"}

# States that indicate an active/paying subscription.
ACTIVE_LOOKING_STATES = {"active", "activated", "trialing", "trial"}

# States that indicate a cancelled/inactive subscription.
CANCELLED_LOOKING_STATES = {"cancelled", "canceled", "inactive", "expired", "ended"}


def is_terminal_state(state: str, resource_type: str = "payment") -> bool:
    """Checks whether a given state is terminal (should not transition further)."""
    if resource_type == "subscription":
        return state.lower() in TERMINAL_SUBSCRIPTION_STATES
    return state.lower() in TERMINAL_PAYMENT_STATES


def is_valid_transition(from_state: str, to_state: str, resource_type: str = "payment") -> bool:
    """Checks whether a transition from one state to another is valid.

    Returns True for an unrecognized `from_state` ("can't judge" rather
    than "reject") -- unchanged from the original semantics in
    state_transition_consistency.py; callers that need strict validation
    should check membership in VALID_PAYMENT_TRANSITIONS /
    VALID_SUBSCRIPTION_TRANSITIONS themselves first (state_exploration.py
    does exactly that, since exhaustive enumeration only makes sense over
    states the table actually knows about).
    """
    transitions = VALID_SUBSCRIPTION_TRANSITIONS if resource_type == "subscription" else VALID_PAYMENT_TRANSITIONS
    from_lower = from_state.lower()
    to_lower = to_state.lower()
    if from_lower not in transitions:
        return True
    return to_lower in transitions[from_lower]


def all_states(resource_type: str = "payment") -> frozenset[str]:
    """Every state name the model for this resource type knows about,
    whether it appears as a source or only ever as a target."""
    transitions = VALID_SUBSCRIPTION_TRANSITIONS if resource_type == "subscription" else VALID_PAYMENT_TRANSITIONS
    states = set(transitions.keys())
    for targets in transitions.values():
        states |= targets
    return frozenset(states)
