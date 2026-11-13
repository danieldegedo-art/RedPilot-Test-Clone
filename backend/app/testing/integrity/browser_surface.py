"""B35 (owns A27): Stateful Browser-Automation Surface -- BOUNDED and FAIL-CLOSED.

Models a browser session over the authorized target's payment flow as a small,
deterministic state machine, and validates a proposed action sequence against both
the authorized scope and sane session state. It plans; it does not drive a real
browser (that happens through the real browser tools under the usual controls).

Bounds:
  * Fixed action vocabulary (ZR-036): NAVIGATE / FILL / SUBMIT / READ -- matching
    B38's playwright leg; nothing else is expressible.
  * SCOPE: navigation is the only action that changes host, and a NAVIGATE to a host
    outside the authorized allowlist is refused (REFUSED_SCOPE). So the whole session
    stays on authorized hosts.
  * STATE sanity: FILL/SUBMIT/READ require a prior NAVIGATE; SUBMIT requires the form
    to have been filled (no submitting an untouched form). Violations are refused
    (REFUSED_STATE) at the first offending step.
  * A hard cap on the number of actions, and deterministic planning.
  * FAIL-CLOSED: without its enabling control the surface plans nothing (FAIL_CLOSED).

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "browser-surface/1.0"
MAX_ACTIONS = 64


class BrowserAction(str, Enum):
    NAVIGATE = "navigate"
    FILL = "fill"
    SUBMIT = "submit"
    READ = "read"


class SurfaceStatus(str, Enum):
    PLANNED = "PLANNED"
    FAIL_CLOSED = "FAIL_CLOSED"
    REFUSED_SCOPE = "REFUSED_SCOPE"    # navigation to an unauthorized host
    REFUSED_STATE = "REFUSED_STATE"    # an action invalid for the current session state


@dataclass(frozen=True)
class Action:
    kind: BrowserAction
    host: str | None = None    # required for NAVIGATE; ignored otherwise
    field: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class SurfacePlan:
    status: SurfaceStatus
    steps: tuple[dict[str, Any], ...]      # validated steps (up to the point of refusal)
    final_state: dict[str, Any]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "steps": [dict(s) for s in self.steps],
                "final_state": dict(self.final_state), "reason": self.reason}


def plan(actions: list[Action], *, allowed_hosts: set[str], enabled: bool,
         max_actions: int = MAX_ACTIONS) -> SurfacePlan:
    """Validate and plan `actions`. FAIL-CLOSED without the control; REFUSED_SCOPE on
    a navigation off the allowlist; REFUSED_STATE on an action invalid for the state."""
    empty = {"current_host": None, "form_dirty": False, "navigated": False}
    if not enabled:
        return SurfacePlan(SurfaceStatus.FAIL_CLOSED, (), empty,
                           "FAIL-CLOSED: browser automation is disabled because its enabling control is absent")
    if len(actions) > max_actions:
        return SurfacePlan(SurfaceStatus.REFUSED_STATE, (), empty,
                           f"REFUSED: {len(actions)} actions exceeds the cap of {max_actions}")

    state = dict(empty)
    steps: list[dict[str, Any]] = []
    for i, a in enumerate(actions):
        if a.kind is BrowserAction.NAVIGATE:
            if not a.host or a.host not in allowed_hosts:
                return SurfacePlan(SurfaceStatus.REFUSED_SCOPE, tuple(steps), state,
                                   f"REFUSED (scope) at step {i}: navigation to {a.host!r} is outside the authorized "
                                   f"host allowlist {sorted(allowed_hosts)}")
            state = {"current_host": a.host, "form_dirty": False, "navigated": True}
        else:
            if not state["navigated"]:
                return SurfacePlan(SurfaceStatus.REFUSED_STATE, tuple(steps), state,
                                   f"REFUSED (state) at step {i}: {a.kind.value} before any NAVIGATE")
            if a.kind is BrowserAction.FILL:
                state = {**state, "form_dirty": True}
            elif a.kind is BrowserAction.SUBMIT:
                if not state["form_dirty"]:
                    return SurfacePlan(SurfaceStatus.REFUSED_STATE, tuple(steps), state,
                                       f"REFUSED (state) at step {i}: SUBMIT with no prior FILL (untouched form)")
                state = {**state, "form_dirty": False}
            # READ does not change state
        steps.append({"kind": a.kind.value, "host": state["current_host"], "field": a.field})

    return SurfacePlan(SurfaceStatus.PLANNED, tuple(steps), state,
                       f"{len(steps)} action(s) planned on authorized hosts; a validated plan for the real browser "
                       f"tools to run under the usual controls (this surface drives nothing itself)")


def plan_payload(actions: list[Action], *, allowed_hosts: set[str], enabled: bool,
                 max_actions: int = MAX_ACTIONS) -> dict[str, Any]:
    p = plan(actions, allowed_hosts=allowed_hosts, enabled=enabled, max_actions=max_actions)
    return {"module_version": MODULE_VERSION, **p.to_dict(),
            "note": "Bounded browser-session state machine: fixed action set (ZR-036), navigation confined to the "
                    "authorized host allowlist, state-sane transitions, FAIL-CLOSED. It plans; the real browser "
                    "tools execute under controls."}
