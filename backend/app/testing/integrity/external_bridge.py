"""B38: External Tool Bridge -- BOUNDED, FAIL-CLOSED, with an absolute denylist.

A validating adapter boundary for the few external analysis tools the owner kept in
scope (turn 1): Ghidra (static RE), semgrep (static code scan), Playwright (browser
automation of the authorized target). It describes HOW RedPilot would invoke such a
tool and validates a request against a fixed allowlist -- it does NOT bundle or run
the tools (none are installed here; egress is blocked). An allowed request yields a
validated invocation spec that a separately-gated executor would run; anything else
is refused.

The safety model:
  * ABSOLUTE DENYLIST (owner decision, turn 1): Sliver (C2), BloodHound (AD
    attack-path), and other offensive frameworks are refused with DENIED_SCOPE
    UNCONDITIONALLY -- the denylist is checked before the enable gate, so these can
    never be bridged, control present or not.
  * FAIL-CLOSED: for an in-scope tool, the bridge still refuses (FAIL_CLOSED) unless
    its enabling control is present.
  * BOUNDED operations: each allowed tool exposes only a fixed set of operations
    (ZR-036); an unknown tool or an unpermitted operation is refused.
  * The bridge runs nothing: it returns a validated spec or a refusal. No arbitrary
    command execution is expressible through it.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "external-bridge/1.0"


class BridgeStatus(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED_SCOPE = "DENIED_SCOPE"          # denylisted tool -> absolute, unconditional refusal
    DENIED_UNKNOWN = "DENIED_UNKNOWN"      # tool not on the allowlist
    DENIED_OPERATION = "DENIED_OPERATION"  # operation not permitted for that tool
    FAIL_CLOSED = "FAIL_CLOSED"            # in-scope tool, but its enabling control is absent


@dataclass(frozen=True)
class ToolLeg:
    name: str
    operations: frozenset[str]
    purpose: str


# In scope (owner, turn 1): static RE + static scan + authorized-target browser automation.
ALLOWED_LEGS: dict[str, ToolLeg] = {
    "ghidra": ToolLeg("ghidra", frozenset({"decompile", "disassemble", "list_symbols"}),
                      "static reverse-engineering of an authorized artifact"),
    "semgrep": ToolLeg("semgrep", frozenset({"scan"}), "static code scan with a provided ruleset"),
    "playwright": ToolLeg("playwright", frozenset({"navigate", "fill", "submit", "read"}),
                          "browser automation of the authorized target's payment flow"),
}

# Absolute denylist (owner, turn 1): offensive frameworks / C2 / AD attack-path.
# Refused unconditionally -- never bridged, control present or not.
DENYLISTED: frozenset[str] = frozenset({"sliver", "bloodhound", "cobalt_strike", "metasploit", "havoc", "brute_force_ai"})


@dataclass(frozen=True)
class BridgeDecision:
    status: BridgeStatus
    tool: str
    operation: str
    invocation: dict[str, Any] | None   # a validated spec ONLY when ALLOWED
    reason: str

    @property
    def allowed(self) -> bool:
        return self.status is BridgeStatus.ALLOWED

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "tool": self.tool, "operation": self.operation,
                "invocation": self.invocation, "reason": self.reason}


def bridge(tool: str, operation: str, *, enabled: bool, target: str | None = None) -> BridgeDecision:
    """Validate a request against the allowlist. The denylist is checked FIRST, so a
    denylisted tool is refused for scope reasons regardless of `enabled`."""
    t = (tool or "").strip().lower()

    if t in DENYLISTED:
        return BridgeDecision(BridgeStatus.DENIED_SCOPE, t, operation, None,
                              "DENIED (scope): offensive framework / C2 / AD attack-path tool is out of scope by the "
                              "owner's turn-1 decision; refused unconditionally (the enable gate is never even reached)")
    if t not in ALLOWED_LEGS:
        return BridgeDecision(BridgeStatus.DENIED_UNKNOWN, t, operation, None,
                              "DENIED: tool is not on the fixed allowlist (ghidra | semgrep | playwright)")
    if not enabled:
        return BridgeDecision(BridgeStatus.FAIL_CLOSED, t, operation, None,
                              "FAIL-CLOSED: the external-tool bridge is disabled because its enabling control is absent")
    leg = ALLOWED_LEGS[t]
    if operation not in leg.operations:
        return BridgeDecision(BridgeStatus.DENIED_OPERATION, t, operation, None,
                              f"DENIED: operation {operation!r} is not permitted for {t} "
                              f"(allowed: {sorted(leg.operations)})")
    return BridgeDecision(BridgeStatus.ALLOWED, t, operation,
                          {"tool": t, "operation": operation, "target": target, "purpose": leg.purpose},
                          "validated invocation spec; the bridge runs nothing -- a separately-gated executor would run it")


def bridge_payload(tool: str, operation: str, *, enabled: bool, target: str | None = None) -> dict[str, Any]:
    d = bridge(tool, operation, enabled=enabled, target=target)
    return {"module_version": MODULE_VERSION, **d.to_dict(),
            "allowlist": sorted(ALLOWED_LEGS), "denylist": sorted(DENYLISTED),
            "note": "Bounded adapter boundary: fixed allowlist + per-tool operations (ZR-036), FAIL-CLOSED, and an "
                    "absolute denylist (Sliver/BloodHound/etc.) refused unconditionally. The bridge validates and "
                    "returns a spec; it never executes a tool."}
