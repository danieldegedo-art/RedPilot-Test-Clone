"""B38: tests for app/testing/integrity/external_bridge.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.external_bridge import (  # noqa: E402
    ALLOWED_LEGS, DENYLISTED, BridgeStatus, bridge, bridge_payload,
)


def test_denylisted_tools_refused_unconditionally_even_when_enabled():
    for t in ("sliver", "bloodhound", "Cobalt_Strike", "METASPLOIT"):
        d = bridge(t, "anything", enabled=True)
        assert d.status == BridgeStatus.DENIED_SCOPE and d.invocation is None, t


def test_denylist_takes_precedence_over_the_enable_gate():
    # a denylisted tool is DENIED_SCOPE (not FAIL_CLOSED) even with the control absent
    assert bridge("sliver", "x", enabled=False).status == BridgeStatus.DENIED_SCOPE


def test_fail_closed_for_an_in_scope_tool_when_control_absent():
    d = bridge("ghidra", "decompile", enabled=False)
    assert d.status == BridgeStatus.FAIL_CLOSED and d.invocation is None


def test_allowed_tool_and_operation_yields_a_validated_spec():
    d = bridge("ghidra", "decompile", enabled=True, target="artifact-123")
    assert d.allowed and d.status == BridgeStatus.ALLOWED
    assert d.invocation == {"tool": "ghidra", "operation": "decompile", "target": "artifact-123",
                            "purpose": ALLOWED_LEGS["ghidra"].purpose}


def test_unpermitted_operation_is_denied():
    assert bridge("semgrep", "decompile", enabled=True).status == BridgeStatus.DENIED_OPERATION
    assert bridge("semgrep", "scan", enabled=True).allowed


def test_unknown_tool_is_denied():
    assert bridge("nmap", "scan", enabled=True).status == BridgeStatus.DENIED_UNKNOWN


def test_payload_lists_allow_and_deny_and_is_json_safe():
    payload = bridge_payload("playwright", "navigate", enabled=True, target="https://authorized.example")
    assert set(payload["allowlist"]) == {"ghidra", "semgrep", "playwright"}
    assert "sliver" in payload["denylist"] and "bloodhound" in payload["denylist"]
    assert payload["status"] == "ALLOWED"
    assert json.loads(json.dumps(payload)) == payload
