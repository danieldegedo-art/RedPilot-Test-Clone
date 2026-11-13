"""B32 / A25: tests for app/testing/integrity/attack_chain.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.attack_chain import (  # noqa: E402
    BASELINE_STATE, LINKS, ComposeStatus, compose_chains, compose_payload, effect_of, precondition_of,
)
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402


def test_fail_closed_when_the_enabling_control_is_absent():
    res = compose_chains("PBB-G", enabled=False)
    assert res.status == ComposeStatus.FAIL_CLOSED and res.chains == ()   # capability OFF, not open


def test_composes_the_minimal_u_x_g_chain():
    res = compose_chains("PBB-G", enabled=True)
    assert res.status == ComposeStatus.COMPOSED
    assert ("PBB-U", "PBB-X", "PBB-G") in [c.steps for c in res.chains]


def test_every_chain_ends_at_goal_and_is_precondition_valid():
    res = compose_chains("PBB-G", enabled=True)
    for chain in res.chains:
        assert chain.steps[-1] == "PBB-G"
        state = set(BASELINE_STATE)
        for step in chain.steps:
            assert LINKS[step].precondition <= state      # each step was actually enabled
            state |= LINKS[step].effect


def test_depth_cap_is_respected():
    res = compose_chains("PBB-G", enabled=True, max_depth=4)
    assert all(len(c.steps) <= 4 for c in res.chains)
    assert compose_chains("PBB-G", enabled=True, max_depth=2).status == ComposeStatus.NO_CHAIN  # minimal is length 3
    try:
        compose_chains("PBB-G", enabled=True, max_depth=99)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_only_registered_steps_and_unknown_goal_rejected():
    res = compose_chains("PBB-G", enabled=True)
    assert all(step in EXPERIMENT_CLASSES for c in res.chains for step in c.steps)
    try:
        compose_chains("PBB-NOT-REAL", enabled=True)
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_precondition_and_effect_catalog_serves_zr019():
    assert set(LINKS) == set(EXPERIMENT_CLASSES)                 # one link per pre-registered class
    assert precondition_of("PBB-U")["satisfied_by_baseline"] is True
    assert precondition_of("PBB-G")["satisfied_by_baseline"] is False
    assert effect_of("PBB-U")["state_atoms"] == ["access_without_payment"]
    assert json.loads(json.dumps(precondition_of("PBB-G"))) == precondition_of("PBB-G")


def test_baseline_reachable_goal_and_payload_json_safe():
    res = compose_chains("PBB-U", enabled=True)
    assert res.status == ComposeStatus.COMPOSED and ("PBB-U",) in [c.steps for c in res.chains]
    payload = compose_payload("PBB-G", enabled=True)
    assert json.loads(json.dumps(payload)) == payload
