"""B33: tests for app/testing/integrity/fleet_orchestration.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.fleet_orchestration import (  # noqa: E402
    MAX_WORKERS_CAP, OrchestrationStatus, dependencies_from_catalog, orchestrate, orchestrate_payload,
)


def test_fail_closed_when_the_enabling_control_is_absent():
    plan = orchestrate(["PBB-U", "PBB-F"], enabled=False, max_workers=4)
    assert plan.status == OrchestrationStatus.FAIL_CLOSED and plan.waves == ()


def test_independent_hypotheses_share_a_wave_up_to_the_cap():
    hs = ["PBB-U", "PBB-F", "PBB-H", "PBB-E"]
    assert orchestrate(hs, enabled=True, max_workers=4).waves == (("PBB-E", "PBB-F", "PBB-H", "PBB-U"),)
    two = orchestrate(hs, enabled=True, max_workers=2).waves
    assert two == (("PBB-E", "PBB-F"), ("PBB-H", "PBB-U"))


def test_respects_dependency_ordering():
    hs = ["PBB-U", "PBB-X", "PBB-G"]
    deps = dependencies_from_catalog(hs)
    plan = orchestrate(hs, enabled=True, max_workers=8, dependencies=deps)
    assert plan.waves == (("PBB-U",), ("PBB-X",), ("PBB-G",))   # U before X before G


def test_worker_cap_caps_each_wave():
    hs = ["PBB-U", "PBB-F", "PBB-H", "PBB-E", "PBB-C"]
    waves = orchestrate(hs, enabled=True, max_workers=2).waves
    assert [len(w) for w in waves] == [2, 2, 1] and all(len(w) <= 2 for w in waves)


def test_dependency_cycle_is_detected():
    try:
        orchestrate(["PBB-U", "PBB-F"], enabled=True, max_workers=4,
                    dependencies={"PBB-U": {"PBB-F"}, "PBB-F": {"PBB-U"}})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_bad_inputs_rejected():
    for args, kw in [
        (["NOT-REAL"], dict(enabled=True, max_workers=4)),
        (["PBB-U"], dict(enabled=True, max_workers=0)),
        (["PBB-U"], dict(enabled=True, max_workers=MAX_WORKERS_CAP + 1)),
        (["PBB-U", "PBB-U"], dict(enabled=True, max_workers=4)),
    ]:
        try:
            orchestrate(args, **kw)
            assert False, f"expected ValueError for {args} {kw}"
        except ValueError:
            pass


def test_dependencies_from_catalog_and_payload_json_safe():
    deps = dependencies_from_catalog(["PBB-U", "PBB-X", "PBB-G"])
    assert deps["PBB-U"] == set() and deps["PBB-X"] == {"PBB-U"} and deps["PBB-G"] == {"PBB-X"}
    payload = orchestrate_payload(["PBB-U", "PBB-X", "PBB-G"], enabled=True, max_workers=4,
                                  dependencies=deps)
    assert json.loads(json.dumps(payload)) == payload
