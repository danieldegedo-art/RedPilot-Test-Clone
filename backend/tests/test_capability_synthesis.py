"""B34: tests for app/testing/integrity/capability_synthesis.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.capability_synthesis import (  # noqa: E402
    SynthStatus, synthesize, synthesize_payload,
)
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402

ALL = set(EXPERIMENT_CLASSES)


def test_fail_closed_synthesizes_nothing():
    r = synthesize(enabled=False, prior={"PBB-U": 1.0})
    assert r.status == SynthStatus.FAIL_CLOSED and r.probe is None


def test_synthesized_template_is_always_a_registered_class_even_with_a_bogus_prior():
    r = synthesize(enabled=True, conclusive=set(), prior={"PBB-EVIL": 999.0})   # off-catalog prior
    assert r.status == SynthStatus.SYNTHESIZED
    assert r.probe.template_id in EXPERIMENT_CLASSES          # B28: never a novel/off-catalog target


def test_closed_loop_picks_the_highest_prior_inconclusive_class():
    r = synthesize(enabled=True, conclusive={"PBB-U"}, prior={"PBB-X": 1.0})
    assert r.status == SynthStatus.SYNTHESIZED and r.probe.template_id == "PBB-X" and r.probe.params == {}


def test_out_of_bounds_parameter_is_refused():
    r = synthesize(enabled=True, conclusive=ALL - {"PBB-F"}, declared_params={"plan": "ultra"})
    assert r.status == SynthStatus.REFUSED_PARAM and r.probe is None


def test_missing_required_parameter_is_refused():
    r = synthesize(enabled=True, conclusive=ALL - {"PBB-F"}, declared_params={})
    assert r.status == SynthStatus.REFUSED_PARAM


def test_in_bounds_parameter_is_synthesized():
    r = synthesize(enabled=True, conclusive=ALL - {"PBB-F"}, declared_params={"plan": "pro"})
    assert r.status == SynthStatus.SYNTHESIZED
    assert r.probe.template_id == "PBB-F" and r.probe.params == {"plan": "pro"}


def test_nothing_to_do_when_all_conclusive_and_payload_json_safe():
    assert synthesize(enabled=True, conclusive=ALL).status == SynthStatus.NOTHING_TO_DO
    payload = synthesize_payload(enabled=True, conclusive={"PBB-U"}, prior={"PBB-G": 1.0})
    assert json.loads(json.dumps(payload)) == payload
