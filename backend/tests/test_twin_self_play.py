"""B31: tests for app/testing/integrity/twin_self_play.py. Stdlib only."""
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.twin_self_play import TrainStatus, train, train_payload  # noqa: E402
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402


def test_fail_closed_returns_uniform_prior_and_no_training():
    r = train(enabled=False)
    assert r.status == TrainStatus.FAIL_CLOSED and r.episodes_run == 0
    assert all(abs(v - 1.0 / len(EXPERIMENT_CLASSES)) < 1e-9 for v in r.prior.values())


def test_prior_keys_are_exactly_the_fixed_classes():
    r = train(enabled=True, episodes=50)
    assert set(r.prior) == set(EXPERIMENT_CLASSES)


def test_every_class_keeps_a_nonzero_weight_even_if_never_drawn():
    r = train(enabled=True, episodes=200, flaw_distribution=["PBB-U"])
    assert all(v > 0 for v in r.prior.values())          # Laplace: no probe dropped
    assert r.prior["PBB-U"] == max(r.prior.values())


def test_learns_a_skewed_prior():
    r = train(enabled=True, episodes=300, seed=7, flaw_distribution=["PBB-U", "PBB-U", "PBB-F"])
    assert r.prior["PBB-U"] > r.prior["PBB-F"] > r.prior["PBB-E"]   # PBB-E never drawn


def test_deterministic_given_seed():
    a = train(enabled=True, episodes=300, seed=7, flaw_distribution=["PBB-U", "PBB-F", "PBB-G"])
    b = train(enabled=True, episodes=300, seed=7, flaw_distribution=["PBB-U", "PBB-F", "PBB-G"])
    assert a.prior == b.prior


def test_off_catalog_flaw_and_bad_episodes_rejected():
    try:
        train(enabled=True, flaw_distribution=["NOT-A-CLASS"])
        assert False, "expected ValueError"
    except ValueError:
        pass
    try:
        train(enabled=True, episodes=0)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_twin_only_no_target_param_prior_sums_to_one_and_json_safe():
    params = inspect.signature(train).parameters
    assert "target" not in params and "host" not in params and "url" not in params   # twin-only, never a live target
    r = train(enabled=True, episodes=100, seed=1)
    assert abs(sum(r.prior.values()) - 1.0) < 1e-9
    payload = train_payload(enabled=True, episodes=100, seed=1)
    assert json.loads(json.dumps(payload)) == payload
