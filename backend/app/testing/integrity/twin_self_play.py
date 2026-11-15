"""B31 (owns A26): Twin-Self-Play Trainer -- BOUNDED, FAIL-CLOSED, twin-only.

"Self-play" here is a cheap, fully-synthetic way to learn a PRIOR over which
pre-registered probes to try first -- nothing more. The hard bounds that make this
safe rather than a capability generator:

  * The output is ONLY a prior: a normalised weighting over the fixed ten
    pre-registered oracle classes (`findings.EXPERIMENT_CLASSES`). It never emits a
    new action, probe, payload, or capability. Learning cannot expand the action set
    (ZR-036) -- it can only reweight the existing one.
  * TWIN-ONLY. Training runs against the synthetic twin's local, synthetic flaw
    configurations (B29), NEVER a live target. There is no target/host parameter
    anywhere in this module (live-target self-play, B27, is rejected by the owner).
  * FAIL-CLOSED. Without its enabling control, `train(enabled=False)` performs no
    training and returns the uniform prior.
  * Deterministic (seeded), episode-capped, and Laplace-smoothed so every class keeps
    a non-zero weight -- the learned prior reprioritises, it never drops a probe
    (the H4 never-skip discipline carried into learning).

The prior feeds the planner (B39/ZR-010); it is advice about ordering, never proof
and never a verdict.

Stdlib only; pure.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "twin-self-play/1.0"
MAX_EPISODES = 10000
_CLASSES = tuple(sorted(EXPERIMENT_CLASSES))
_N = len(_CLASSES)


class TrainStatus(str, Enum):
    TRAINED = "TRAINED"
    FAIL_CLOSED = "FAIL_CLOSED"   # enabling control absent -> no training, uniform prior


@dataclass(frozen=True)
class TrainResult:
    status: TrainStatus
    prior: dict[str, float]      # normalised weight per pre-registered class (sums to 1)
    episodes_run: int
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "prior": {k: round(v, 6) for k, v in self.prior.items()},
                "episodes_run": self.episodes_run, "note": self.note}


def uniform_prior() -> dict[str, float]:
    return {c: 1.0 / _N for c in _CLASSES}


def train(*, enabled: bool = True, episodes: int = 200, seed: int = 0,
          flaw_distribution: list[str] | None = None) -> TrainResult:
    """Learn a prior over the fixed probe classes by synthetic self-play against the
    twin's flaw configurations. FAIL-CLOSED when `enabled` is False."""
    if not enabled:
        return TrainResult(TrainStatus.FAIL_CLOSED, uniform_prior(), 0,
                           "FAIL-CLOSED: self-play training is disabled because its enabling control is absent; "
                           "returning the uniform prior (no training performed)")
    if episodes < 1:
        raise ValueError("episodes must be >= 1")
    episodes = min(episodes, MAX_EPISODES)

    distribution = list(flaw_distribution) if flaw_distribution is not None else list(_CLASSES)
    if not distribution:
        raise ValueError("flaw_distribution must be non-empty")
    off_catalog = [c for c in distribution if c not in EXPERIMENT_CLASSES]
    if off_catalog:
        raise ValueError(f"flaw classes {sorted(set(off_catalog))} are not pre-registered oracle classes "
                         f"(self-play never trains toward an off-catalog target)")

    rng = random.Random(seed)
    credits = {c: 0 for c in _CLASSES}
    for _ in range(episodes):
        # draw a synthetic twin flaw config; the probe that detects flaw-class X is the X oracle.
        flaw = rng.choice(distribution)
        credits[flaw] += 1

    # Laplace smoothing: every class keeps a non-zero weight (a learned prior never drops a probe).
    denom = episodes + _N
    prior = {c: (credits[c] + 1) / denom for c in _CLASSES}
    return TrainResult(TrainStatus.TRAINED, prior, episodes,
                       f"prior over {_N} pre-registered classes from {episodes} synthetic twin episode(s) "
                       f"(seed={seed}); Laplace-smoothed so no probe is dropped; feeds the planner as ordering advice")


def train_payload(*, enabled: bool, episodes: int = 200, seed: int = 0,
                  flaw_distribution: list[str] | None = None) -> dict[str, Any]:
    res = train(enabled=enabled, episodes=episodes, seed=seed, flaw_distribution=flaw_distribution)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "note": "Synthetic self-play against the local twin ONLY (never a live target -- B27 rejected). The "
                    "output is a reweighting of the fixed pre-registered probe set (ZR-036), FAIL-CLOSED, "
                    "deterministic, and never a new capability or a verdict."}
