"""Deterministic randomized population for the hardened benchmark.

Given a seed, produces a diverse, adversarial population of target configurations:
real flaws (single and in combination), FP-bait decoys (lying debug hints, UI-only
badges, within-SLA refund lags), opacity/UNK cases, and out-of-model blind spots
(coupon). Truth is NOT recorded here -- ground_truth.probe_truth derives it from the
target's behavior. Disjoint seed ranges give a tuning split and a held-out test split.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

# flags that create a real, externally-provable bypass, grouped by the class they trip
P0_FLAGS: dict[str, list[dict[str, Any]]] = {
    "U": [{"return_trusts_status_claim": True}],
    "F": [{"plan_claim_trusted_at_return": True}, {"checkout_trusts_client_amount": True}, {"plan_not_enforced": True}],
    "H": [{"currency_confusion": True}],
    "C": [{"replay_grants_again": True}],
    "G": [{"tenant_claim_trusted": True}],
    "X": [{"payment_owner_unchecked": True}],
    "R": [{"refund_revokes": False}, {"revoke_delay_s": 2.0}],
}
# opacity / openness: the differential is not externally executable -> truth UNK
UNK_FLAGS: list[dict[str, Any]] = [
    {"feature_async": True},
    {"feature_open": True},
    {"sandbox_broken": True},
    {"global_entitlement_leak": True},
]
# benign noise that must NOT change truth -- pure FP-bait
NOISE_FLAGS: list[dict[str, Any]] = [
    {"emit_debug_hints": True},
    {"emit_debug_hints": True, "hint_claims_flaw": True},
    {"ui_optimistic_success": True},     # only a divergence when the server does NOT grant
    {"revoke_delay_s": 0.3},             # within a generous SLA => still SAFE
]


@dataclass(frozen=True)
class Instance:
    name: str
    flags: dict[str, Any]
    brief_overrides: dict[str, Any]
    category: str
    noise: tuple[str, ...] = field(default_factory=tuple)


def _merge(*parts: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for p in parts:
        out.update(p)
    return out


def _maybe_noise(rng: random.Random, flags: dict[str, Any], p: float = 0.5) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Fold in benign FP-bait that does not change truth. Skip ui_optimistic when the
    instance already grants server-side (there it would be a real path, not UI-only),
    and skip revoke-delay noise on refund-bearing instances (would perturb R timing)."""
    applied: list[str] = []
    for noise in NOISE_FLAGS:
        if rng.random() > p:
            continue
        if "ui_optimistic_success" in noise and any(flags.get(k) for k in ("return_trusts_status_claim",)):
            continue
        if "revoke_delay_s" in noise and ("refund_revokes" in flags or "revoke_delay_s" in flags):
            continue
        flags = _merge(flags, noise)
        applied.append(",".join(noise))
    return flags, tuple(applied)


def sample(n: int, seed: int) -> list[Instance]:
    rng = random.Random(seed)
    out: list[Instance] = []
    i = 0

    def add(flags: dict[str, Any], category: str, sla: float = 1.0, noise_p: float = 0.5) -> None:
        nonlocal i
        flags2, noise = _maybe_noise(rng, dict(flags), noise_p)
        overrides = {"limits": {"revocation_sla_seconds": sla}}
        out.append(Instance(f"gen_{i:03d}", flags2, overrides, category, noise))
        i += 1

    # target composition (fractions of n)
    want_clean = max(4, n // 6)
    want_single = max(8, n // 3)
    want_combo = max(4, n // 6)
    want_unk = max(3, n // 8)
    want_blind = max(2, n // 10)

    for _ in range(want_clean):
        add({}, "clean", noise_p=0.7)

    classes = list(P0_FLAGS)
    for _ in range(want_single):
        cls = rng.choice(classes)
        flag = dict(rng.choice(P0_FLAGS[cls]))
        sla = 0.5 if cls == "R" else 1.0
        add(flag, f"single:{cls}", sla=sla)

    for _ in range(want_combo):
        k = rng.randint(2, 4)
        chosen = rng.sample(classes, k)
        flags: dict[str, Any] = {}
        for cls in chosen:
            flags.update(rng.choice(P0_FLAGS[cls]))
        sla = 0.5 if "R" in chosen else 1.0
        add(flags, "combo:" + "+".join(sorted(chosen)), sla=sla, noise_p=0.4)

    for _ in range(want_unk):
        add(dict(rng.choice(UNK_FLAGS)), "unk", noise_p=0.3)

    for _ in range(want_blind):
        # coupon blind spot, sometimes with a real in-model flaw alongside it
        flags = {"coupon_grants_top_tier": True}
        if rng.random() < 0.5:
            cls = rng.choice(classes)
            flags.update(rng.choice(P0_FLAGS[cls]))
        add(flags, "blind:coupon", noise_p=0.3)

    rng.shuffle(out)
    # re-number after shuffle so names are stable in presentation order
    return [Instance(f"gen_{j:03d}", inst.flags, inst.brief_overrides, inst.category, inst.noise)
            for j, inst in enumerate(out)]


# disjoint splits: tuning is where any future improvement may look; test is report-only
def tuning(n: int = 60) -> list[Instance]:
    return sample(n, seed=20260001)


def held_out(n: int = 60) -> list[Instance]:
    return sample(n, seed=78889001)
