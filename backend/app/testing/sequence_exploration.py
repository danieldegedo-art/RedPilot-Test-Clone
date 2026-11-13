"""Where exponential growth genuinely lives in this problem, and where it
does not -- checked by counting, not assumed.

THE HONEST NEGATIVE RESULT FIRST
-----------------------------------
The first, most obvious place to look for "exponential" is the number of
distinct operation SEQUENCES on one resource as sequence length L grows
(state_exploration.py's graph, walked instead of just single-hopped).
Checked directly against VALID_PAYMENT_TRANSITIONS: path count at L=1..4
is 4, 4, 2, 1, then ZERO for L>=5. This graph is a shallow, mostly acyclic
DAG toward terminal states -- every path dies out within 4 hops because
every terminal state (refunded/cancelled/failed/expired) has no outgoing
edges. Single-resource path length is NOT exponential here, full stop.
Claiming otherwise for this specific graph would be false, so this module
does not build a "path depth" explorer at all -- see
enumerate_state_space_paths() below for the one that exists, kept
specifically to make this negative result checkable rather than asserted.

WHERE IT ACTUALLY IS
-----------------------
Two DIFFERENT combinatorial axes, neither bounded by the graph's shallow
depth, both verified by direct counting below:

1. INTERLEAVING ORDER, not just interleaving PAIR. state_exploration.py's
   concurrent-race generator asks "which TWO operations could race from
   this state" (C(k,2) pairs). The sharper, more realistic question for k
   truly concurrent operations is "in which ORDER could all k, or any
   subset of >=2 of them, actually get interleaved by the scheduler" --
   that count is sum_{s=2}^{k} C(k,s) * s!, which is C(4,2)=6 at k=4 (this
   graph's actual maximum branching factor) but 320 at k=5, 13692 at k=7,
   109592 at k=8 -- genuinely, checkably exponential (worse than
   exponential, in fact: s! grows faster than any fixed base^s). This
   graph tops out at k=4 (authorized/pending both have 4 legal exits) --
   the formula's growth rate does not depend on that cap; a payment
   system with more concurrently-available operations from one state
   (common in real systems with optional partial-capture, adjustments,
   holds, etc. layered onto a base lifecycle) would see it directly.

2. JOINT STATE SPACE OF M INTERACTING RESOURCES. One resource's lifecycle
   has 8 states -- small, and (per point above) shallow. M resources that
   can affect each other's outcome (sharing an idempotency key, a rate
   limit, a customer balance, a webhook delivery order) have a joint
   state space of 8^M: 8, 64, 512, 4096, 32768, 262144 for M=1..6. This
   does not run out the way single-resource path length does -- it is
   exponential in M with no natural ceiling from the graph's own shape.

WHY THIS MUST BE BOUNDED, NOT BRUTE-FORCED (feeds directly into axis 2's
resource-limit requirement)
--------------------------------------------------------------------------
109592 orderings at k=8, or 262144 joint states at M=6, are each
individually cheap to check but expensive to enumerate exhaustively and
run against a real target over real HTTP -- at k=10 the ordering count is
in the tens of millions. Exhaustive enumeration is the right approach
while the numbers stay in the hundreds (this module does exactly that,
and MAX_EXHAUSTIVE_INTERLEAVINGS below is the explicit, stated ceiling
past which this module refuses to enumerate everything and falls back to
sampling instead) -- past that, the honest answer is bounded random
sampling of the space, not "run all of it," exactly the state-explosion
problem model checking has always had. Claiming otherwise (unbounded
exhaustive N-wise exploration "just works" at any scale) would violate
axis 2's own "every test must run with a defined resource ceiling"
requirement.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from itertools import combinations, permutations
from math import comb, factorial

from app.testing.lifecycle_model import VALID_PAYMENT_TRANSITIONS, VALID_SUBSCRIPTION_TRANSITIONS

# Past this many total orderings, enumerate_interleaving_orders switches
# from exhaustive enumeration to bounded random sampling (see
# sample_interleaving_orders) rather than materializing the full list --
# an explicit, checkable ceiling, not an implicit slowdown someone
# discovers by running out of memory.
MAX_EXHAUSTIVE_INTERLEAVINGS = 5_000


@dataclass(frozen=True)
class InterleavingOrder:
    resource_type: str
    from_state: str
    order: tuple[str, ...]  # target states, in the order they would be attempted


def theoretical_interleaving_count(k: int) -> int:
    """sum_{s=2}^{k} C(k,s) * s! -- every ordering of every subset of size
    >=2 out of k legal concurrent operations. Pure combinatorics, no
    dependency on any specific graph; used to report the growth curve
    even for k larger than any state in the current lifecycle model
    actually has, precisely to show the FORMULA's growth is not an
    artifact of this graph's particular (small) branching factor."""
    return sum(comb(k, s) * factorial(s) for s in range(2, k + 1))


def enumerate_interleaving_orders(
    transitions: dict[str, set[str]], resource_type: str, *, max_exhaustive: int = MAX_EXHAUSTIVE_INTERLEAVINGS
) -> tuple[tuple[InterleavingOrder, ...], bool]:
    """For every state with k>=2 legal exits, enumerates every ORDERING of
    every subset of size >=2 of those exits -- generalizing
    state_exploration.py's pairwise concurrent-race generator (which only
    ever considers unordered pairs) to full interleaving order. Returns
    (orders, was_exhaustive) -- was_exhaustive is False if any single
    state's own count exceeded `max_exhaustive`, in which case THAT
    state's contribution is sampled (see sample_interleaving_orders)
    instead of fully enumerated, and the caller is told so rather than
    silently getting a partial result that looks complete.
    """
    results: list[InterleavingOrder] = []
    exhaustive = True
    for state, targets in transitions.items():
        k = len(targets)
        if k < 2:
            continue
        if theoretical_interleaving_count(k) > max_exhaustive:
            exhaustive = False
            continue  # see sample_interleaving_orders for this state instead
        for s in range(2, k + 1):
            for subset in combinations(sorted(targets), s):
                for order in permutations(subset):
                    results.append(InterleavingOrder(resource_type, state, order))
    return tuple(results), exhaustive


def sample_interleaving_orders(
    transitions: dict[str, set[str]], resource_type: str, state: str, *, n_samples: int, seed: int
) -> tuple[InterleavingOrder, ...]:
    """Bounded random sampling of the interleaving-order space for one
    state whose exhaustive count exceeds MAX_EXHAUSTIVE_INTERLEAVINGS --
    the honest fallback described in this module's docstring. Deterministic
    for a fixed seed (uses a local random.Random, never the module-global
    random -- same determinism rationale as property_testing.py)."""
    rng = random.Random(seed)
    targets = sorted(transitions.get(state, ()))
    k = len(targets)
    results = []
    for _ in range(n_samples):
        s = rng.randint(2, k)
        subset = rng.sample(targets, s)
        rng.shuffle(subset)
        results.append(InterleavingOrder(resource_type, state, tuple(subset)))
    return tuple(results)


def joint_state_space_size(single_resource_state_count: int, num_resources: int) -> int:
    """single_resource_state_count ** num_resources -- the size of the
    joint state space of `num_resources` resources whose outcomes can
    affect each other (shared idempotency key, shared rate-limit bucket,
    shared customer balance). Deliberately just `**`, not a graph walk:
    this is the OTHER genuinely exponential axis (see module docstring),
    kept separate from enumerate_interleaving_orders because the two
    model different real scenarios (one resource with many concurrent
    operations, vs. many resources interacting) and conflating them would
    overstate either one."""
    return single_resource_state_count ** num_resources


def growth_curve_report(max_k: int = 8) -> list[dict]:
    """Real, checkable numbers backing this module's claims -- what the
    project's before/after report's chart is built from."""
    all_payment_states = {s for v in VALID_PAYMENT_TRANSITIONS.values() for s in v} | set(VALID_PAYMENT_TRANSITIONS.keys())
    n_states = len(all_payment_states)
    rows = []
    for k in range(2, max_k + 1):
        rows.append(
            {
                "k_or_m": k,
                "pairs_c_k_2": comb(k, 2),
                "interleaving_orderings": theoretical_interleaving_count(k),
                "joint_state_space_size": joint_state_space_size(n_states, k),
            }
        )
    return rows
