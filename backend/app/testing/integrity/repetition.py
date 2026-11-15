"""ZR-011: dedicated repetition-avoidance / adaptive ordering.

The risk scheduler (prioritization.py) already demotes a hypothesis whose LATEST
prior was RULED_OUT (a flat -30). ZR-011 is the dimension that single term cannot
express: HISTORY across runs. A class that has come back RULED_OUT run after run
has diminishing returns on re-testing and should drift down the order so budget
flows to unresolved work; a class that keeps FLAPPING, or whose last result is an
open lead, should hold its place or rise. This is how a new run "demonstrably
changes behaviour" from the prior run (the ZR-007/ZR-011 acceptance criterion).

TWO HARD LIMITS (from run_memory.py's H4 note and ZR-038):
  * NEVER skips a test. This emits an ORDERING adjustment only, and the repeat
    demotion is CAPPED, so even a long clean streak keeps the hypothesis in the
    run -- the spec records a known false-clearance gap in the RULED_OUT branch,
    so a "stably clean" class must still be re-tested, just later.
  * CLASS-LEVEL only (ZR-038). A profile is built from a sequence of VERDICTS per
    hypothesis id -- no identities, tenants, payloads or evidence.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.testing.purity.taxonomy import Verdict

STABLE_CLEAN_RUNS = 2       # >= this many trailing RULED_OUT = "stably clean", start the progressive demotion
PER_REPEAT_DEMOTION = -5.0  # extra demotion per consecutive clean run beyond the first
REPEAT_CAP = 4              # cap the progressive demotion (min total -20) -- never enough to skip, only to reorder
FLAP_WINDOW = 3             # how many trailing runs define "flapping"
OPEN_BOOST = 15.0           # last result is an open lead -> keep it near the front
FLAP_BOOST = 10.0           # result keeps changing -> unstable, worth attention

_OPEN = (Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE, Verdict.UNKNOWN)


@dataclass(frozen=True)
class RepetitionProfile:
    hypothesis_id: str
    runs_seen: int
    consecutive_ruled_out: int
    last_verdict: Verdict | None
    flapping: bool
    stably_clean: bool
    open_lead: bool

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "runs_seen": self.runs_seen, "consecutive_ruled_out": self.consecutive_ruled_out,
                "last_verdict": self.last_verdict.value if self.last_verdict else None, "flapping": self.flapping,
                "stably_clean": self.stably_clean, "open_lead": self.open_lead}


def profile_from(hypothesis_id: str, verdicts: Sequence[Verdict]) -> RepetitionProfile:
    """verdicts: chronological (oldest -> newest) for one hypothesis."""
    runs = len(verdicts)
    consecutive = 0
    for v in reversed(verdicts):
        if v == Verdict.RULED_OUT:
            consecutive += 1
        else:
            break
    last = verdicts[-1] if verdicts else None
    window = verdicts[-FLAP_WINDOW:]
    flapping = len(set(window)) > 1
    return RepetitionProfile(hypothesis_id, runs, consecutive, last, flapping,
                             stably_clean=consecutive >= STABLE_CLEAN_RUNS, open_lead=last in _OPEN if last is not None else False)


def repetition_adjustment(profile: RepetitionProfile) -> tuple[float, str]:
    """ORDERING adjustment (never a skip) + a human-readable reason."""
    adj = 0.0
    reasons: list[str] = []
    if profile.stably_clean:
        demote = PER_REPEAT_DEMOTION * min(profile.consecutive_ruled_out - 1, REPEAT_CAP)
        adj += demote
        reasons.append(f"RULED_OUT {profile.consecutive_ruled_out} runs in a row -> demote {demote} (capped; still re-tested, just later)")
    if profile.open_lead:
        adj += OPEN_BOOST
        reasons.append(f"last result is an open lead ({profile.last_verdict.value}) -> +{OPEN_BOOST}")
    if profile.flapping and not profile.stably_clean:
        adj += FLAP_BOOST
        reasons.append(f"result flapping over the last {FLAP_WINDOW} runs -> +{FLAP_BOOST}")
    return adj, ("; ".join(reasons) or "no repetition signal (insufficient history or first run)")


@dataclass
class RepetitionRegister:
    profiles: dict[str, RepetitionProfile]

    @classmethod
    def from_history(cls, history: Mapping[str, Sequence[Verdict]]) -> "RepetitionRegister":
        return cls({h: profile_from(h, list(vs)) for h, vs in history.items()})

    def adjustments(self) -> dict[str, float]:
        return {h: repetition_adjustment(p)[0] for h, p in self.profiles.items()}

    def deprioritized(self) -> list[dict[str, Any]]:
        """Stably-clean classes being pushed later this run -- surfaced with the
        reason, never silently skipped."""
        out = []
        for h, p in sorted(self.profiles.items()):
            adj, reason = repetition_adjustment(p)
            if adj < 0:
                out.append({"hypothesis_id": h, "adjustment": adj, "reason": reason})
        return out

    def report(self) -> dict[str, Any]:
        rows = []
        for h in sorted(self.profiles):
            adj, reason = repetition_adjustment(self.profiles[h])
            rows.append({**self.profiles[h].to_dict(), "adjustment": round(adj, 4), "reason": reason})
        return {"profiles": rows, "deprioritized": self.deprioritized(),
                "note": "Adaptive ordering only (ZR-011): a stably-clean class drifts later but is NEVER skipped (H4 false-clearance gap); demotion is capped."}
