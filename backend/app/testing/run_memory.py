"""ZR-007 (the part experiment prioritization needs) / ZR-038: what earlier runs
concluded about THIS target, read back out of what is already persisted.

NO NEW SCHEMA WAS NEEDED FOR THIS PART
--------------------------------------
Every finding PaymentIntegrityModule emits is already a TestResultRecord row
(category "payment_integrity") whose input_parameters carry the full finding
(`_integrity`: hypothesis_id, verdict, ...) and the engagement's
`brief_fingerprint` -- and since ZR-009 those rows are written as they are
produced, so they survive a restart and a crashed run still leaves its
findings behind. This module is the reader: the latest verdict per hypothesis
for one brief, as a mapping the scheduler (prioritization.py) consumes.

WHAT THIS IS NOT
----------------
ZR-007 as written also covers a durable store under the PESM, the evidence
graph and the coverage lattice. None of that is built here: PESM's persistent
store is still in-memory only (pesm.InMemoryPESMStore), and the evidence graph
(B9) and coverage lattice (B18) don't exist yet. This is the findings-verdict
slice of "a new run sees prior run's results", nothing more.

BOUNDARIES THAT ARE DELIBERATE
------------------------------
  * One brief only (ZR-038 / authorization scope). A row from a different
    engagement brief -- or one carrying no fingerprint at all -- is never used,
    however recent. The SQL filter in app/db/memory.py is the first line of
    defence and this reducer re-checks anyway, so a wrong or missing WHERE
    clause cannot leak another target's verdicts into this run.
  * No individual-level data (ZR-038: "never as profiles of individuals").
    PriorFinding holds a hypothesis id, a verdict, a run id, a timestamp and
    the brief fingerprint -- no identity or tenant aliases, no payloads, no
    evidence. A test pins the exact field set, so adding one is a decision
    someone has to make on purpose.
  * Advisory only. Priors reorder the run (see prioritization.py); they never
    skip a test and never decide a verdict. A failure to read them is logged and
    reported as `degraded`, and the run proceeds without them -- never silently.
  * Evidence ages out. With max_age set, anything older is ignored (and counted),
    since the target may have been redeployed since; undated rows can't be shown
    to be fresh, so they are ignored too when an age limit applies.

Stdlib only.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping, Sequence

from app.testing.enums import TestCategory
from app.testing.prioritization import Prioritizer
from app.testing.purity.taxonomy import Verdict

logger = logging.getLogger("qa.run_memory")

DEFAULT_MAX_PRIOR_AGE = timedelta(days=30)  # a tunable default, not a derived fact
_CATEGORY = TestCategory.PAYMENT_INTEGRITY.value
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class PriorFinding:
    hypothesis_id: str
    verdict: Verdict
    run_id: str
    observed_at: datetime | None
    brief_fingerprint: str
    # Deliberately nothing else. See "BOUNDARIES THAT ARE DELIBERATE" above.


@dataclass(frozen=True)
class PriorFindings:
    by_hypothesis: Mapping[str, PriorFinding] = field(default_factory=dict)
    rows_read: int = 0  # finding rows (category payment_integrity, carrying `_integrity`) examined
    skipped_unreadable: int = 0  # carried `_integrity` but it was malformed (no hypothesis id, unknown verdict, ...)
    skipped_other_brief: int = 0  # a different brief's finding, or one with no fingerprint (unscoped evidence is never trusted)
    skipped_stale: int = 0  # older than max_age, or undated while an age limit applies
    degraded: bool = False  # the rows could not be read at all
    degraded_reason: str | None = None

    def verdicts(self) -> dict[str, Verdict]:
        return {h: p.verdict for h, p in self.by_hypothesis.items()}


def _as_utc(value: Any) -> datetime | None:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def prior_findings_from_rows(
    rows: Sequence[Mapping[str, Any]], *, brief_fingerprint: str,
    now: datetime | None = None, max_age: timedelta | None = None,
) -> PriorFindings:
    """rows: mappings shaped like TestResultRecord (run_id, category, input_parameters, finished_at)."""
    now_utc = _as_utc(now) or datetime.now(timezone.utc)
    best: dict[str, PriorFinding] = {}
    read = unreadable = other_brief = stale = 0

    for row in rows:
        if row.get("category") != _CATEGORY:
            continue
        params = row.get("input_parameters")
        integrity = params.get("_integrity") if isinstance(params, Mapping) else None
        if integrity is None:
            continue  # not a finding row (e.g. the capability-gap summary row)
        read += 1

        hypothesis = integrity.get("hypothesis_id") if isinstance(integrity, Mapping) else None
        try:
            verdict = Verdict(integrity["verdict"])
        except (KeyError, TypeError, ValueError):
            verdict = None
        if not isinstance(hypothesis, str) or not hypothesis or verdict is None:
            unreadable += 1
            continue

        fingerprint = params.get("brief_fingerprint")
        if fingerprint != brief_fingerprint:
            other_brief += 1
            continue

        observed_at = _as_utc(row.get("finished_at"))
        if max_age is not None and (observed_at is None or now_utc - observed_at > max_age):
            stale += 1
            continue

        candidate = PriorFinding(hypothesis, verdict, str(row.get("run_id", "")), observed_at, fingerprint)
        current = best.get(hypothesis)
        if current is None or (candidate.observed_at or _EPOCH, candidate.run_id) > (current.observed_at or _EPOCH, current.run_id):
            best[hypothesis] = candidate

    return PriorFindings(best, read, unreadable, other_brief, stale)


RowSource = Callable[[], Awaitable[Sequence[Mapping[str, Any]]]]


async def load_prior_findings(
    row_source: RowSource, *, brief_fingerprint: str,
    now: datetime | None = None, max_age: timedelta | None = DEFAULT_MAX_PRIOR_AGE,
) -> PriorFindings:
    try:
        rows = await row_source()
    except Exception as exc:  # noqa: BLE001 - priors are advisory; see the module docstring
        logger.exception("could not read prior findings; this run proceeds without them")
        return PriorFindings(degraded=True, degraded_reason=f"{type(exc).__name__}")
    return prior_findings_from_rows(rows, brief_fingerprint=brief_fingerprint, now=now, max_age=max_age)


def prioritizer_from_priors(priors: PriorFindings, **signals: Any) -> Prioritizer:
    """The scheduler's prior-evidence signal, sourced from what earlier runs concluded."""
    return Prioritizer(prior_verdicts=priors.verdicts(), **signals)
