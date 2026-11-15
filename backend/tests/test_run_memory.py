"""ZR-007 / ZR-038: app/testing/run_memory.py.

The important property here is the contract between WRITER and READER. Rows
are produced by the real PaymentIntegrityModule._finding_result, pushed through
the same normalize_result_for_persistence the real DB write uses
(api/v1/runs.py::_persist_result_db), and round-tripped through JSON like the
JSON column does -- so if the writer's key names, the redaction step, or the
serialization ever change in a way that breaks the reader, this fails, instead
of the reader quietly returning nothing in production.

Not covered, and said plainly: app/db/memory.py (the SQL) -- no sqlalchemy here.
"Survives a restart" is simulated by discarding every object and rebuilding
from the JSON-serialized rows; the database round trip itself needs your machine.

Needs only the pydantic/httpx shims.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import KIND_FEATURE_USE, ConfirmationCandidate, OracleObservation  # noqa: E402
from app.enterprise_controls.oracle_gate import ConfirmationGate  # noqa: E402
from app.testing.integrity.engine import EXPERIMENT_CLASSES, FLOW_BY_HYPOTHESIS, SPECS, TITLES  # noqa: E402
from app.testing.integrity.findings import Finding  # noqa: E402
from app.testing.modules.payment_integrity import PaymentIntegrityModule  # noqa: E402
from app.testing.prioritization import schedule  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402
from app.testing.redaction import normalize_result_for_persistence  # noqa: E402
from app.testing.run_memory import (  # noqa: E402
    DEFAULT_MAX_PRIOR_AGE, PriorFinding, PriorFindings, load_prior_findings, prior_findings_from_rows, prioritizer_from_priors,
)

FP = "fp-target-A"
NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
STATIC = ["PBB-U", "PBB-F", "PBB-H", "PBB-C", "PBB-G", "PBB-X", "PBB-R", "PBB-E"]


def _token_for(hypothesis_id: str):
    class _L:
        def is_admitted(self, _):
            return True
    cand = ConfirmationCandidate(
        hypothesis_id=hypothesis_id,
        control_denied=OracleObservation("o1", "f", "clean", None, "denied", KIND_FEATURE_USE, True, "s1", ("a",), discriminating=True),
        scenario_allowed=OracleObservation("o2", "f", "victim", None, "allowed", KIND_FEATURE_USE, True, "s2", ("a",)),
        clean_reproduction=OracleObservation("o3", "f", "victim", None, "allowed", KIND_FEATURE_USE, True, "s3", ("a",)),
        qualifying_payment_present=False,
    )
    d = ConfirmationGate(ledger=_L()).evaluate(cand)
    assert d.confirmed
    return d.token


def _finding(hyp: str, verdict: Verdict) -> Finding:
    return Finding(hypothesis_id=hyp, p0_class=EXPERIMENT_CLASSES[hyp], title=TITLES[hyp], verdict=verdict, confidence="medium" if verdict != Verdict.CONFIRMED_P0 else "high",
                   summary="x", spec=SPECS[hyp], token=_token_for(hyp) if verdict == Verdict.CONFIRMED_P0 else None)


def _row(finding: Finding, *, run_id: str, fingerprint: str = FP, finished_at=NOW) -> dict:
    """What the database would hand back for a finding written by the REAL writer."""
    module = PaymentIntegrityModule.__new__(PaymentIntegrityModule)  # _finding_result touches no instance state
    result = module._finding_result(finding, fingerprint)
    fields = normalize_result_for_persistence({
        "test_case_id": result.test_case_id, "name": result.name, "input_parameters": result.input_parameters, "actual": result.actual,
        "expected": result.expected, "recommendation": result.recommendation, "description": result.description,
        "request_json": None, "response_json": None,
    })
    category = result.category if isinstance(result.category, str) else result.category.value
    return {"run_id": run_id, "category": category,
            "input_parameters": json.loads(json.dumps(fields["input_parameters"], default=str)),  # the JSON column
            "finished_at": finished_at}


# ---- the writer/reader contract ------------------------------------------------------

def test_every_verdict_survives_the_real_writer_the_real_redaction_and_a_json_round_trip():
    pairs = [("PBB-U", Verdict.CONFIRMED_P0), ("PBB-F", Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE),
             ("PBB-H", Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE), ("PBB-C", Verdict.RULED_OUT),
             ("PBB-G", Verdict.UNKNOWN), ("PBB-X", Verdict.BLOCKED)]
    rows = [_row(_finding(h, v), run_id="run-1") for h, v in pairs]
    got = prior_findings_from_rows(rows, brief_fingerprint=FP)
    assert got.verdicts() == dict(pairs)
    assert (got.rows_read, got.skipped_unreadable, got.skipped_other_brief, got.skipped_stale) == (6, 0, 0, 0)


def test_the_latest_run_wins_per_hypothesis_whatever_order_rows_arrive_in():
    old = _row(_finding("PBB-U", Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE), run_id="run-1", finished_at=NOW - timedelta(days=5))
    new = _row(_finding("PBB-U", Verdict.RULED_OUT), run_id="run-2", finished_at=NOW - timedelta(days=1))
    for rows in ([old, new], [new, old]):
        got = prior_findings_from_rows(rows, brief_fingerprint=FP)
        assert got.by_hypothesis["PBB-U"].verdict == Verdict.RULED_OUT and got.by_hypothesis["PBB-U"].run_id == "run-2"


# ---- isolation between targets (ZR-038 / authorization scope) ---------------------------

def test_another_briefs_findings_never_leak_in_however_recent():
    mine = _row(_finding("PBB-U", Verdict.RULED_OUT), run_id="run-1", finished_at=NOW - timedelta(days=3))
    theirs = _row(_finding("PBB-U", Verdict.CONFIRMED_P0), run_id="run-9", fingerprint="fp-target-B", finished_at=NOW)
    unscoped = _row(_finding("PBB-F", Verdict.CONFIRMED_P0), run_id="run-8", finished_at=NOW)
    del unscoped["input_parameters"]["brief_fingerprint"]
    got = prior_findings_from_rows([mine, theirs, unscoped], brief_fingerprint=FP)
    assert got.verdicts() == {"PBB-U": Verdict.RULED_OUT}
    assert got.skipped_other_brief == 2, "a different brief's row and an unscoped row are both refused, and counted"


def test_priors_hold_no_individual_level_data():
    """ZR-038: persistent state is test fixtures/findings/coverage/scoring, 'never
    profiles of individuals'. Pins the exact field set so adding one (an identity
    alias, a payload) is something a person has to decide, not something that slips in."""
    assert {f.name for f in dataclasses.fields(PriorFinding)} == {"hypothesis_id", "verdict", "run_id", "observed_at", "brief_fingerprint"}
    assert {f.name for f in dataclasses.fields(PriorFindings)} == {
        "by_hypothesis", "rows_read", "skipped_unreadable", "skipped_other_brief", "skipped_stale", "degraded", "degraded_reason"}


# ---- tolerance for rows that aren't what we expect ------------------------------------------

def test_rows_that_are_not_findings_are_ignored_without_being_counted():
    gap_summary_row = {"run_id": "r", "category": "payment_integrity", "input_parameters": {"capability_gaps": []}, "finished_at": NOW}
    other_category = {"run_id": "r", "category": "functional", "input_parameters": {"_integrity": {"hypothesis_id": "PBB-U", "verdict": "CONFIRMED_P0"}, "brief_fingerprint": FP}, "finished_at": NOW}
    got = prior_findings_from_rows([gap_summary_row, other_category], brief_fingerprint=FP)
    assert got.verdicts() == {} and got.rows_read == 0


def test_malformed_finding_rows_are_counted_and_never_trusted():
    base = {"run_id": "r", "category": "payment_integrity", "finished_at": NOW}
    bad = [
        {**base, "input_parameters": {"_integrity": {"hypothesis_id": "PBB-U"}, "brief_fingerprint": FP}},  # no verdict
        {**base, "input_parameters": {"_integrity": {"hypothesis_id": "PBB-U", "verdict": "MAYBE"}, "brief_fingerprint": FP}},  # unknown verdict
        {**base, "input_parameters": {"_integrity": {"verdict": "RULED_OUT"}, "brief_fingerprint": FP}},  # no hypothesis
        {**base, "input_parameters": {"_integrity": "not a mapping", "brief_fingerprint": FP}},
        {**base, "input_parameters": {"_integrity": {"hypothesis_id": "", "verdict": "RULED_OUT"}, "brief_fingerprint": FP}},  # empty hypothesis
    ]
    got = prior_findings_from_rows(bad, brief_fingerprint=FP)
    assert got.verdicts() == {} and got.rows_read == 5 and got.skipped_unreadable == 5


def test_rows_with_non_mapping_parameters_do_not_crash_the_reader():
    rows = [{"run_id": "r", "category": "payment_integrity", "input_parameters": p, "finished_at": NOW} for p in (None, "text", 7, [])]
    assert prior_findings_from_rows(rows, brief_fingerprint=FP).rows_read == 0


# ---- evidence ages out ------------------------------------------------------------------------

def test_stale_and_undated_evidence_is_ignored_when_an_age_limit_applies():
    fresh = _row(_finding("PBB-U", Verdict.RULED_OUT), run_id="r1", finished_at=NOW - timedelta(days=10))
    stale = _row(_finding("PBB-F", Verdict.RULED_OUT), run_id="r2", finished_at=NOW - timedelta(days=40))
    undated = _row(_finding("PBB-H", Verdict.RULED_OUT), run_id="r3", finished_at=None)
    got = prior_findings_from_rows([fresh, stale, undated], brief_fingerprint=FP, now=NOW, max_age=timedelta(days=30))
    assert got.verdicts() == {"PBB-U": Verdict.RULED_OUT} and got.skipped_stale == 2


def test_with_no_age_limit_old_and_undated_evidence_is_used():
    stale = _row(_finding("PBB-F", Verdict.RULED_OUT), run_id="r2", finished_at=NOW - timedelta(days=400))
    undated = _row(_finding("PBB-H", Verdict.RULED_OUT), run_id="r3", finished_at=None)
    got = prior_findings_from_rows([stale, undated], brief_fingerprint=FP, now=NOW, max_age=None)
    assert set(got.verdicts()) == {"PBB-F", "PBB-H"} and got.skipped_stale == 0


def test_naive_and_string_timestamps_are_handled_and_compared_sanely():
    older = _row(_finding("PBB-U", Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE), run_id="r1", finished_at=datetime(2026, 10, 1, 0, 0))  # naive, taken as UTC
    newer = _row(_finding("PBB-U", Verdict.RULED_OUT), run_id="r2", finished_at="2026-10-20T08:30:00+00:00")  # ISO string, as a JSON-serialized row would carry
    got = prior_findings_from_rows([older, newer], brief_fingerprint=FP, now=NOW, max_age=timedelta(days=60))
    assert got.by_hypothesis["PBB-U"].verdict == Verdict.RULED_OUT


def test_the_default_age_limit_is_applied_by_load_prior_findings():
    stale = _row(_finding("PBB-U", Verdict.RULED_OUT), run_id="r", finished_at=NOW - DEFAULT_MAX_PRIOR_AGE - timedelta(days=1))

    async def source():
        return [stale]
    assert asyncio.run(load_prior_findings(source, brief_fingerprint=FP, now=NOW)).skipped_stale == 1


# ---- advisory, never blocking ---------------------------------------------------------------------

def test_an_unreadable_source_degrades_loudly_and_does_not_raise():
    records: list[logging.LogRecord] = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record)

    log = logging.getLogger("qa.run_memory")
    h = _H()
    log.addHandler(h)

    async def boom():
        raise ConnectionError("database unreachable")
    try:
        got = asyncio.run(load_prior_findings(boom, brief_fingerprint=FP, now=NOW))
    finally:
        log.removeHandler(h)
    assert got.degraded and got.degraded_reason == "ConnectionError" and got.verdicts() == {}
    assert any(r.exc_info for r in records), "must be logged, not swallowed"


# ---- ZR-007's acceptance criterion, end to end ----------------------------------------------------------

def test_a_new_run_after_a_restart_sees_the_prior_runs_results_and_orders_by_them():
    """'State survives process restart; a new run sees prior run's results.'
    Run 1 concludes: PBB-U ruled out, PBB-C partially validated. Everything in
    memory is then discarded; run 2 starts from nothing but the persisted rows
    and must schedule differently because of them. By hand, scores are
    U 100-30=70, C 75+25=100, F90 H90, G85 X85, R80, E held last."""
    persisted = json.dumps([
        {**r, "finished_at": r["finished_at"].isoformat()}
        for r in (_row(_finding("PBB-U", Verdict.RULED_OUT), run_id="run-1", finished_at=NOW - timedelta(days=2)),
                  _row(_finding("PBB-C", Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE), run_id="run-1", finished_at=NOW - timedelta(days=2)),
                  _row(_finding("PBB-F", Verdict.CONFIRMED_P0), run_id="run-7", fingerprint="fp-target-B", finished_at=NOW - timedelta(days=1)))  # another target's
    ])
    # "Restart": from here on, run 2 is built from `persisted` (a JSON string) alone -- no Finding, no row object, no store carries over.

    async def row_source():
        return json.loads(persisted)

    priors = asyncio.run(load_prior_findings(row_source, brief_fingerprint=FP, now=NOW))
    assert priors.verdicts() == {"PBB-U": Verdict.RULED_OUT, "PBB-C": Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE}
    assert priors.skipped_other_brief == 1

    p = prioritizer_from_priors(priors, flow_of=FLOW_BY_HYPOTHESIS)
    assert p(STATIC) == ["PBB-C", "PBB-F", "PBB-H", "PBB-G", "PBB-X", "PBB-R", "PBB-U", "PBB-E"]
    assert p.last_schedule is not None and p.last_schedule.order == tuple(p(STATIC))
    assert tuple(schedule(STATIC).order) != tuple(p.last_schedule.order), "the persisted results changed the order"


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
