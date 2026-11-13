"""ZR-003 / ZR-012 (B10 prioritization half): app/testing/prioritization.py and
the engine-side guard integrity/engine.py::_apply_prioritizer.

Expected orders below are worked out by hand from BASE_RISK and the documented
adjustments, then asserted -- not copied from the scheduler's own output. The
static order they are all measured against is
    U F H C G X R E        (indices 0..7)
and base risk is U100 F90 H90 X85 G85 R80 C75 E40, ties broken by that index.

Needs only the pydantic shim (engine.py imports it); no HTTP, no DB.
"""
from __future__ import annotations

import ast
import dataclasses
import logging
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.fsm_compiler import ObservedTransition, compile_fsm  # noqa: E402
from app.testing.integrity.engine import EXPERIMENT_ORDER, FLOW_BY_HYPOTHESIS, _apply_prioritizer  # noqa: E402
from app.testing.prioritization import (  # noqa: E402
    BASE_RISK, DEFAULT_BASE_RISK, DERIVED_HYPOTHESES, Prioritizer, schedule,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402

STATIC = list(EXPERIMENT_ORDER)
U, F, H, C, G, X, R, E = "PBB-U", "PBB-F", "PBB-H", "PBB-C", "PBB-G", "PBB-X", "PBB-R", "PBB-E"


def order(**kw) -> tuple[str, ...]:
    return schedule(STATIC, **kw).order


# ---- the scheduler ---------------------------------------------------------------

def test_static_order_is_what_we_think_it_is():
    assert STATIC == [U, F, H, C, G, X, R, E]


def test_with_no_signals_order_follows_payment_risk_and_breaks_ties_by_static_position():
    # F,H tie at 90 (F first); G,X tie at 85 (G first, it is earlier in the static order); then R80, C75; E held last
    assert order() == (U, F, H, G, X, R, C, E)


def test_payment_risk_outranks_presentation_anomalies():
    """ZR-012: UI/redirect/cache anomalies (PBB-E) behind payment risk, by score AND by position."""
    s = schedule(STATIC)
    by = {b.hypothesis_id: b for b in s.breakdowns}
    assert all(by[h].score > by[E].score for h in STATIC if h != E)
    assert s.order[-1] == E


def test_a_cleared_hypothesis_moves_later_but_is_not_dropped():
    assert order(prior_verdicts={U: Verdict.RULED_OUT}) == (F, H, G, X, R, C, U, E)  # U: 100-30 = 70, below C's 75


def test_an_open_lead_moves_up():
    assert order(prior_verdicts={C: Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE}) == (U, C, F, H, G, X, R, E)  # C: 75+25 = 100, ties U, U is earlier
    assert order(prior_verdicts={X: Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE}) == (U, X, F, H, G, R, C, E)  # X: 85+15 = 100
    assert order(prior_verdicts={R: Verdict.CONFIRMED_P0}) == (U, F, H, R, G, X, C, E)  # R: 80+10 = 90, ties F,H; static position puts R after them


def test_unknown_and_blocked_priors_do_not_move_anything():
    assert order(prior_verdicts={U: Verdict.UNKNOWN, F: Verdict.BLOCKED}) == order()


def _fsm_observing_refund_and_entitlement_but_missing_checkout():
    return compile_fsm(
        [ObservedTransition("entitlement", "active", "refund_processed", "revoked"),
         ObservedTransition("entitlement", "active", "access_revoked", "revoked")],
        resource_type="entitlement", expected_flow_types=("checkout", "refund", "entitlement"),
    )


def test_flow_coverage_reorders_the_run():
    """Observed: refund, entitlement (+10). Expected but never seen: checkout (-20).
    Neutral: subscription, payment (neither expected nor observed).
    G 85+10=95, F 90, H 90, R 80+10=90, X 85, U 100-20=80, C 75-20=55; E held."""
    got = order(fsms=[_fsm_observing_refund_and_entitlement_but_missing_checkout()], flow_of=FLOW_BY_HYPOTHESIS)
    assert got == (G, F, H, R, X, U, C, E)


def test_no_flow_mapping_means_no_coverage_adjustment():
    assert order(fsms=[_fsm_observing_refund_and_entitlement_but_missing_checkout()]) == order()


def test_signals_change_the_order_which_is_zr003s_acceptance_criterion():
    base = order()
    assert order(prior_verdicts={U: Verdict.RULED_OUT}) != base
    assert order(fsms=[_fsm_observing_refund_and_entitlement_but_missing_checkout()], flow_of=FLOW_BY_HYPOTHESIS) != base


def test_weights_are_overridable_per_engagement():
    assert order(weights={C: 200.0})[0] == C


# ---- hard constraints ----------------------------------------------------------------

def test_a_derived_hypothesis_stays_last_no_matter_how_high_it_scores():
    """PBB-E is computed from what every other experiment observes. Run early, it
    would clear a hypothesis over states it hadn't observed yet."""
    s = schedule(STATIC, weights={E: 10_000.0}, prior_verdicts={E: Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE})
    assert s.order[-1] == E and s.held_last == (E,)
    assert s.breakdowns[-1].score > s.breakdowns[0].score, "held last despite the highest score -- that is the point"


def test_opting_out_of_the_hold_is_explicit_not_accidental():
    assert schedule(STATIC, weights={E: 10_000.0}, derived_last=()).order[0] == E


def test_unweighted_hypotheses_are_scheduled_and_reported_never_dropped():
    s = schedule([U, F, H, C, G, X, R, "PBB-NEW", E])
    assert "PBB-NEW" in s.order and s.unweighted == ("PBB-NEW",)
    assert s.order == (U, F, H, G, X, R, C, "PBB-NEW", E)  # default 50: below C's 75, above nothing else weighted, E held last
    assert DEFAULT_BASE_RISK == 50.0


def test_every_experiment_has_a_registered_weight_and_derived_ones_are_real_experiments():
    assert not (set(EXPERIMENT_ORDER) - set(BASE_RISK)), "an experiment would silently get DEFAULT_BASE_RISK"
    assert DERIVED_HYPOTHESES <= set(EXPERIMENT_ORDER)


def test_breakdown_is_a_faithful_trace_of_the_decision():
    s = schedule(STATIC, prior_verdicts={H: Verdict.RULED_OUT})
    assert [b.hypothesis_id for b in s.breakdowns] == list(s.order)
    h = next(b for b in s.breakdowns if b.hypothesis_id == H)
    assert (h.base_risk, h.prior_verdict, h.prior_adjustment, h.coverage_adjustment, h.score) == (90.0, "RULED_OUT", -30.0, 0.0, 60.0)
    e = next(b for b in s.breakdowns if b.hypothesis_id == E)
    assert e.held_last and e.score == 40.0


def test_properties_hold_across_many_random_signal_combinations():
    rng = random.Random(20261025)
    fsm = _fsm_observing_refund_and_entitlement_but_missing_checkout()
    pool = [*EXPERIMENT_ORDER, "PBB-NEW1", "PBB-NEW2"]
    verdicts = list(Verdict)
    for _ in range(300):
        hyps = rng.sample(pool, rng.randint(1, len(pool)))
        prior = {h: rng.choice(verdicts) for h in rng.sample(hyps, rng.randint(0, len(hyps)))}
        weights = {rng.choice(hyps): rng.choice([0.0, 30.0, 200.0])} if rng.random() < 0.3 else None
        kw = dict(prior_verdicts=prior, weights=weights, fsms=[fsm] if rng.random() < 0.5 else [],
                  flow_of=FLOW_BY_HYPOTHESIS if rng.random() < 0.5 else None)
        s = schedule(hyps, **kw)

        assert sorted(s.order) == sorted(hyps), "never drops or duplicates an experiment"
        assert s.order == schedule(hyps, **kw).order, "deterministic"
        free = [b for b in s.breakdowns if not b.held_last]
        assert [b.score for b in free] == sorted((b.score for b in free), reverse=True), "scores non-increasing"
        assert s.breakdowns[len(free):] == tuple(b for b in s.breakdowns if b.held_last), "held ones are at the end"
        assert [b.hypothesis_id for b in s.breakdowns if b.held_last] == [h for h in hyps if h in DERIVED_HYPOTHESES]
        for b in s.breakdowns:
            assert b.score == round(b.base_risk + b.prior_adjustment + b.coverage_adjustment, 4)


def test_scheduling_cannot_produce_or_influence_a_verdict():
    """B10's text says its score 'gates CONFIRMED_P0'. ZR-024/025 say nothing but
    ConfirmationGate may confirm. Structural check, via the AST so the docstring
    discussing this does not trip it."""
    src = (Path(__file__).parent.parent / "app" / "testing" / "prioritization.py").read_text()
    forbidden = {"ConfirmationToken", "ConfirmationGate", "ConfirmationCandidate", "oracle_gate"}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ImportFrom):
            assert not (forbidden & ({node.module or ""} | {a.name for a in node.names})), ast.dump(node)
        if isinstance(node, ast.Import):
            assert not (forbidden & {a.name for a in node.names}), ast.dump(node)
    for cls in (type(schedule(STATIC)), type(schedule(STATIC).breakdowns[0])):
        assert not ({"verdict", "confirmed", "token"} & {f.name for f in dataclasses.fields(cls)}), cls


# ---- the engine-side guard --------------------------------------------------------------

class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _guard(prioritizer):
    cap, log = _Capture(), logging.getLogger("qa.integrity.engine")
    log.addHandler(cap)
    old = log.level
    log.setLevel(logging.DEBUG)
    try:
        return _apply_prioritizer(list(STATIC), prioritizer), cap.records
    finally:
        log.removeHandler(cap)
        log.setLevel(old)


def test_no_prioritizer_is_exactly_todays_behaviour():
    got, logs = _guard(None)
    assert got == STATIC and not logs


def test_a_valid_reordering_is_accepted():
    got, logs = _guard(lambda h: [F, U, H, C, G, X, R, E])
    assert got == [F, U, H, C, G, X, R, E] and not logs


def test_a_prioritizer_that_drops_an_experiment_is_rejected_loudly():
    got, logs = _guard(lambda h: [x for x in h if x != R])
    assert got == STATIC
    assert any(r.levelno == logging.ERROR for r in logs)


def test_a_prioritizer_that_duplicates_or_invents_is_rejected_loudly():
    for bad in (lambda h: [*h, U], lambda h: [*h[:-1], "PBB-INVENTED"]):
        got, logs = _guard(bad)
        assert got == STATIC and any(r.levelno == logging.ERROR for r in logs)


def test_a_prioritizer_that_raises_cannot_stop_the_run():
    def boom(h):
        raise RuntimeError("scheduler bug")
    got, logs = _guard(boom)
    assert got == STATIC and any(r.exc_info for r in logs)


def test_the_engine_enforces_the_derived_hypothesis_even_if_the_prioritizer_does_not():
    got, logs = _guard(lambda h: [E, U, F, H, C, G, X, R])
    assert got == [U, F, H, C, G, X, R, E], "E moved last, the others' relative order untouched"
    assert any(r.levelno == logging.WARNING for r in logs)


def test_the_real_prioritizer_works_through_the_guard_and_keeps_its_reasoning():
    p = Prioritizer(prior_verdicts={U: Verdict.RULED_OUT})
    got, logs = _guard(p)
    assert got == [F, H, G, X, R, C, U, E] and not logs
    assert p.last_schedule is not None and p.last_schedule.order == tuple(got)


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
