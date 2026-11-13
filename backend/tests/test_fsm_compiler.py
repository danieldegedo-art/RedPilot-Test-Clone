"""B1 / ZR-001: the FSM compiler (app/testing/fsm_compiler.py).

Every expected number below is computed by hand from the documented formula
(confidence = obs / (obs_for_that_state_and_trigger + SUPPORT_PRIOR)), not
read back from the code's own output.

Stdlib only -- fsm_compiler, pesm, state_exploration and lifecycle_model are
all dependency-free.
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.fsm_compiler import (  # noqa: E402
    FLOW_TYPES, UNCLASSIFIED, FSMHistory, ObservedTransition, _FLOW_RULES, _MAX_EVIDENCE_IDS,
    analyze, classify_flow, compare_with_spec, compile_from_pesm, compile_fsm, validate,
)
from app.testing.lifecycle_model import VALID_SUBSCRIPTION_TRANSITIONS  # noqa: E402
from app.testing.pesm import EntitlementStatus, EntitlementTransition, InMemoryPESMStore  # noqa: E402
from app.testing.state_exploration import reachable_states  # noqa: E402


def obs(frm: str, trig: str, to: str, rt: str = "subscription", ev: tuple[str, ...] = ()) -> ObservedTransition:
    return ObservedTransition(rt, frm, trig, to, None, ev)


# ---- flow classification --------------------------------------------------

def test_classify_flow_maps_each_flow_type():
    table = {
        "payment_confirmed": "payment", "checkout_completed": "checkout", "webhook_payment_succeeded": "provider_event",
        "subscription_created": "subscription", "trial_started": "trial", "subscription_renewed": "renewal",
        "cancel_requested": "cancellation", "refund_processed": "refund", "chargeback_opened": "chargeback",
        "plan_upgrade": "upgrade", "plan_downgrade": "downgrade", "access_revoked": "entitlement",
    }
    for trigger, expected in table.items():
        assert classify_flow(trigger) == expected, (trigger, classify_flow(trigger))
    assert set(table.values()) == set(FLOW_TYPES), "every ZR-001 flow type must be covered by this table"


def test_classify_flow_does_not_force_unknown_triggers_into_a_flow():
    assert classify_flow("something_else_entirely") == UNCLASSIFIED
    assert classify_flow("") == UNCLASSIFIED


def test_classify_flow_matches_word_starts_not_substrings():
    """The reason for word-start matching: plain substring matching puts
    'industrial_event' in the trial flow and 'discharge_complete' in payment."""
    assert classify_flow("industrial_event") == UNCLASSIFIED
    assert classify_flow("discharge_complete") == UNCLASSIFIED


def test_classify_flow_specific_vocabulary_beats_the_general_words_it_contains():
    assert classify_flow("payment_refunded") == "refund"  # not payment
    assert classify_flow("subscription_cancelled") == "cancellation"  # not subscription
    assert classify_flow("chargeback_opened") == "chargeback"  # not payment ("charge")
    assert classify_flow("webhook_payment_succeeded") == "provider_event"  # not payment
    assert classify_flow("Subscription-Renewed") == "renewal"  # case/punctuation-insensitive; not subscription
    assert classify_flow("checkout_abandoned") == "checkout"


def test_every_flow_type_is_reachable_through_the_rules():
    assert {flow for flow, _ in _FLOW_RULES} == set(FLOW_TYPES)


# ---- compile: support, confidence, nondeterminism --------------------------

def test_confidence_is_support_over_support_plus_prior():
    fsm = compile_fsm([obs("active", "cancel_requested", "cancelled")] * 3, resource_type="subscription")
    (t,) = fsm.transitions()
    assert t.observations == 3
    assert t.confidence == 0.6  # 3 / (3 + 2)
    assert t.flow_type == "cancellation"


def test_one_observation_cannot_read_as_certain():
    (t,) = compile_fsm([obs("a", "refund_processed", "b")], resource_type="subscription").transitions()
    assert t.confidence == round(1 / 3, 4)


def test_nondeterminism_splits_confidence_and_is_surfaced():
    o = [obs("active", "payment_failed", "past_due")] * 2 + [obs("active", "payment_failed", "expired")]
    fsm = compile_fsm(o, resource_type="subscription")
    assert fsm.predict("active", "payment_failed") == (("past_due", 0.4), ("expired", 0.2))  # 2/5, 1/5
    assert fsm.segment("payment").nondeterministic == (("active", "payment_failed"),)


def test_other_resource_types_are_not_mixed_in():
    o = [obs("active", "cancel_requested", "cancelled"), obs("captured", "refund_processed", "refunded", rt="payment")]
    fsm = compile_fsm(o, resource_type="subscription")
    assert fsm.observation_count == 1
    assert {t.to_state for t in fsm.transitions()} == {"cancelled"}


def test_evidence_references_are_carried_and_bounded():
    many = tuple(f"ev-{i:03d}" for i in range(_MAX_EVIDENCE_IDS + 15))
    (t,) = compile_fsm([obs("a", "refund_processed", "b", ev=many)], resource_type="subscription").transitions()
    assert len(t.evidence_artifact_ids) == _MAX_EVIDENCE_IDS
    assert t.evidence_artifact_ids == tuple(sorted(many))[:_MAX_EVIDENCE_IDS]


# ---- coverage (ZR-001's acceptance criterion) -------------------------------

def test_expected_flow_types_without_observations_are_reported_as_gaps_not_invented():
    fsm = compile_fsm([obs("active", "cancel_requested", "cancelled")], resource_type="subscription",
                      expected_flow_types=("cancellation", "refund", "chargeback"))
    assert fsm.uncovered_flow_types == ("chargeback", "refund")
    assert fsm.segment("refund") is None


def test_a_misspelled_expected_flow_type_fails_loudly():
    try:
        compile_fsm([], resource_type="subscription", expected_flow_types=("refnd",))
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "refnd" in str(e)


# ---- fingerprints and versioning --------------------------------------------

def test_fingerprint_ignores_observation_order_and_evidence_references():
    a = [obs("x", "refund_processed", "y"), obs("y", "cancel_requested", "z")]
    f1 = compile_fsm(a, resource_type="subscription")
    f2 = compile_fsm(list(reversed(a)), resource_type="subscription")
    f3 = compile_fsm([obs("x", "refund_processed", "y", ev=("e1",)), obs("y", "cancel_requested", "z", ev=("e2",))], resource_type="subscription")
    assert f1.fingerprint == f2.fingerprint == f3.fingerprint


def test_more_support_changes_content_but_not_structure_new_transition_changes_both():
    base = [obs("x", "refund_processed", "y")]
    f_base = compile_fsm(base, resource_type="subscription")
    f_more = compile_fsm(base + base, resource_type="subscription")
    f_new = compile_fsm(base + [obs("y", "cancel_requested", "z")], resource_type="subscription")
    assert f_more.fingerprint != f_base.fingerprint
    assert f_more.structure_fingerprint == f_base.structure_fingerprint
    assert f_new.fingerprint != f_base.fingerprint
    assert f_new.structure_fingerprint != f_base.structure_fingerprint


def test_history_cuts_a_new_version_only_when_the_model_changes_and_retains_all():
    h = FSMHistory()
    o1 = [obs("x", "refund_processed", "y")]
    v1 = h.update(o1, resource_type="subscription")
    again = h.update(o1, resource_type="subscription")
    assert again is v1 and len(h.versions("subscription")) == 1

    v2 = h.update(o1 + [obs("y", "cancel_requested", "z")], resource_type="subscription")
    assert v2.version == 2 and v2.model_version != v1.model_version
    assert h.latest("subscription") is v2
    assert h.get("subscription", 1) is v1 and h.get("subscription", 1).observation_count == 1  # the old version is untouched
    assert [f.version for f in h.versions("subscription")] == [1, 2]


def test_changing_the_engagement_coverage_expectation_is_a_new_version():
    h = FSMHistory()
    o = [obs("a", "refund_processed", "b")]
    v1 = h.update(o, resource_type="subscription", expected_flow_types=("refund",))
    v2 = h.update(o, resource_type="subscription", expected_flow_types=("refund", "chargeback"))
    assert v2.version == 2 and v2.uncovered_flow_types == ("chargeback",) and v1.uncovered_flow_types == ()


def test_resource_types_are_versioned_independently():
    h = FSMHistory()
    h.update([obs("a", "refund_processed", "b")], resource_type="subscription")
    p = h.update([obs("created", "payment_confirmed", "captured", rt="payment")], resource_type="payment")
    assert p.version == 1 and h.latest("subscription").version == 1


# ---- empirical validation ---------------------------------------------------

def test_validate_classifies_confirmed_divergent_and_novel():
    fsm = compile_fsm([obs("active", "cancel_requested", "cancelled")] * 3, resource_type="subscription")
    report = validate(fsm, [
        obs("active", "cancel_requested", "cancelled"),  # confirmed
        obs("active", "cancel_requested", "active"),  # divergent: known (state, trigger), unseen outcome
        obs("trialing", "cancel_requested", "cancelled"),  # novel: (state, trigger) never seen
        obs("captured", "refund_processed", "refunded", rt="payment"),  # other resource type: ignored
    ])
    assert report.confirmed == 1 and len(report.divergent) == 1 and len(report.novel) == 1
    assert report.needs_recompile is True
    assert report.model_version == fsm.model_version


def test_validate_with_only_confirming_observations_does_not_ask_for_a_recompile():
    fsm = compile_fsm([obs("active", "cancel_requested", "cancelled")] * 3, resource_type="subscription")
    assert validate(fsm, [obs("active", "cancel_requested", "cancelled")]).needs_recompile is False


# ---- comparison with the specified lifecycle ---------------------------------

def test_compare_with_spec_flags_illegal_observed_transitions_as_candidates():
    fsm = compile_fsm([
        obs("cancelled", "payment_confirmed", "active"),  # the spec says cancelled is terminal
        obs("active", "payment_failed", "past_due"), obs("active", "payment_failed", "past_due"),  # legal
        obs("active", "webhook_replayed", "active"),  # no state change: not a transition
        obs("limbo", "payment_confirmed", "active"),  # state the spec has never heard of
    ], resource_type="subscription")
    cmp = compare_with_spec(fsm, VALID_SUBSCRIPTION_TRANSITIONS)
    assert [(t.from_state, t.to_state) for t in cmp.illegal_observed] == [("cancelled", "active")]
    assert cmp.unknown_states == frozenset({"limbo"}), "unknown vocabulary must be reported, not judged illegal"
    assert ("active", "past_due") not in cmp.unobserved_legal  # observed
    assert ("trialing", "active") in cmp.unobserved_legal  # specified but never seen: a coverage gap


# ---- graph analysis, reusing state_exploration --------------------------------

def test_analyze_with_derived_and_explicit_initial_states():
    fsm = compile_fsm([obs("new", "subscription_created", "active"), obs("active", "cancel_requested", "cancelled"),
                       obs("stray", "cancel_requested", "cancelled")], resource_type="subscription")
    derived = analyze(fsm)
    assert derived.initial_states == frozenset({"new", "stray"}) and derived.unreachable == frozenset()
    assert derived.dead_ends == frozenset({"cancelled"})
    explicit = analyze(fsm, initial_states=["new"])
    assert explicit.reachable == frozenset({"new", "active", "cancelled"}) and explicit.unreachable == frozenset({"stray"})


def test_analyze_claims_nothing_unreachable_when_every_state_is_on_a_cycle():
    fsm = compile_fsm([obs("a", "payment_confirmed", "b"), obs("b", "payment_failed", "a")], resource_type="subscription")
    assert analyze(fsm).unreachable == frozenset()


def test_observed_machine_goes_through_the_existing_graph_primitive():
    fsm = compile_fsm([obs("new", "subscription_created", "active"), obs("active", "cancel_requested", "cancelled")], resource_type="subscription")
    assert reachable_states(fsm.as_transition_map(), "new") == frozenset({"new", "active", "cancelled"})


# ---- PESM integration ---------------------------------------------------------

def test_compile_from_pesm_compiles_the_recorded_entitlement_lifecycle():
    async def go():
        store, history = InMemoryPESMStore(), FSMHistory()
        t0 = datetime(2026, 10, 25, tzinfo=timezone.utc)

        def tr(frm, to, trig, ev):
            return EntitlementTransition("f1", "alice", None, frm, to, trig, t0, ev)

        await store.record_transition(tr(EntitlementStatus.NEVER_GRANTED, EntitlementStatus.ACTIVE, "payment_confirmed", ("ev-1",)))
        await store.record_transition(tr(EntitlementStatus.NEVER_GRANTED, EntitlementStatus.ACTIVE, "payment_confirmed", ("ev-2",)))
        await store.record_transition(tr(EntitlementStatus.ACTIVE, EntitlementStatus.REVOKED, "refund_processed", ("ev-3",)))
        fsm = await compile_from_pesm(store, history, expected_flow_types=("payment", "refund", "chargeback"))
        return fsm

    fsm = asyncio.run(go())
    assert fsm.resource_type == "entitlement" and fsm.model_version.startswith("entitlement@v1:")
    assert fsm.uncovered_flow_types == ("chargeback",)
    pay = fsm.segment("payment").transitions[0]
    assert (pay.from_state, pay.to_state, pay.observations) == ("never_granted", "active", 2)
    assert pay.evidence_artifact_ids == ("ev-1", "ev-2")
    assert analyze(fsm, initial_states=["never_granted"]).reachable == frozenset({"never_granted", "active", "revoked"})


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
