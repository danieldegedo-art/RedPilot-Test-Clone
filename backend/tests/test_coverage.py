"""ZR-006 / B18: tests for app/testing/integrity/coverage.py (multi-dimensional
coverage tracking). Stdlib only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.coverage import CoverageMatrix, _aggregate, coverage_matrix  # noqa: E402
from app.testing.integrity.findings import SCOPE_BY_HYPOTHESIS  # noqa: E402
from app.testing.purity.taxonomy import Coverage, Verdict  # noqa: E402


class _F:
    def __init__(self, hid, verdict, p0_class, affected_flow):
        self.hypothesis_id = hid
        self.verdict = verdict
        self.p0_class = p0_class
        self.affected_flow = affected_flow


class _Result:
    def __init__(self, findings):
        self.findings = findings


def _cell(matrix, dimension, value):
    return next(c for c in matrix.by_dimension(dimension) if c.value == value)


# ---- aggregation rule ----------------------------------------------------------

def test_aggregate_is_covered_only_if_every_contributor_is_covered():
    assert _aggregate([Coverage.COVERED, Coverage.COVERED]) == Coverage.COVERED
    assert _aggregate([Coverage.COVERED, Coverage.UNKNOWN]) == Coverage.UNKNOWN  # least-covered wins
    assert _aggregate([Coverage.COVERED, Coverage.PARTIALLY_COVERED]) == Coverage.PARTIALLY_COVERED
    assert _aggregate([Coverage.PARTIALLY_COVERED, Coverage.BLOCKED]) == Coverage.BLOCKED


def test_aggregate_empty_is_unknown_never_covered():
    assert _aggregate([]) == Coverage.UNKNOWN


# ---- per-verdict cell coverage -------------------------------------------------

def test_conclusive_verdicts_are_covered_and_inconclusive_are_not():
    r = _Result([
        _F("PBB-U", Verdict.CONFIRMED_P0, "unconfirmed_payment_grants_access", "checkout"),
        _F("PBB-F", Verdict.RULED_OUT, "plan_or_price_binding", "subscription"),
        _F("PBB-H", Verdict.UNKNOWN, "currency_binding", "payment"),
        _F("PBB-R", Verdict.BLOCKED, "retention_after_refund", "refund"),
        _F("PBB-E", Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, "ui_vs_server_divergence", "entitlement"),
    ])
    m = coverage_matrix(r)
    assert _cell(m, "hypothesis_class", "unconfirmed_payment_grants_access").coverage == Coverage.COVERED
    assert _cell(m, "hypothesis_class", "plan_or_price_binding").coverage == Coverage.COVERED
    assert _cell(m, "hypothesis_class", "currency_binding").coverage == Coverage.UNKNOWN
    assert _cell(m, "hypothesis_class", "retention_after_refund").coverage == Coverage.BLOCKED
    assert _cell(m, "hypothesis_class", "ui_vs_server_divergence").coverage == Coverage.PARTIALLY_COVERED


# ---- flow aggregation (least-covered-wins across experiments in a flow) ---------

def test_a_flow_with_one_unknown_probe_is_not_reported_covered():
    r = _Result([
        _F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
        _F("PBB-C", Verdict.UNKNOWN, "duplicate_value_via_return_flow_repetition", "checkout"),  # same flow, inconclusive
    ])
    m = coverage_matrix(r)
    checkout = _cell(m, "flow_type", "checkout")
    assert checkout.coverage == Coverage.UNKNOWN  # the RULED_OUT probe cannot average the UNKNOWN one away
    assert set(checkout.experiments) == {"PBB-U", "PBB-C"}


def test_a_flow_with_all_conclusive_probes_is_covered():
    r = _Result([
        _F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
        _F("PBB-C", Verdict.CONFIRMED_P0, "duplicate_value_via_return_flow_repetition", "checkout"),
    ])
    assert _cell(coverage_matrix(r), "flow_type", "checkout").coverage == Coverage.COVERED


# ---- scope dimension uses the declared mapping ---------------------------------

def test_test_scope_dimension_groups_by_declared_scope():
    r = _Result([
        _F("PBB-G", Verdict.CONFIRMED_P0, "cross_tenant_binding", "entitlement"),
        _F("PBB-X", Verdict.RULED_OUT, "cross_identity_binding", "payment"),
        _F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
    ])
    m = coverage_matrix(r)
    assert _cell(m, "test_scope", "cross_tenant").coverage == Coverage.COVERED
    assert _cell(m, "test_scope", "cross_identity").coverage == Coverage.COVERED
    assert _cell(m, "test_scope", "single_identity").experiments == ("PBB-U",)
    # the declared mapping is what drives it
    assert SCOPE_BY_HYPOTHESIS["PBB-G"] == "cross_tenant"


# ---- matrix shape, tally, uncovered, round-trip --------------------------------

def test_matrix_has_three_dimensions_and_a_verdict_tally():
    r = _Result([_F("PBB-U", Verdict.CONFIRMED_P0, "unconfirmed_payment_grants_access", "checkout")])
    m = coverage_matrix(r)
    assert m.dimensions() == ["hypothesis_class", "flow_type", "test_scope"]
    assert m.verdict_tally == {"CONFIRMED_P0": 1}


def test_uncovered_lists_every_non_covered_cell():
    r = _Result([
        _F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
        _F("PBB-H", Verdict.UNKNOWN, "currency_binding", "payment"),
    ])
    m = coverage_matrix(r)
    assert all(c.coverage != Coverage.COVERED for c in m.uncovered())
    # the currency class / payment flow / single_identity-with-unknown all surface as not-covered
    assert any(c.dimension == "hypothesis_class" and c.value == "currency_binding" for c in m.uncovered())


def test_to_dict_is_json_safe_and_deterministic():
    r = _Result([
        _F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
        _F("PBB-G", Verdict.CONFIRMED_P0, "cross_tenant_binding", "entitlement"),
    ])
    import json
    d = coverage_matrix(r).to_dict()
    assert json.loads(json.dumps(d)) == d  # fully JSON-safe
    assert coverage_matrix(r).to_dict() == d  # deterministic


def test_empty_result_yields_no_cells_and_empty_tally():
    m = coverage_matrix(_Result([]))
    assert m.cells == [] and m.verdict_tally == {}
