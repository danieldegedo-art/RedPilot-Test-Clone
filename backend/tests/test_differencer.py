"""B6: tests for app/testing/integrity/differencer.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.differencer import (  # noqa: E402
    Divergence, DivergenceStatus, SubjectSurfaces, Surface, SurfaceClaim, diff, diff_all, report,
)


def _subj(key, p0, **surf):
    """surf: surface_name=bool|None (claims_entitled)."""
    claims = tuple(SurfaceClaim(Surface(s), v, artifact_id=f"art-{s}") for s, v in surf.items())
    return SubjectSurfaces(key, p0, claims)


def test_view_claims_paid_but_server_denies_is_trust_defect_not_p0():
    d = diff(_subj("declined-payer/tier", "unconfirmed_payment_grants_access",
                   server_enforced=False, account_view=True, return_badge=True))
    assert d.status == DivergenceStatus.DIVERGENT
    assert d.classification == "trust_defect"
    assert d.authoritative_entitled is False                 # server governs, not the badges
    assert set(d.diverging_surfaces) == {"account_view", "return_badge"}
    assert "NOT a P0" in d.note


def test_server_allows_but_a_surface_says_not_paid_is_also_a_trust_defect():
    d = diff(_subj("payer/feature", "retention_after_refund",
                   server_enforced=True, account_view=False))
    assert d.status == DivergenceStatus.DIVERGENT
    assert d.authoritative_entitled is True
    assert d.diverging_surfaces == ("account_view",)


def test_consistent_when_every_surface_agrees_with_the_server():
    d = diff(_subj("payer/feature", "plan_or_price_binding",
                   server_enforced=True, account_view=True, return_badge=True, alt_channel=True))
    assert d.status == DivergenceStatus.CONSISTENT
    assert d.diverging_surfaces == ()
    assert d.authoritative_entitled is True


def test_inconclusive_without_an_authoritative_surface_never_promotes_a_view():
    # a view and a badge both scream "paid" -- but the server was never observed.
    d = diff(_subj("mystery/feature", "ui_vs_server_divergence",
                   account_view=True, return_badge=True))
    assert d.status == DivergenceStatus.INCONCLUSIVE
    assert d.authoritative_entitled is None                  # the whole point: NOT inferred to True
    assert d.classification == "inconclusive"


def test_single_authoritative_surface_has_nothing_to_diff():
    d = diff(_subj("payer/feature", "plan_or_price_binding", server_enforced=False))
    assert d.status == DivergenceStatus.CONSISTENT
    assert d.authoritative_entitled is False and d.diverging_surfaces == ()


def test_unobserved_surfaces_are_ignored_not_counted_as_agreeing():
    # server denies; account_view unobserved (None) -> no non-authoritative claim to diff -> CONSISTENT,
    # and the unobserved surface contributes no evidence id.
    d = diff(_subj("payer/feature", "plan_or_price_binding", server_enforced=False, account_view=None))
    assert d.status == DivergenceStatus.CONSISTENT
    assert "art-account_view" not in d.evidence_ids
    assert "art-server_enforced" in d.evidence_ids


def test_authoritative_outcome_comes_only_from_the_server_even_against_a_majority():
    # three non-authoritative surfaces all claim paid; the server denies. Majority does NOT win.
    d = diff(_subj("declined-payer/tier", "unconfirmed_payment_grants_access",
                   server_enforced=False, account_view=True, return_badge=True, alt_channel=True))
    assert d.authoritative_entitled is False
    assert d.status == DivergenceStatus.DIVERGENT
    assert len(d.diverging_surfaces) == 3


def test_report_buckets_and_is_json_safe():
    subjects = [
        _subj("a", "unconfirmed_payment_grants_access", server_enforced=False, account_view=True),   # trust defect
        _subj("b", "plan_or_price_binding", server_enforced=True, account_view=True),                 # consistent
        _subj("c", "ui_vs_server_divergence", account_view=True),                                      # inconclusive
    ]
    rep = report(subjects)
    assert rep["trust_defects"] == ["a"] and rep["inconclusive"] == ["c"]
    assert rep["subjects"] == 3
    assert json.loads(json.dumps(rep)) == rep
