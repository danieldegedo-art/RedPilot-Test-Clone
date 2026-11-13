"""Entitlement-binding invariant (app/testing/integrity/entitlement_binding.py).

Pure/stdlib; no engine or httpx import needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.entitlement_binding import (  # noqa: E402
    BindingDimension, BindingObservation, BindingVerdict, analyze_bindings, check_binding,
)


def _obs(**over):
    base = dict(feature_id="premium_export", identity_alias="A", outcome="allowed",
                qualifying_payment=True, tenant_alias="T-A", payer_identity="A", payer_tenant="T-A")
    base.update(over)
    return BindingObservation(**base)


def test_allowed_and_self_paid_holds():
    r = check_binding(_obs())
    assert r.verdict is BindingVerdict.HOLD and r.dimension is BindingDimension.NONE


def test_denied_holds_nothing_to_bind():
    r = check_binding(_obs(outcome="denied"))
    assert r.verdict is BindingVerdict.HOLD and r.dimension is BindingDimension.NONE


def test_indeterminate_is_inconclusive_never_a_guess():
    r = check_binding(_obs(outcome="indeterminate"))
    assert r.verdict is BindingVerdict.INCONCLUSIVE


def test_allowed_without_payment_is_unpaid_access_violation():
    r = check_binding(_obs(qualifying_payment=False, payer_identity=None, payer_tenant=None))
    assert r.verdict is BindingVerdict.VIOLATED and r.dimension is BindingDimension.UNPAID_ACCESS


def test_allowed_but_paid_by_another_identity_is_cross_identity_violation():
    r = check_binding(_obs(identity_alias="B", payer_identity="A", tenant_alias="T-B", payer_tenant="T-B"))
    assert r.verdict is BindingVerdict.VIOLATED and r.dimension is BindingDimension.CROSS_IDENTITY


def test_allowed_but_paid_under_another_tenant_is_cross_tenant_violation():
    r = check_binding(_obs(identity_alias="A", payer_identity="A", tenant_alias="T-B", payer_tenant="T-A"))
    assert r.verdict is BindingVerdict.VIOLATED and r.dimension is BindingDimension.CROSS_TENANT


def test_analyze_consolidates_tally_and_surfaces_violations():
    report = analyze_bindings([
        _obs(identity_alias="A"),                                              # hold
        _obs(identity_alias="C", qualifying_payment=False, payer_identity=None, payer_tenant=None),  # unpaid
        _obs(identity_alias="D", payer_identity="A", tenant_alias="T-D", payer_tenant="T-D"),         # cross-identity
        _obs(identity_alias="E", outcome="indeterminate"),                     # inconclusive
    ])
    assert report["checked"] == 4
    assert report["all_bindings_hold"] is False
    assert report["verdict_tally"] == {"hold": 1, "inconclusive": 1, "violated": 2}
    dims = {v["dimension"] for v in report["violations"]}
    assert dims == {"unpaid_access", "cross_identity"}
    # determinism
    assert analyze_bindings([_obs(), _obs(identity_alias="B", qualifying_payment=False, payer_identity=None)]) \
        == analyze_bindings([_obs(), _obs(identity_alias="B", qualifying_payment=False, payer_identity=None)])


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
