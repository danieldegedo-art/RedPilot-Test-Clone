#!/usr/bin/env python3
"""Severity-ranking accuracy: measure the engine's per-class severity model against an
INDEPENDENT model derived from first principles, so the 'not measured' scorecard item
becomes a real number. The independent model is documented and intentionally built from
different axes than the engine's hand-assigned bands:

  blast radius  -- who can benefit from the bypass:
                   everyone / unrelated-others = 4, another tenant or identity = 3, the attacker only = 2, nobody = 0
  revenue magnitude -- how much paid value is lost per exploit:
                   full paid feature for free = 3, a higher tier while underpaying = 2, bounded overage or time-limited = 1, none = 0

  independent_score = blast + magnitude   (higher = more severe)

We report: inversions (pairs the engine orders strictly opposite to the independent model
-- the real defect if any), pairwise concordance, and a rank correlation. Judgment-based
axis: no gain is claimed where the engine is already consistent.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_severity.py
"""
from __future__ import annotations

import itertools

from app.testing.integrity.findings import EXPERIMENT_CLASSES
from app.testing.integrity.impact_assessment import CLASS_SEVERITY, Severity

# independent model (blast, magnitude) per pre-registered class
BLAST = {
    "paid_feature_open_to_unpaid": 4, "entitlement_leak_to_unrelated_identity": 4,
    "cross_tenant_binding": 3, "cross_identity_binding": 3,
    "unconfirmed_payment_grants_access": 2, "plan_or_price_binding": 2, "currency_binding": 2,
    "duplicate_value_via_return_flow_repetition": 2, "retention_after_refund": 2, "ui_vs_server_divergence": 0,
}
MAGNITUDE = {
    "paid_feature_open_to_unpaid": 3, "entitlement_leak_to_unrelated_identity": 3,
    "unconfirmed_payment_grants_access": 3, "cross_tenant_binding": 3, "cross_identity_binding": 3,
    "plan_or_price_binding": 2, "currency_binding": 2,
    "duplicate_value_via_return_flow_repetition": 1, "retention_after_refund": 1, "ui_vs_server_divergence": 0,
}
_ENGINE_ORDINAL = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFORMATIONAL: 1, Severity.NONE: 0}


def _sign(x: float) -> int:
    return (x > 0) - (x < 0)


def main() -> int:
    classes = sorted(set(EXPERIMENT_CLASSES.values()))
    indep = {c: BLAST[c] + MAGNITUDE[c] for c in classes}
    eng = {c: _ENGINE_ORDINAL[CLASS_SEVERITY[c]] for c in classes}

    print(f"{'class':46s} {'engine':16s} {'indep(blast+mag)':16s}")
    for c in sorted(classes, key=lambda x: -indep[x]):
        print(f"  {c:44s} {CLASS_SEVERITY[c].value:16s} {BLAST[c]}+{MAGNITUDE[c]}={indep[c]}")

    inversions, concordant, total = [], 0, 0
    for a, b in itertools.combinations(classes, 2):
        se, si = _sign(eng[a] - eng[b]), _sign(indep[a] - indep[b])
        total += 1
        if se == si:
            concordant += 1
        elif se != 0 and si != 0 and se != si:  # strictly opposite order = a real ranking defect
            inversions.append((a, b))

    # Spearman-style rank correlation (average ranks, Pearson on ranks)
    def ranks(d):
        order = sorted(d, key=lambda k: d[k])
        r = {}
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and d[order[j + 1]] == d[order[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r
    re_, ri = ranks(eng), ranks(indep)
    n = len(classes)
    mean_e = sum(re_.values()) / n
    mean_i = sum(ri.values()) / n
    cov = sum((re_[c] - mean_e) * (ri[c] - mean_i) for c in classes)
    ve = sum((re_[c] - mean_e) ** 2 for c in classes) ** 0.5
    vi = sum((ri[c] - mean_i) ** 2 for c in classes) ** 0.5
    rho = cov / (ve * vi) if ve and vi else 0.0

    print("\n== severity-ranking accuracy (engine vs independent blast+magnitude model) ==")
    print(f"  class pairs compared         : {total}")
    print(f"  strict inversions (defects)  : {len(inversions)}  {inversions if inversions else ''}")
    print(f"  pairwise concordance         : {concordant}/{total} = {concordant/total:.3f}")
    print(f"  rank correlation (Spearman)  : {rho:.3f}")
    print("\n  interpretation: 0 inversions => the engine's severity ordering never contradicts the independent")
    print("  model; concordance < 1 with 0 inversions => the engine is CONSISTENT but COARSER (it ties classes")
    print("  the independent model separates). That is a defensible, not a wrong, severity model.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
