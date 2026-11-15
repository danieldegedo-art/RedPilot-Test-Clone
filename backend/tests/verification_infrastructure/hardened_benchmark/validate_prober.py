#!/usr/bin/env python3
"""Cross-check: does the INDEPENDENT prober agree with the base benchmark's
hand-authored truth on all 21 existing scenarios?

If yes, the prober can be trusted to label a large randomized population with no
hand-authoring -- which is what removes the shared-authorship bias. Run:

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/validate_prober.py
"""
from __future__ import annotations

import asyncio

from hardened_benchmark.ground_truth import EXPERIMENTS, probe_truth
from purity_benchmark.customer_target import TargetFlags
from purity_benchmark.scenarios import SCENARIOS


def _sla(scenario) -> float:
    return float(scenario.brief_overrides.get("limits", {}).get("revocation_sla_seconds", 1.0))


async def main() -> int:
    exp_matches = aux_matches = 0
    exp_total = aux_total = 0
    mismatches: list[str] = []
    print(f"{'scenario':38s} {'experiments':12s} {'open/leak':10s}")
    for sc in SCENARIOS:
        got = await probe_truth(TargetFlags(**sc.flags), sla=_sla(sc))
        exp_ok = all(got.truth[e] == sc.truth[e] for e in EXPERIMENTS)
        diffs = [f"{e}:{got.truth[e]}!={sc.truth[e]}" for e in EXPERIMENTS if got.truth[e] != sc.truth[e]]
        exp_total += 1
        exp_matches += int(exp_ok)
        aux_ok = (got.open_present == sc.expects_open_finding) and (got.leak_present == sc.expects_leak_finding)
        aux_total += 1
        aux_matches += int(aux_ok)
        if not exp_ok:
            mismatches.append(f"{sc.name}: {', '.join(diffs)}")
        if not aux_ok:
            mismatches.append(f"{sc.name}: open={got.open_present}/exp{sc.expects_open_finding} leak={got.leak_present}/exp{sc.expects_leak_finding}")
        flag = "ok " if (exp_ok and aux_ok) else "XX "
        print(f"{flag}{sc.name:35s} {'MATCH' if exp_ok else 'DIFF':12s} {'MATCH' if aux_ok else 'DIFF':10s}")

    print("\n== independent-prober vs hand-authored truth ==")
    print(f"experiment truth maps agree: {exp_matches}/{exp_total}")
    print(f"open/leak aux agree:         {aux_matches}/{aux_total}")
    if mismatches:
        print("\nMISMATCHES (investigate -- a disagreement is a real finding, not noise):")
        for m in mismatches:
            print("  -", m)
        return 1
    print("\nAll 21 scenarios: independent behavioral truth == hand-authored truth.")
    print("=> the prober can label a randomized population without hand-authoring; shared-authorship bias on the TRUTH side is removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
