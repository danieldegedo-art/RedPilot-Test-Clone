"""External regression intelligence: turns an engine result into a safe, repeatable black-box regression and replays it.

* a CONFIRMED_P0 becomes a regression that must turn RULED_OUT once fixed (``expect_after_fix``);
* a RULED_OUT becomes a false-positive control that must STAY RULED_OUT;
* UNKNOWN/BLOCKED/PARTIAL entries are carried as 'open' and are never presented as passing;
* the spec carries the brief fingerprint and the re-run triggers (what changes require re-validation) and the clean-session / fixture-reset instructions.
Only external facts are stored (hypothesis ids, verdicts, brief fingerprint) -- no tokens, no payment ids, no internal causes. Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable

from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.findings import ENGINE_VERSION, EngineResult
from app.testing.purity.taxonomy import Verdict

RERUN_TRIGGERS = (
    "any change to checkout, payment/return flow, subscription view, refund or protected-feature routes or fields (the brief fingerprint changes)",
    "any change to plans, prices, currencies, quotas or tier gating", "any change to identity/tenant/session handling or entitlement binding",
    "a new payment provider, payment method or sandbox fixture", "every release that touches billing or entitlement code (the code is never inspected -- the black-box result is simply re-earned)",
)
CLEAN_SESSION_INSTRUCTIONS = ("Use brand-new synthetic identities (signup) or reset the approved identity pool; use no stored cookies/local storage; authenticate only with the identity's own token.",
                              "Run the plan against the same environment class (sandbox/benchmark) and the same brief fingerprint; do not reuse payment references from earlier runs.")


def _regression_kind(verdict: Verdict) -> tuple[str, str | None]:
    """The regression kind + post-fix expectation for one verdict. Shared by
    build_regression_spec (the spec row) and regression_reference (the per-finding
    pointer) so the two vocabularies can never drift apart. PBB-OPEN is excluded
    upstream by hypothesis id, not here."""
    if verdict == Verdict.CONFIRMED_P0:
        return "regression_for_confirmed_p0", Verdict.RULED_OUT.value
    if verdict == Verdict.RULED_OUT:
        return "false_positive_control", Verdict.RULED_OUT.value
    return "open_not_a_pass", None


def regression_reference(hypothesis_id: str, verdict: Verdict, brief_fingerprint: str) -> str | None:
    """ZR-023/ZR-019: a stable, portable reference tying a REAL finding to the
    entry build_regression_spec would emit for it:
    '<kind>:<hypothesis_id>@<brief_fingerprint>'. PBB-OPEN is never turned into a
    regression check (it can carry no pass/fail expectation), so it has no
    reference."""
    if hypothesis_id == "PBB-OPEN":
        return None
    kind, _ = _regression_kind(verdict)
    return f"{kind}:{hypothesis_id}@{brief_fingerprint}"


def attach_regression_references(findings: Iterable[Any], brief_fingerprint: str) -> None:
    """Set Finding.regression_test_reference in place for every finding that maps
    to a regression check, so a real finding (not only a benchmark PI-SUMMARY row)
    carries the id of the check that re-validates it (ZR-023/B26). PBB-OPEN stays
    None."""
    for f in findings:
        ref = regression_reference(f.hypothesis_id, f.verdict, brief_fingerprint)
        if ref is not None:
            f.regression_test_reference = ref


def build_regression_spec(result: EngineResult, brief: ExecutionBrief) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for f in result.findings:
        if f.hypothesis_id == "PBB-OPEN":
            continue
        kind, expect = _regression_kind(f.verdict)
        checks.append({"hypothesis_id": f.hypothesis_id, "p0_class": f.p0_class, "kind": kind, "verdict_at_creation": f.verdict.value, "expect_after_fix": expect})
    return {"engine_version": ENGINE_VERSION, "brief_fingerprint": brief.fingerprint(), "checks": checks, "rerun_triggers": list(RERUN_TRIGGERS),
            "clean_session_instructions": list(CLEAN_SESSION_INSTRUCTIONS), "fixture_reset": "synthetic identities are minted per experiment via the approved signup flow (no shared state survives a run)", "contains_secrets": False}


@dataclass
class RegressionOutcome:
    passed: bool
    details: list[str]
    stale: bool


async def replay_regression(spec: dict[str, Any], brief: ExecutionBrief, run: Callable[[list[str]], Awaitable[EngineResult]]) -> RegressionOutcome:
    """Re-run only the hypotheses in the spec; compare with expectations. A changed brief fingerprint makes the spec STALE (revalidate, do not trust)."""
    stale = spec.get("brief_fingerprint") != brief.fingerprint()
    targets = [c["hypothesis_id"] for c in spec["checks"] if c["expect_after_fix"] is not None]
    result = await run(targets)
    verdicts = result.verdicts()
    details: list[str] = []
    ok = not stale
    if stale:
        details.append("brief fingerprint changed since the regression was created: the spec is stale and must be re-validated, not trusted")
    for c in spec["checks"]:
        if c["expect_after_fix"] is None:
            continue
        actual = verdicts.get(c["hypothesis_id"])
        good = actual == c["expect_after_fix"]
        ok = ok and good
        details.append(f"{c['hypothesis_id']} ({c['kind']}): expected {c['expect_after_fix']}, got {actual}" + ("" if good else "  <-- REGRESSION"))
    return RegressionOutcome(ok, details, stale)
