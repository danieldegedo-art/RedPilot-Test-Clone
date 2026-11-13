"""ZR-033: the 5-condition final quality gate, coded as a checkable gate.

Before an engagement may be called complete, ALL FIVE conditions must hold. Each is a
deterministic predicate over a declared engagement summary; the gate names every
failing condition and the findings responsible. It is FAIL-CLOSED: missing data makes
the dependent condition FAIL -- the gate never passes on absent evidence.

  QG-1 scenario_coverage   -- every ZR-031 minimum-required scenario was exercised.
  QG-2 schema_complete     -- every CONFIRMED_P0 finding is schema-complete (ZR-019, 1.0).
  QG-3 server_confirmed    -- no CONFIRMED_P0 rests on a non-authoritative/client signal
                              alone (ZR-016/ZR-024/ZR-025): each was server-confirmed.
  QG-4 reproducible        -- every CONFIRMED_P0 carries a reproduction bundle (ZR-015).
  QG-5 regression_referenced -- every CONFIRMED_P0 carries a regression reference (ZR-023).

Conditions QG-2..5 quantify over CONFIRMED_P0 findings only: a non-P0 verdict populates
fewer fields by design, so holding it to the P0 schema would be wrong. With zero
confirmed findings QG-2..5 hold vacuously -- a clean engagement still passes. Pure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from app.testing.integrity import scenario_registry

MODULE_VERSION = "quality-gate/1.0"
_P0 = "CONFIRMED_P0"
_COMPLETE = 1.0 - 1e-9


@dataclass(frozen=True)
class FindingView:
    """The minimal, declared view of a finding the gate needs. Built from a real
    Finding's fields by the caller (the engine/report layer)."""
    finding_id: str
    verdict: str
    schema_completeness: float = 0.0
    server_confirmed: bool = False
    has_reproduction: bool = False
    has_regression_reference: bool = False


@dataclass(frozen=True)
class ConditionResult:
    condition_id: str
    name: str
    passed: bool
    offenders: tuple[str, ...] = ()   # finding ids / scenario keys responsible for a failure
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"condition_id": self.condition_id, "name": self.name, "passed": self.passed,
                "offenders": list(self.offenders), "detail": self.detail}


@dataclass(frozen=True)
class GateResult:
    passed: bool
    conditions: tuple[ConditionResult, ...]
    note: str = ""

    def failing(self) -> tuple[str, ...]:
        return tuple(c.condition_id for c in self.conditions if not c.passed)

    def to_dict(self) -> dict[str, Any]:
        return {"module_version": MODULE_VERSION, "passed": self.passed, "failing": list(self.failing()),
                "conditions": [c.to_dict() for c in self.conditions], "note": self.note}


def _p0_condition(cid: str, name: str, confirmed: list[FindingView], ok, detail_ok: str, detail_bad: str) -> ConditionResult:
    offenders = tuple(f.finding_id for f in confirmed if not ok(f))
    passed = not offenders
    return ConditionResult(cid, name, passed, offenders, detail_ok if passed else detail_bad)


def evaluate(*, observed_scenarios: Iterable[Any] | None,
             findings: list[FindingView] | None) -> GateResult:
    """Run all five conditions. FAIL-CLOSED: `None` inputs fail their condition."""
    conditions: list[ConditionResult] = []

    # QG-1: scenario coverage (ZR-031). None -> fail-closed.
    if observed_scenarios is None:
        conditions.append(ConditionResult("QG-1", "scenario_coverage", False, (),
                                           "FAIL-CLOSED: no observed-scenario set supplied"))
    else:
        missing = scenario_registry.unmet(observed_scenarios)
        conditions.append(ConditionResult(
            "QG-1", "scenario_coverage", not missing,
            tuple(f"{s.oracle_class}@{s.scope}" for s in missing),
            "all ZR-031 required scenarios exercised" if not missing else f"{len(missing)} required scenario(s) unmet"))

    # QG-2..5: over CONFIRMED_P0 findings. None findings -> fail-closed on all four.
    if findings is None:
        for cid, name in (("QG-2", "schema_complete"), ("QG-3", "server_confirmed"),
                          ("QG-4", "reproducible"), ("QG-5", "regression_referenced")):
            conditions.append(ConditionResult(cid, name, False, (), "FAIL-CLOSED: no findings supplied"))
    else:
        confirmed = [f for f in findings if f.verdict == _P0]
        conditions.append(_p0_condition("QG-2", "schema_complete", confirmed,
                                        lambda f: f.schema_completeness >= _COMPLETE,
                                        "every CONFIRMED_P0 is schema-complete (ZR-019)",
                                        "CONFIRMED_P0 finding(s) below schema_completeness 1.0"))
        conditions.append(_p0_condition("QG-3", "server_confirmed", confirmed,
                                        lambda f: f.server_confirmed,
                                        "no CONFIRMED_P0 rests on a client signal alone (ZR-016)",
                                        "CONFIRMED_P0 finding(s) not server-confirmed"))
        conditions.append(_p0_condition("QG-4", "reproducible", confirmed,
                                        lambda f: f.has_reproduction,
                                        "every CONFIRMED_P0 has a reproduction bundle (ZR-015)",
                                        "CONFIRMED_P0 finding(s) without reproduction"))
        conditions.append(_p0_condition("QG-5", "regression_referenced", confirmed,
                                        lambda f: f.has_regression_reference,
                                        "every CONFIRMED_P0 has a regression reference (ZR-023)",
                                        "CONFIRMED_P0 finding(s) without a regression reference"))

    passed = all(c.passed for c in conditions)
    return GateResult(passed, tuple(conditions),
                      "5-condition final quality gate (ZR-033); all must pass, fail-closed on missing evidence")


def evaluate_payload(*, observed_scenarios: Iterable[Any] | None,
                     findings: list[FindingView] | None) -> dict[str, Any]:
    return evaluate(observed_scenarios=observed_scenarios, findings=findings).to_dict()
