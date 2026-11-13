"""Attack-layer agents (A8, A9, A11, A38) over the existing bounded capabilities.

Each wraps a pure capability already built + tested and emits LEADS for the planner
and the pre-registered oracles -- never a finding (ZR-017 still confirms separately).

  A8  Differential Testing            -> differencer.report (cross-surface consistency;
                                         a divergence is a trust defect, never a P0)
  A9  Business-Logic Hypothesis       -> contract_inference.infer (observed condition ->
                                         server-outcome clauses; a lead, never a verdict)
  A11 Race & State-Transition         -> race_window.detect (TOCTOU window) + a bounded,
                                         deterministic illegal-transition check (observed
                                         minus allowed), mirroring the STATE-002 rule as a
                                         pre-execution lead
  A38 Symbolic-Solver                 -> symbolic_solver.solve_for_violation (bounded,
                                         contract-consistent counterexamples to probe)

No agent widens what its capability allows; all outputs are leads. Stdlib only; pure.
"""
from __future__ import annotations

from typing import Any

from app.testing.agents.base import Agent
from app.testing.integrity import contract_inference, differencer, race_window, symbolic_solver


class DifferentialTestingAgent(Agent):
    agent_id, name, role = "A8", "Differential Testing", "attack"

    def _run(self, *, subjects: list[differencer.SubjectSurfaces]) -> tuple[str, dict[str, Any], list[str]]:
        rep = differencer.report(subjects)
        leads = [f"trust-defect lead on {k} (cross-surface divergence)" for k in rep["trust_defects"]]
        return f"{len(rep['trust_defects'])} trust defect(s), {len(rep['inconclusive'])} inconclusive", rep, leads


class BusinessLogicHypothesisAgent(Agent):
    agent_id, name, role = "A9", "Business-Logic Hypothesis", "attack"

    def _run(self, *, observations: list[contract_inference.AccessObservation], min_support: int = 2) \
            -> tuple[str, dict[str, Any], list[str]]:
        clauses = contract_inference.infer(observations, min_support=min_support)
        by = {s: [c for c in clauses if c.status.value == s] for s in ("INFERRED", "CONFLICTED", "INSUFFICIENT")}
        leads = [f"hypothesis: {dict(c.antecedent)} -> {c.inferred_outcome.value}" for c in by["INFERRED"]]
        leads += [f"non-determinism lead: {dict(c.antecedent)} gave both outcomes" for c in by["CONFLICTED"]]
        return f"{len(by['INFERRED'])} inferred, {len(by['CONFLICTED'])} conflicted, {len(by['INSUFFICIENT'])} insufficient", \
            {"clauses": [c.to_dict() for c in clauses]}, leads


class RaceStateTransitionAgent(Agent):
    agent_id, name, role = "A11", "Race and State-Transition Analysis", "attack"

    def _run(self, *, operations: list[race_window.Operation], quota: int,
             observed_transitions: list[Any] | None = None,
             allowed_transitions: list[Any] | None = None) -> tuple[str, dict[str, Any], list[str]]:
        race = race_window.detect(operations, quota=quota)
        allowed = {tuple(t) for t in (allowed_transitions or [])}
        seen = [tuple(t) for t in (observed_transitions or [])]
        illegal = sorted({f"{a}->{b}" for (a, b) in seen if (a, b) not in allowed})
        leads: list[str] = []
        if race.status is race_window.RaceStatus.WINDOW_FOUND:
            leads.append(f"race-window lead: probe PBB-C at concurrency {race_window.suggest_probe_concurrency(quota)}")
        leads += [f"illegal-transition lead: {t} (not in the allowed set; confirm with STATE-002)" for t in illegal]
        data = {"race": race.to_dict(),
                "suggested_probe_concurrency": race_window.suggest_probe_concurrency(quota),
                "illegal_transitions": illegal}
        return f"race {race.status.value}; {len(illegal)} illegal transition(s)", data, leads


class SymbolicSolverAgent(Agent):
    agent_id, name, role = "A38", "Symbolic-Solver Agent", "attack"

    def _run(self, *, variables: list[symbolic_solver.Variable],
             implications: list[symbolic_solver.Implication],
             violation: tuple[tuple[str, Any], ...]) -> tuple[str, dict[str, Any], list[str]]:
        res = symbolic_solver.solve_for_violation(variables, implications, violation=violation)
        leads = [f"probe condition: {c}" for c in res.to_dict()["counterexamples"][:3]]
        return f"{res.status.value}: {len(res.counterexamples)} counterexample(s)", res.to_dict(), leads


AGENTS: tuple[Agent, ...] = (
    DifferentialTestingAgent(), BusinessLogicHypothesisAgent(),
    RaceStateTransitionAgent(), SymbolicSolverAgent(),
)
