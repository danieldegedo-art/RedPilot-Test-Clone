"""Learning / planning / orchestration agents (A19, A30, A39, A20).

Each wraps a capability already built + tested and returns a uniform `AgentReport`.
The generation-cluster delegates stay FAIL-CLOSED (A30) and the planners emit plans
and leads only -- nothing here runs an experiment (ZR-017 still confirms separately).

  A19 Feedback-Learning (learning)      -> feedback_loop.fold (bounded per-hypothesis
                                           state fold; never invents a target, B28)
  A30 Capability-Synthesis (learning)   -> capability_synthesis.synthesize (FAIL-CLOSED;
                                           parameterises a pre-registered template only)
  A39 Graph-Analyst (planning)          -> chokepoints.chokepoint_report (remediation
                                           ranking over a finished run; never a verdict)
  A20 Orchestrator/Fleet Coordinator    -> the full planning pipeline over THREE
      (orchestration)                      capabilities: prioritization.schedule (order)
                                           -> fleet_orchestration.orchestrate (dependency
                                           waves, FAIL-CLOSED) + kill_chain_roster (fleet
                                           composition). Produces a schedule, runs nothing.

Stdlib only; pure.
"""
from __future__ import annotations

from typing import Any

from app.testing import prioritization
from app.testing.agents.base import Agent
from app.testing.integrity import (
    capability_synthesis, chokepoints, feedback_loop, fleet_orchestration,
    kill_chain_roster as roster,
)


class FeedbackLearningAgent(Agent):
    agent_id, name, role = "A19", "Feedback-Learning", "learning"

    def _run(self, *, events: list[feedback_loop.FeedbackEvent], registered: set[str],
             states: dict[str, feedback_loop.HypothesisState] | None = None) \
            -> tuple[str, dict[str, Any], list[str]]:
        res = feedback_loop.fold(dict(states or {}), events, registered=set(registered))
        leads = [f"ruled out (demoted, never skipped): {hid}" for hid, st in sorted(res.states.items()) if st.ruled_out]
        return f"{len(res.applied)} event(s) folded, {len(res.skipped_duplicates)} duplicate(s) skipped", \
            res.to_dict(), leads


class CapabilitySynthesisAgent(Agent):
    agent_id, name, role = "A30", "Capability-Synthesis Agent", "learning"

    def _run(self, *, enabled: bool, conclusive: set[str] | None = None,
             prior: dict[str, float] | None = None,
             declared_params: dict[str, Any] | None = None) -> tuple[str, dict[str, Any], list[str]]:
        res = capability_synthesis.synthesize(enabled=enabled, conclusive=conclusive, prior=prior,
                                              declared_params=declared_params)
        leads = []
        if res.status is capability_synthesis.SynthStatus.SYNTHESIZED and res.probe is not None:
            leads = [f"run pre-registered probe {res.probe.template_id} {res.probe.params} (ZR-017 confirms)"]
        return res.status.value, res.to_dict(), leads


class GraphAnalystAgent(Agent):
    agent_id, name, role = "A39", "Graph-Analyst Agent", "planning"

    def _run(self, *, result: Any) -> tuple[str, dict[str, Any], list[str]]:
        rep = chokepoints.chokepoint_report(result)
        fix = rep["summary"]["highest_leverage_fix"]
        leads = [f"highest-leverage remediation: fix {c} (proven flawed)" for c in rep["summary"]["proven_flawed"]]
        return f"highest-leverage fix: {fix}", rep, leads


class OrchestratorAgent(Agent):
    agent_id, name, role = "A20", "Orchestrator/Fleet Coordinator", "orchestration"

    def _run(self, *, hypotheses: list[str], enabled: bool = True, max_workers: int = 4,
             weights: dict[str, float] | None = None,
             prior_verdicts: dict[str, Any] | None = None,
             flow_of: dict[str, str] | None = None) -> tuple[str, dict[str, Any], list[str]]:
        sched = prioritization.schedule(hypotheses, weights=weights, prior_verdicts=prior_verdicts, flow_of=flow_of)
        order = list(sched.order)
        deps = fleet_orchestration.dependencies_from_catalog(order)
        plan = fleet_orchestration.orchestrate(order, enabled=enabled, max_workers=max_workers, dependencies=deps)
        all_agents = roster.roster()
        activatable = [a.agent_id for a in all_agents if roster.is_activatable(a.agent_id)]
        out_of_scope = sorted(a.agent_id for a in roster.out_of_scope())
        data = {
            "priority_order": order,
            "plan": plan.to_dict(),
            "fleet": {"declared_fleet_size": roster.FLEET_SIZE, "in_roster": len(all_agents),
                      "activatable": len(activatable), "out_of_scope": out_of_scope},
        }
        return f"{len(order)} hypotheses -> {len(plan.waves)} wave(s); " \
            f"{len(activatable)} agents activatable, {len(out_of_scope)} out of scope", data, []


AGENTS: tuple[Agent, ...] = (
    FeedbackLearningAgent(), CapabilitySynthesisAgent(), GraphAnalystAgent(), OrchestratorAgent(),
)
