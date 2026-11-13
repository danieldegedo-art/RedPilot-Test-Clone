"""Proof-layer agents (A13, A14, A15, A28, A29) over the existing proof capabilities.

Each delegates to a module already built + tested; the agent adds the uniform report
and scope preservation (base.Agent). No new capability.
  A13 Severity & Impact-Assessment -> impact_assessment.assess_all
  A28 Impact Quantifier            -> impact_assessment (quantified rollup)
  A14 Duplicate & Novelty          -> dedup (own-history novelty, §7.2)
  A15 Report-Generation            -> narrative.report
  A29 Chain-Trace Renderer         -> narrative.narrate_chain
Stdlib only; pure.
"""
from __future__ import annotations

from typing import Any

from app.testing.agents.base import Agent
from app.testing.integrity import dedup, impact_assessment, narrative


class SeverityImpactAgent(Agent):
    agent_id, name, role = "A13", "Severity and Impact-Assessment", "proof"

    def _run(self, *, findings: list[dict[str, Any]]) -> tuple[str, dict[str, Any], list[str]]:
        out = impact_assessment.assess_all(findings)
        return f"severity: {out['severity_counts']}", out, []


class ImpactQuantifierAgent(Agent):
    agent_id, name, role = "A28", "Impact Quantifier", "proof"

    def _run(self, *, findings: list[dict[str, Any]]) -> tuple[str, dict[str, Any], list[str]]:
        out = impact_assessment.assess_all(findings)
        counts = out["severity_counts"]
        crit, high = counts.get("critical", 0), counts.get("high", 0)
        return f"{crit} critical, {high} high", {"severity_counts": counts}, []


class NoveltyAgent(Agent):
    agent_id, name, role = "A14", "Duplicate and Novelty-Analysis", "proof"

    def _run(self, *, findings: list[dict[str, Any]]) -> tuple[str, dict[str, Any], list[str]]:
        reg = dedup.NoveltyRegister()
        novel: list[str] = []
        duplicate: list[str] = []
        rows: list[dict[str, Any]] = []
        for f in findings:
            fp = dedup.fingerprint(f.get("issue_class"), f.get("flow"), f.get("target"))
            nov = reg.assess(fp)
            (novel if nov.is_novel else duplicate).append(f.get("id", fp.digest))
            rows.append(nov.to_dict())
            reg.register(fp)
        return f"{len(novel)} novel, {len(duplicate)} duplicate (own §7.2 history)", \
            {"novel": novel, "duplicate": duplicate, "assessments": rows}, []


class ReportAgent(Agent):
    agent_id, name, role = "A15", "Report-Generation", "proof"

    def _run(self, *, findings: list[dict[str, Any]], chains: list[dict[str, Any]] | None = None) \
            -> tuple[str, dict[str, Any], list[str]]:
        rep = narrative.report(findings, chains)
        return rep["headline"], rep, []


class ChainTraceAgent(Agent):
    agent_id, name, role = "A29", "Chain-Trace Renderer", "proof"

    def _run(self, *, chains: list[dict[str, Any]]) -> tuple[str, dict[str, Any], list[str]]:
        traces = [narrative.narrate_chain(c) for c in chains]
        return f"{len(traces)} chain(s) rendered", {"traces": traces}, []


AGENTS: tuple[Agent, ...] = (
    SeverityImpactAgent(), ImpactQuantifierAgent(), NoveltyAgent(), ReportAgent(), ChainTraceAgent(),
)
