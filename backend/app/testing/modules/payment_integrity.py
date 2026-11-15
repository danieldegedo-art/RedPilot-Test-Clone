"""Payment Integrity (Pure Black-Box Protected-Feature Oracle engine) -- the product module around app/testing/integrity/engine.py.

PURE BLACK-BOX: the module knows only what an authorised external customer-level tester knows (the Execution Brief) and proves things
only by USING server-enforced paid features as synthetic identities. It reads no target logs/DB/dashboards/admin APIs, signs no provider
webhooks, holds no target secrets and never calls internal routes (the purity gate in ScopeGuard would refuse them anyway).

Opt-in by BRIEF: with no valid Execution Brief this module sends NOT ONE request; it only emits the capability-gap register so the P0
classes nobody tested show up as BLOCKED in every run. With a valid brief it runs the experiments through a guarded client that shares
the run's ScopeGuard (host allowlist, request budget, rate limit, kill switch, purity gate) but carries NO run-level cookies/headers:
every request is authenticated only by the synthetic identity's own token, so a 'clean session' really is clean.

Status mapping (never PASS unless a hypothesis was actually RULED OUT):
  CONFIRMED_P0 -> FAIL | PARTIALLY_VALIDATED / SUSPECTED / UNKNOWN / BLOCKED -> WARNING | RULED_OUT -> PASS (WARNING when a UI/redirect divergence was observed)
"No confirmed P0" never means "no P0 exists": the summary result repeats that and lists what was NOT tested.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.core.control_port import BriefRejected, get_control_adapter
from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus, TestCategory
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import FLOW_BY_HYPOTHESIS, PureBlackBoxEngine
from app.testing.integrity.evidence_graph import EvidenceGraph, artifact_timestamps_from_ledger, evidence_graph_for_finding
from app.testing.integrity.findings import Finding
from app.testing.integrity.gaps import GapRow, capability_gaps, unknown_exposures
from app.testing.integrity.coverage import coverage_matrix  # ZR-006/ZR-022: multi-dimensional coverage in the summary
from app.testing.integrity.completion_report import build_completion_report  # ZR-034: engagement completion report
from app.testing.integrity.regression import build_regression_spec
from app.testing.pesm import record_oracle_observations
from app.testing.prioritization import Prioritizer

logger = logging.getLogger("qa.modules.payment_integrity")
from app.testing.models import TestResult
from app.testing.purity.taxonomy import Verdict

_STATUS = {Verdict.CONFIRMED_P0: ResultStatus.FAIL, Verdict.RULED_OUT: ResultStatus.PASS}


def host_permitted(base_url: str, allowed_hosts: tuple[str, ...]) -> bool:
    """Is the run's target host approved by the brief? The decision is an Enterprise Control (enterprise_controls/brief_validation.py)."""
    return get_control_adapter().host_permitted(base_url, allowed_hosts)


async def build_prioritizer(enabled: bool, brief_fingerprint: str) -> Prioritizer | None:
    """ZR-003/ZR-007/ZR-012, gated by RunSettings.prioritize_experiments (off by
    default). Extracted to its own function, rather than left inline in run()
    below, specifically so it is callable without a live target or a database --
    see tests/test_payment_integrity_prioritizer_wiring.py.

    The db import is local and lazy, not at module level: this keeps
    PaymentIntegrityModule importable without sqlalchemy installed when the
    setting is off (today's default, and every existing deployment until
    someone turns this on), matching the control-port's own established
    pattern for an optional capability (core/control_port/__init__.py's loader).
    A missing dependency, or any other failure building the prioritizer, is
    logged and this returns None -- the engine then runs the static order,
    exactly as it does today; one optional ordering signal must never be able
    to stop a run.
    """
    if not enabled:
        return None
    try:
        from app.db.memory import row_source_for
        from app.testing.run_memory import load_prior_findings, prioritizer_from_priors

        priors = await load_prior_findings(row_source_for(brief_fingerprint), brief_fingerprint=brief_fingerprint)
        if priors.degraded:
            logger.warning("prior findings unavailable (%s); scheduling without them", priors.degraded_reason)
        return prioritizer_from_priors(priors, flow_of=FLOW_BY_HYPOTHESIS)
    except Exception:
        logger.exception("could not build the experiment prioritizer; running the static order")
        return None


async def build_feature_registry(*, prefer_durable: bool = True):
    """ZR-002/ZR-007 wiring: construct the PESM store for a run. Prefers the durable
    SQLAlchemy-backed store (`app/db/pesm_store.py`) and lazy-imports it -- so this
    module stays importable without sqlalchemy -- falling back to the in-memory store
    on ImportError or any construction failure. Same fail-safe, optional-capability
    pattern as build_prioritizer above: it never raises and always returns a usable
    PESMStore, so the entitlement-state recording below is wired either way.

    (The durable branch cannot execute in a sandbox without sqlalchemy; the in-memory
    fallback path it returns there is the one under test -- see
    tests/test_feature_registry_wiring.py.)
    """
    if prefer_durable:
        try:
            from app.db.pesm_store import SQLAlchemyPESMStore
            return SQLAlchemyPESMStore()
        except Exception as exc:  # ImportError (no sqlalchemy) or any construction fault
            logger.warning("durable PESM store unavailable (%s); using the in-memory PESM store", exc)
    from app.testing.pesm import InMemoryPESMStore
    return InMemoryPESMStore()


class PaymentIntegrityModule(BaseTestModule):
    module_id = "payment_integrity"
    display_name = "Payment Integrity (Pure Black-Box Protected-Feature Oracle)"
    category = TestCategory.PAYMENT_INTEGRITY

    def _result(self, test_case_id: str, name: str, status: ResultStatus, expected: str, actual: str, params: dict[str, Any],
                recommendation: str | None = None, description: str = "") -> TestResult:
        now = datetime.now(timezone.utc)
        return TestResult(test_case_id=test_case_id, category=TestCategory.PAYMENT_INTEGRITY, name=name, description=description or name, input_parameters=params,
                          expected=expected, actual=actual, status=status, recommendation=recommendation, started_at=now, finished_at=now, duration_ms=0.0)

    def _gap_result(self, rows: list[GapRow], headline: str) -> TestResult:
        open_rows = unknown_exposures(rows)
        return self._result(
            "PI-CAPABILITY-GAP", f"Payment-integrity capability gaps: {len(open_rows)} P0 class(es) not covered", ResultStatus.WARNING,
            expected="Every critical payment-to-entitlement class is either tested or explicitly listed as UNKNOWN/BLOCKED.",
            actual=f"{headline}. {len(open_rows)} of {len(rows)} P0 classes are NOT covered in this run -- UNKNOWN/BLOCKED, not safe.",
            params={"capability_gaps": [r.to_dict() for r in open_rows]}, recommendation="; ".join(dict.fromkeys(r.smallest_safe_next_capability for r in open_rows)) or None)

    def _recommendation(self, f: Finding) -> str | None:
        if f.verdict == Verdict.CONFIRMED_P0:
            return ("Release-blocking. Externally reproduced under clean authorised conditions with a server-enforced protected-feature oracle; the internal cause is UNKNOWN (never inferred). "
                    "After the fix this experiment must turn RULED_OUT on re-run (the regression spec is in the summary result).")
        if f.verdict == Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE:
            return f"Not a confirmed P0: {'; '.join(f.reasons) or 'a confirmation condition is missing'}. Provide the missing external input or confirm manually."
        if f.verdict in (Verdict.UNKNOWN, Verdict.BLOCKED):
            return f"This P0 class remains {f.verdict.value} (not safe): {f.summary} Smallest safe improvement: resolve the stated barrier in the Execution Brief/environment and re-run."
        if f.divergences:
            return "No P0 (server-enforced behaviour is correct), but customer-visible pages mislead: " + "; ".join(f.divergences)
        return None

    def _finding_result(self, f: Finding, fingerprint: str, graph: EvidenceGraph | None = None) -> TestResult:
        status = _STATUS.get(f.verdict, ResultStatus.WARNING)
        if f.verdict == Verdict.RULED_OUT and f.divergences:
            status = ResultStatus.WARNING
        return self._result(
            f"PI-{f.hypothesis_id}", f"[{f.verdict.value}] {f.hypothesis_id} ({f.p0_class}): {f.title}", status, expected=f.spec.expected_outcome, actual=f.summary,
            params={"_integrity": f.to_dict(), "brief_fingerprint": fingerprint, **({"evidence_graph": graph.to_dict()} if graph is not None else {})},
            recommendation=self._recommendation(f), description=f.spec.invariant)

    async def run(self) -> None:
        raw = self.context.settings.integrity_brief
        if raw is None:
            await self.emit(self._gap_result(capability_gaps(None, None), "No Execution Brief is declared for this run, so NO experiment ran and NO request was sent"))
            return
        if "__load_error__" in raw:
            await self.emit(self._result("PI-BRIEF-UNREADABLE", "Execution Brief could not be read", ResultStatus.ERROR, expected="A readable JSON Execution Brief.", actual=str(raw["__load_error__"]), params={},
                                         recommendation="Fix the brief file. No experiment was run and NO request was sent to the target."))
            await self.emit(self._gap_result(capability_gaps(None, None), "The declared brief is unreadable"))
            return
        try:
            brief = ExecutionBrief.from_dict(raw)
        except BriefRejected as exc:
            await self.emit(self._result("PI-BRIEF-INVALID", "Execution Brief rejected (fail closed)", ResultStatus.ERROR, expected="A valid, authorised, customer-level, sandbox-scoped Execution Brief.",
                                         actual="; ".join(str(r) for r in exc.reasons), params={"reasons": [r.__dict__ for r in exc.reasons]},
                                         recommendation="Fix the brief. Secrets, admin/staff credentials, internal URLs, hints and hidden-route lists are refused by design. No experiment was run and NO request was sent."))
            await self.emit(self._gap_result(capability_gaps(None, None), "The declared brief was rejected"))
            return
        if not host_permitted(self.context.base_url, brief.allowed_hosts):
            await self.emit(self._result("PI-BRIEF-HOST", "Target host is outside the brief's approved hosts", ResultStatus.ERROR, expected="The run's target host is listed in the brief's allowed_hosts.",
                                         actual=f"{self.context.base_url} is not covered by allowed_hosts={list(brief.allowed_hosts)}", params={"allowed_hosts": list(brief.allowed_hosts)},
                                         recommendation="Add the host to the brief (only if it is truly authorised) or fix the run's environment URL. No request was sent."))
            await self.emit(self._gap_result(capability_gaps(None, None), "The brief does not authorise this target"))
            return

        # Always guarded: the run's shared ScopeGuard, or (bare unit-test contexts only) one built from the brief's own limits -- the purity gate is never skipped.
        controls = get_control_adapter()
        guard = self.context.guard or controls.create_run_guard(controls.build_scope_policy(self.context.base_url, max_requests=brief.limits.max_requests, max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base_url=self.context.base_url, timeout_seconds=brief.limits.timeout_seconds, proxy_url=self.context.settings.proxy_url, headers={},
                            user_agent="qa-pure-black-box-engine/1.0", max_retries=0, guard=guard, stateless=True)
        fingerprint = brief.fingerprint()
        if self.context.feature_registry is None:
            # ZR-002/ZR-007 wiring: ensure a PESM store exists so the entitlement-state
            # recording below is live (durable SQLAlchemy store when available, in-memory
            # fallback otherwise). Fail-safe: build_feature_registry never raises.
            self.context.feature_registry = await build_feature_registry()
        prioritizer = await build_prioritizer(self.context.settings.prioritize_experiments, fingerprint)
        observations: list = []
        admission_order: list[str] = []
        artifact_stamps: dict = {}
        try:
            engine = PureBlackBoxEngine(
                http, brief, base_url=self.context.base_url, prioritizer=prioritizer,
                enable_channel_probe=True, enable_chain_probe=True, find_fast=False,
                enable_race_probe=True, race_burst=24,
                enable_convergence_probe=True, convergence_use_schema=True, convergence_concurrent=True,
                enable_fabric_probe=True, fabric_use_dag=True, fabric_use_race=True,
                fabric_multi_candidate=True, fabric_fresh_challenge=True,
                enable_reconciliation_probe=True, recon_use_lifecycle=True,
                recon_use_overlay=True, recon_use_sequence=True,
                enable_federation=True, fed_use_discovery=True, fed_use_token_re=True,
                fed_use_trust_graph=True, fed_use_orchestration=True,
                fed_use_analogy=True, fed_use_infogain=True,
                enable_behavior_probe=True, enable_greybox_probe=True,
                enable_cold_discovery=True, enable_replay_probe=True,
                enable_crosssubject_probe=True,
            )
            outcome = await engine.run()
            observations = list(engine.oracle.observations)
            admission_order = list(engine.ledger.accepted)  # dicts keep insertion order: the ledger's own admission order
            artifact_stamps = artifact_timestamps_from_ledger(engine.ledger.accepted)
            if self.context.feature_registry is not None:
                # ZR-002 / A5: model this run's oracle observations as entitlement-state
                # snapshots. Advisory, like build_prioritizer above -- one broken optional
                # write must never take the run's actual findings down with it.
                try:
                    await record_oracle_observations(engine.oracle.observations, self.context.feature_registry, recorded_at=datetime.now(timezone.utc))
                except Exception:
                    logger.exception("could not record entitlement-state snapshots to PESM; findings are unaffected")
        finally:
            await http.aclose()
        chains: dict[str, dict] = {}
        for finding in outcome.findings:
            graph: EvidenceGraph | None
            try:
                graph = evidence_graph_for_finding(finding.hypothesis_id, finding.artifact_ids, observations=observations,
                                                   admission_order=admission_order, artifact_timestamps=artifact_stamps)
                chains[finding.hypothesis_id] = {"completeness": round(graph.completeness(), 4), "nodes": len(graph.nodes), "unlinked": graph.unlinked_nodes()}
            except Exception:  # advisory: a graph failure must never cost the finding itself
                logger.exception("could not build the evidence graph for %s; the finding is emitted without it", finding.hypothesis_id)
                graph = None
            await self.emit(self._finding_result(finding, fingerprint, graph))

        counts = Counter(f.verdict.value for f in outcome.findings)
        rows = capability_gaps(brief, outcome)
        open_rows = unknown_exposures(rows)
        not_tested = [f"{f.hypothesis_id}: {f.summary}" for f in outcome.findings if f.verdict in (Verdict.UNKNOWN, Verdict.BLOCKED)]
        confirmed = counts.get(Verdict.CONFIRMED_P0.value, 0)
        clean = all(f.verdict == Verdict.RULED_OUT and not f.divergences for f in outcome.findings)
        await self.emit(self._result(
            "PI-SUMMARY", "Payment-integrity summary", ResultStatus.FAIL if confirmed else (ResultStatus.PASS if clean and not open_rows else ResultStatus.WARNING),
            expected="Every experiment ends RULED_OUT and no P0 class is left uncovered.",
            actual=(f"{confirmed} confirmed P0, verdicts={dict(counts)}. 'No confirmed P0' never means 'no P0 exists': {len(open_rows)} P0 class(es) are not COVERED in this run "
                    f"(incl. provider-event authenticity and concurrency, which a pure black-box tester cannot test) and {len(not_tested)} experiment(s) ended UNKNOWN/BLOCKED."),
            params={"verdict_counts": dict(counts), "not_tested": not_tested, "capability_gaps": [r.to_dict() for r in open_rows], "coverage_matrix": coverage_matrix(outcome).to_dict(), "brief": brief.to_public_dict(), "evidence": outcome.ledger_summary,
                    "engine_stats": outcome.stats, "evidence_chains": chains, "regression_spec": build_regression_spec(outcome, brief), "controls": outcome.controls,
                    "black_box_purity_attestation": {"source_code_used": False, "repository_access_used": False, "database_access_used": False, "server_log_access_used": False,
                                                     "admin_or_privileged_access_used": False, "internal_api_access_used": False, "payment_provider_dashboard_used": False,
                                                     "real_customer_data_used": False, "external_evidence_only": True, "internal_causal_claims_made": False}},
            recommendation=None if clean and not open_rows else "Work the CONFIRMED_P0 findings first, then resolve every stated barrier for the UNKNOWN/BLOCKED classes."))

        # ZR-034: the Standard Engagement Completion Report -- the delivery artifact for a direct engagement,
        # generated at the end of every engagement (Section 15.1). Same source of truth as PI-SUMMARY, rendered
        # in the fixed seven-section format incl. the mandatory Not-Implemented section (no clean-by-omission).
        report = build_completion_report(outcome, brief)
        await self.emit(self._result(
            "PI-COMPLETION-REPORT", "Engagement Completion Report (ZR-034)",
            ResultStatus.FAIL if confirmed else (ResultStatus.PASS if clean and not open_rows else ResultStatus.WARNING),
            expected="A complete seven-section engagement report: Summary / Requirements-Matrix / Implemented-Changes / Coverage / Findings / Verification / Not-Implemented.",
            actual=f"status={report['summary']['status']}; {report['summary']['confirmed_p0']} confirmed P0; {len(report['not_implemented'])} class(es) in Not-Implemented.",
            params={"engagement_completion_report": report}, recommendation=None))
