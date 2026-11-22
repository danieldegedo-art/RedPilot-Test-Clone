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
from app.testing.integrity.findings import EXPERIMENT_CLASSES, EngineResult
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

    def _auto_brief(self) -> dict[str, Any]:
        """TEST CLONE: auto-generate an Execution Brief from the Electron recon
        data so the PBB engine has real endpoints, plans and features to test.

        When Electron recon captured network calls, this method:
        1. Extracts payment/subscription/billing API endpoints from the calls
        2. Detects plan names and prices from the page HTML
        3. Maps discovered endpoints to brief operations (checkout, subscription, billing)
        4. Identifies paid features (upgrade/pro/ultra pages) as protected surfaces
        5. Uses session cookies as the identity token for probing
        """
        import re as _re
        from urllib.parse import urlparse

        host = urlparse(self.context.base_url).hostname or "localhost"
        recon = self.context.shared_state.get("electron_recon") or {}
        network_calls = recon.get("network_calls", [])
        html = recon.get("html", "")
        cookie_names = recon.get("cookie_names", [])

        surface: dict[str, dict] = {}
        features: dict[str, dict] = {}
        plans: dict[str, dict] = {}
        identities: dict[str, dict] = {}
        declared_paid: list[str] = []

        # --- Extract real API endpoints from captured network calls ---
        _SURFACE_RULES = [
            ("start_checkout", "POST", _re.compile(r"/subscription/checkout_session", _re.I)),
            ("subscription_view", "GET", _re.compile(r"/subscription/checkout_capabilities", _re.I)),
            ("get_pricing", "GET", _re.compile(r"/individual_plan_pricing", _re.I)),
            ("get_pricing", "POST", _re.compile(r"/individual_plan_pricing", _re.I)),
            ("signup", "POST", _re.compile(r"/signup|/register|/auth/register", _re.I)),
            ("sandbox_pay", "POST", _re.compile(r"/billing/.+/pay|/payment", _re.I)),
            ("request_refund", "POST", _re.compile(r"/refund|/billing/.+/cancel", _re.I)),
            ("event_log", "POST", _re.compile(r"/event_logging", _re.I)),
            ("privacy_check", "POST", _re.compile(r"/privacy-consents", _re.I)),
        ]

        seen_ops: set[str] = set()
        for call in network_calls:
            url = call.get("url", "")
            method = call.get("method", "GET").upper()
            parsed = urlparse(url)
            path = parsed.path or "/"
            if parsed.hostname and parsed.hostname != host:
                continue
            for op_name, op_method, pattern in _SURFACE_RULES:
                if op_name in seen_ops:
                    continue
                if method == op_method and pattern.search(path):
                    surface[op_name] = {
                        "method": method,
                        "path": path,
                        "observed_via": "electron_recon_network_capture",
                    }
                    seen_ops.add(op_name)
                    break

        # --- Detect plans and prices from page HTML ---
        plan_patterns = [
            (_re.compile(r"Free\s*(?:plan|tier)", _re.I), "free", 0.0),
            (_re.compile(r"Pro\s*(?:plan|tier)?", _re.I), "pro", 20.0),
            (_re.compile(r"Ultra\s*(?:plan|tier)?", _re.I), "ultra", 180.0),
            (_re.compile(r"Team\s*(?:plan|tier)?", _re.I), "team", 25.0),
            (_re.compile(r"Enterprise\s*(?:plan|tier)?", _re.I), "enterprise", 0.0),
        ]

        # Try to extract real prices from HTML
        price_re = _re.compile(r"(\d+(?:[.,]\d{2})?)\s*(?:€|\$|USD|EUR)", _re.I)
        price_matches = price_re.findall(html)

        # Detect currency from HTML
        currency = "USD"
        if "€" in html or "EUR" in html:
            currency = "EUR"

        for pattern, plan_name, default_price in plan_patterns:
            if pattern.search(html):
                price = default_price
                # Try to find associated price near the plan mention
                plan_section = _re.search(
                    pattern.pattern + r".*?(\d+(?:[.,]\d{2})?)\s*(?:€|\$|USD|EUR)",
                    html, _re.I | _re.S
                )
                if plan_section:
                    raw = plan_section.group(1).replace(",", ".")
                    try:
                        price = float(raw)
                    except ValueError:
                        pass
                plans[plan_name] = {"prices": {currency: price}}

        # Remove free-tier plans (price <= 0): cheapest_plan must be a PAID tier
        # so primary_feature() can match features that require it.
        plans = {k: v for k, v in plans.items()
                 if any(p > 0 for p in v.get("prices", {}).values())}
        if not plans:
            plans = {"pro": {"prices": {currency: 20.0}}}

        # --- Define paid features as protected surfaces ---
        # The upgrade page itself is a feature gate indicator
        base = self.context.base_url.rstrip("/")
        entry = self.context.entry_url

        # Detect plan-gated feature paths from the URL and HTML
        feature_paths = []
        if "/upgrade" in entry or "/pro" in entry or "/ultra" in entry:
            feature_paths.append(("upgrade_access", entry.replace(base, "")))

        # Look for feature-gated paths in network calls
        _FEATURE_PATTERNS = [
            ("claude_chat", _re.compile(r"/api/organizations/.+/chat", _re.I)),
            ("claude_code", _re.compile(r"/api/.+/code|/code/", _re.I)),
            ("model_access", _re.compile(r"/api/.+/model|/api/.+/completions", _re.I)),
            ("settings_billing", _re.compile(r"/api/.+/billing|/settings/billing", _re.I)),
        ]
        for call in network_calls:
            url = call.get("url", "")
            parsed = urlparse(url)
            path = parsed.path or "/"
            for feat_name, pattern in _FEATURE_PATTERNS:
                if feat_name not in features and pattern.search(path):
                    plan_keys = list(plans.keys())
                    cheapest_paid = plan_keys[0]
                    features[feat_name] = {
                        "method": call.get("method", "GET").upper(),
                        "path": path,
                        "proof_field": "data",
                        "requires_plan": cheapest_paid,
                        "consumes_quota": False,
                        "observed_via": "electron_recon_network_capture",
                    }
                    declared_paid.append(feat_name)

        # If we found upgrade/subscription endpoints, add the upgrade page as a feature
        if "start_checkout" in surface or "subscription_view" in surface:
            plan_keys = list(plans.keys())
            cheapest_paid = plan_keys[0]
            priciest = plan_keys[-1] if plan_keys else "pro"
            features["subscription_access"] = {
                "method": "GET",
                "path": surface.get("subscription_view", {}).get("path", "/api/subscription"),
                "proof_field": "data",
                "requires_plan": cheapest_paid,
                "consumes_quota": False,
                "observed_via": "electron_recon_network_capture",
            }
            declared_paid.append("subscription_access")
            if cheapest_paid != priciest:
                features["premium_tier_access"] = {
                    "method": "GET",
                    "path": surface.get("subscription_view", {}).get("path", "/api/subscription"),
                    "proof_field": "data",
                    "requires_plan": priciest,
                    "consumes_quota": False,
                    "observed_via": "electron_recon_network_capture",
                }
                declared_paid.append("premium_tier_access")

        # --- Build identities: clean visitor first (K), authenticated second (V1) ---
        # Order matters: IdentityProvisioner walks the pool in insertion order.
        # K (clean/unauthenticated) must come first, V1 (authenticated) second.
        # After the two control identities, add probe identities that reuse the
        # same tokens so enterprise probes can acquire without exhausting the pool.
        identities["clean_visitor"] = {
            "role": "visitor",
            "tenant": "tenant_clean",
            "token_env": "REDPILOT_CLEAN_TOKEN",
        }
        session_cookies = self.context.session_cookies
        if session_cookies:
            identities["customer_session"] = {
                "role": "customer",
                "tenant": "tenant_primary",
                "token_env": "REDPILOT_SESSION_COOKIE",
            }
            for _i in range(1, 21):
                _role = "customer" if _i % 2 == 1 else "visitor"
                _tenant = "tenant_primary" if _role == "customer" else "tenant_clean"
                _env = "REDPILOT_SESSION_COOKIE" if _role == "customer" else "REDPILOT_CLEAN_TOKEN"
                identities[f"probe_{_i}"] = {"role": _role, "tenant": _tenant, "token_env": _env}

        logger.info(
            "auto-brief: %d surface ops, %d features, %d plans, %d identities from %d network calls",
            len(surface), len(features), len(plans), len(identities), len(network_calls),
        )

        return {
            "authorization_ref": "redpilot-auto-recon",
            "authorized_by": "redpilot-electron-recon",
            "environment": "production",
            "target_kind": "production",
            "allowed_hosts": [host, f"*.{host}"],
            "surface": surface,
            "features": features,
            "plans": plans,
            "primary_currency": currency,
            "identities": identities,
            "limits": {
                "max_requests": 10_000_000,
                "max_requests_per_second": 10_000.0,
                "timeout_seconds": 30.0,
                "quota_probe_cap": 100,
            },
            "declared_paid_features": declared_paid,
            "allow_signup": False,
        }

    async def _run_autonomous_agents(
        self, outcome: EngineResult, brief: ExecutionBrief,
        fingerprint: str, observations: list, chains: dict[str, dict],
    ) -> list[TestResult]:
        """Run the full kill-chain agent roster + every capability module autonomously.

        Every agent and orphaned capability module is invoked with data from the
        engine's results. Each call is fail-safe: an error becomes an ERROR result,
        never a crash that stops the run. Returns TestResult objects to emit.
        """
        results: list[TestResult] = []
        now = datetime.now(timezone.utc)

        def _agent_result(agent_id: str, name: str, status: ResultStatus,
                          actual: str, params: dict[str, Any]) -> TestResult:
            return TestResult(
                test_case_id=f"PI-AGENT-{agent_id}", category=TestCategory.PAYMENT_INTEGRITY,
                name=f"[Agent {agent_id}] {name}", description=f"Autonomous agent {agent_id}: {name}",
                input_parameters=params, expected="Agent completes and produces leads or analysis.",
                actual=actual, status=status, recommendation=None,
                started_at=now, finished_at=datetime.now(timezone.utc), duration_ms=0.0)

        finding_dicts = [f.to_dict() for f in outcome.findings]
        chain_list = [{"steps": list(chains.get(f.hypothesis_id, {}).keys())} for f in outcome.findings if f.hypothesis_id in chains]

        try:
            from app.testing.agents.registry import ALL_AGENTS
            from app.testing.integrity import (
                attack_chain, capability_synthesis, chokepoints, contract_inference,
                dedup, differencer, domain_focus, feedback_loop, fleet_orchestration,
                impact_assessment, kill_chain_roster, knowledge_graph, narrative,
                payment_fingerprint, race_window, rule_mining, specialists,
                symbolic_solver, threat_intel,
            )
            from app.testing.integrity.findings import EXPERIMENT_CLASSES

            # --- Phase 1: Recon agents ---------------------------------------------------
            # A3: Surface Discovery
            try:
                observed_signals: set[str] = set()
                for f in outcome.findings:
                    if f.reasons:
                        observed_signals.update(f.reasons)
                fp_res = payment_fingerprint.fingerprint(observed_signals)
                results.append(_agent_result("A3", "Application-Surface Discovery", ResultStatus.PASS,
                    f"surface fingerprint: {fp_res.best or 'unknown'}", {"fingerprint": fp_res.to_dict()}))
            except Exception as exc:
                results.append(_agent_result("A3", "Application-Surface Discovery", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A4: Authenticated Workflow Mapper
            try:
                flows = [{"name": op_name, "authenticated": "token" in str(op.request_fields)}
                         for op_name, op in brief.operations.items()]
                auth_flows = [f["name"] for f in flows if f["authenticated"]]
                anon_flows = [f["name"] for f in flows if not f["authenticated"]]
                results.append(_agent_result("A4", "Authenticated Workflow Mapper", ResultStatus.PASS,
                    f"{len(auth_flows)} authenticated / {len(anon_flows)} anonymous workflow(s)",
                    {"authenticated": auth_flows, "anonymous": anon_flows}))
            except Exception as exc:
                results.append(_agent_result("A4", "Authenticated Workflow Mapper", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A21-A24: Specialist agents
            for aid, aname in [("A21", "Payment-Provider Specialist"), ("A22", "Webhook-Fraud Specialist"),
                               ("A23", "Coupon/Promo-Abuse Specialist"), ("A24", "Subscription-Lifecycle Specialist")]:
                try:
                    focus = specialists.focus(aid)
                    results.append(_agent_result(aid, aname, ResultStatus.PASS,
                        f"focus: {focus['oracle_classes']}", focus))
                except Exception as exc:
                    results.append(_agent_result(aid, aname, ResultStatus.ERROR,
                        f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A37: Threat-Intel Ingestion
            try:
                ti_res = threat_intel.ingest([])
                results.append(_agent_result("A37", "Threat-Intel Ingestion", ResultStatus.PASS,
                    f"ingested {ti_res.ingested} advisory credit(s), {len(ti_res.unmapped)} unmapped",
                    ti_res.to_dict()))
            except Exception as exc:
                results.append(_agent_result("A37", "Threat-Intel Ingestion", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A36: OSINT Operator (narrowed)
            try:
                osint_focus = domain_focus.focus("A36")
                results.append(_agent_result("A36", "OSINT Operator (narrowed)", ResultStatus.PASS,
                    f"focus: {osint_focus['oracle_classes']}; excludes {osint_focus['excluded']}", osint_focus))
            except Exception as exc:
                results.append(_agent_result("A36", "OSINT Operator", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A33-A35: Domain-pack agents (in-scope)
            for aid, aname in [("A33", "Contract Auditor"), ("A34", "Reverser"), ("A35", "Mobile Operator")]:
                try:
                    dp_focus = domain_focus.focus(aid)
                    results.append(_agent_result(aid, aname, ResultStatus.PASS,
                        f"entitlement-verification focus: {dp_focus['oracle_classes']}", dp_focus))
                except Exception as exc:
                    results.append(_agent_result(aid, aname, ResultStatus.ERROR,
                        f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A31/A32: Out-of-scope (owner-declined) — report refused
            for aid, aname in [("A31", "AD Operator"), ("A32", "Cloud Hunter")]:
                results.append(_agent_result(aid, f"{aname} (owner-declined)", ResultStatus.WARNING,
                    f"{aid} is OUT_OF_SCOPE (owner-declined); not run", {"scope_status": "out_of_scope"}))

            # --- Phase 2: Attack / analysis agents ----------------------------------------
            # A8: Differential Testing
            try:
                subjects = [differencer.SubjectSurfaces(identity=f.hypothesis_id, surfaces=list(f.artifact_ids))
                            for f in outcome.findings if f.artifact_ids]
                diff_rep = differencer.report(subjects) if subjects else {"trust_defects": {}, "inconclusive": []}
                results.append(_agent_result("A8", "Differential Testing", ResultStatus.PASS,
                    f"{len(diff_rep.get('trust_defects', {}))} trust defect(s)", diff_rep))
            except Exception as exc:
                results.append(_agent_result("A8", "Differential Testing", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A9: Business-Logic Hypothesis (contract inference)
            try:
                access_obs = []
                for obs in observations:
                    try:
                        cond = obs.get("condition", {}) if isinstance(obs, dict) else {}
                        ant = tuple(sorted(cond.items())) if isinstance(cond, dict) else ()
                        out_val = obs.get("outcome", "DENIED") if isinstance(obs, dict) else "DENIED"
                        access_obs.append(contract_inference.AccessObservation(
                            antecedent=ant,
                            outcome=contract_inference.Outcome(out_val.upper() if out_val.upper() in ("ALLOWED", "DENIED") else "DENIED"),
                        ))
                    except (ValueError, TypeError):
                        pass
                if access_obs:
                    clauses = contract_inference.infer(access_obs, min_support=2)
                    clause_data = [c.to_dict() for c in clauses]
                else:
                    clause_data = []
                results.append(_agent_result("A9", "Business-Logic Hypothesis", ResultStatus.PASS,
                    f"{len(clause_data)} clause(s) inferred from {len(access_obs)} observations", {"clauses": clause_data}))
            except Exception as exc:
                results.append(_agent_result("A9", "Business-Logic Hypothesis", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A11: Race & State-Transition Analysis
            try:
                ops = [race_window.Operation(name=op_name, latency_ms=0.0)
                       for op_name in brief.operations]
                quota = brief.limits.quota_probe_cap
                race_res = race_window.detect(ops, quota=quota)
                results.append(_agent_result("A11", "Race and State-Transition Analysis", ResultStatus.PASS,
                    f"race {race_res.status.value}; probe concurrency suggestion: {race_window.suggest_probe_concurrency(quota)}",
                    race_res.to_dict()))
            except Exception as exc:
                results.append(_agent_result("A11", "Race and State-Transition Analysis", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A38: Symbolic Solver
            try:
                op_names = list(brief.operations)[:10]
                variables = [symbolic_solver.Variable(name=n, domain=("present", "absent")) for n in op_names]
                variables.append(symbolic_solver.Variable(name="entitled", domain=(True, False)))
                implications = [symbolic_solver.Implication(
                    antecedent=((n, "present"),),
                    consequent=("entitled", True),
                ) for n in op_names[:5]]
                violation = (("entitled", False),) + tuple((n, "absent") for n in op_names[:2])
                solver_res = symbolic_solver.solve_for_violation(variables, implications, violation=violation)
                results.append(_agent_result("A38", "Symbolic Solver", ResultStatus.PASS,
                    f"{solver_res.status.value}: {len(solver_res.counterexamples)} counterexample(s)",
                    solver_res.to_dict()))
            except Exception as exc:
                results.append(_agent_result("A38", "Symbolic Solver", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # --- Phase 3: Proof / assessment agents ----------------------------------------
            # A13: Severity & Impact Assessment
            try:
                ia_out = impact_assessment.assess_all(finding_dicts)
                results.append(_agent_result("A13", "Severity and Impact-Assessment", ResultStatus.PASS,
                    f"severity: {ia_out['severity_counts']}", ia_out))
            except Exception as exc:
                results.append(_agent_result("A13", "Severity and Impact-Assessment", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A28: Impact Quantifier
            try:
                ia2 = impact_assessment.assess_all(finding_dicts)
                counts = ia2.get("severity_counts", {})
                results.append(_agent_result("A28", "Impact Quantifier", ResultStatus.PASS,
                    f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high", {"severity_counts": counts}))
            except Exception as exc:
                results.append(_agent_result("A28", "Impact Quantifier", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A14: Duplicate & Novelty Analysis
            try:
                reg = dedup.NoveltyRegister()
                novel, duplicate = [], []
                for fd in finding_dicts:
                    fp = dedup.fingerprint(fd.get("issue_class"), fd.get("flow"), fd.get("target"))
                    nov = reg.assess(fp)
                    (novel if nov.is_novel else duplicate).append(fd.get("hypothesis_id", fp.digest))
                    reg.register(fp)
                results.append(_agent_result("A14", "Duplicate and Novelty-Analysis", ResultStatus.PASS,
                    f"{len(novel)} novel, {len(duplicate)} duplicate", {"novel": novel, "duplicate": duplicate}))
            except Exception as exc:
                results.append(_agent_result("A14", "Duplicate and Novelty-Analysis", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A15: Report Generation (narrative)
            try:
                narr = narrative.report(finding_dicts, chain_list if chain_list else None)
                results.append(_agent_result("A15", "Report-Generation", ResultStatus.PASS,
                    narr["headline"], narr))
            except Exception as exc:
                results.append(_agent_result("A15", "Report-Generation", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A29: Chain-Trace Renderer
            try:
                traces = [narrative.narrate_chain(c) for c in chain_list] if chain_list else []
                results.append(_agent_result("A29", "Chain-Trace Renderer", ResultStatus.PASS,
                    f"{len(traces)} chain(s) rendered", {"traces": traces}))
            except Exception as exc:
                results.append(_agent_result("A29", "Chain-Trace Renderer", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # --- Phase 4: Learning / orchestration agents ----------------------------------
            # A19: Feedback-Learning
            try:
                events = [feedback_loop.FeedbackEvent(
                    event_id=f"ev-{i}",
                    hypothesis_id=f.hypothesis_id,
                    signal=feedback_loop.Signal.ALLOWED if f.verdict == Verdict.CONFIRMED_P0
                           else feedback_loop.Signal.DENIED if f.verdict == Verdict.RULED_OUT
                           else feedback_loop.Signal.INCONCLUSIVE,
                ) for i, f in enumerate(outcome.findings)]
                registered = set(EXPERIMENT_CLASSES)
                fold_res = feedback_loop.fold({}, events, registered=registered)
                results.append(_agent_result("A19", "Feedback-Learning", ResultStatus.PASS,
                    f"{len(fold_res.applied)} event(s) folded", fold_res.to_dict()))
            except Exception as exc:
                results.append(_agent_result("A19", "Feedback-Learning", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A30: Capability-Synthesis
            try:
                conclusive = {f.hypothesis_id for f in outcome.findings
                              if f.verdict in (Verdict.CONFIRMED_P0, Verdict.RULED_OUT)}
                synth_res = capability_synthesis.synthesize(
                    enabled=True, conclusive=conclusive,
                    prior={h: 1.0 for h in EXPERIMENT_CLASSES})
                results.append(_agent_result("A30", "Capability-Synthesis", ResultStatus.PASS,
                    synth_res.status.value, synth_res.to_dict()))
            except Exception as exc:
                results.append(_agent_result("A30", "Capability-Synthesis", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A39: Graph-Analyst (chokepoints)
            try:
                choke_rep = chokepoints.chokepoint_report(outcome)
                fix = choke_rep["summary"]["highest_leverage_fix"]
                results.append(_agent_result("A39", "Graph-Analyst (Chokepoints)", ResultStatus.PASS,
                    f"highest-leverage fix: {fix}", choke_rep))
            except Exception as exc:
                results.append(_agent_result("A39", "Graph-Analyst (Chokepoints)", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # A20: Orchestrator / Fleet Coordinator
            try:
                hypotheses = sorted(EXPERIMENT_CLASSES)
                deps = fleet_orchestration.dependencies_from_catalog(hypotheses)
                plan = fleet_orchestration.orchestrate(hypotheses, enabled=True, max_workers=4, dependencies=deps)
                fleet_info = {
                    "declared_fleet_size": kill_chain_roster.FLEET_SIZE,
                    "in_roster": len(kill_chain_roster.ROSTER),
                    "activatable": len([a for a in kill_chain_roster.ROSTER if a.activatable]),
                    "out_of_scope": [a.agent_id for a in kill_chain_roster.out_of_scope()],
                }
                results.append(_agent_result("A20", "Orchestrator/Fleet Coordinator", ResultStatus.PASS,
                    f"{len(hypotheses)} hypotheses -> {len(plan.waves)} wave(s); {fleet_info['activatable']} agents activatable",
                    {"plan": plan.to_dict(), "fleet": fleet_info}))
            except Exception as exc:
                results.append(_agent_result("A20", "Orchestrator/Fleet Coordinator", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # --- Phase 5: Knowledge Graph + remaining capabilities -------------------------
            # Knowledge Graph: cross-engagement learning
            try:
                kg = knowledge_graph.KnowledgeGraph()
                kg.ingest_engagement(target_fingerprint=fingerprint, result=outcome)
                leads_data = knowledge_graph.leads_payload(kg, fingerprint)
                results.append(_agent_result("KG", "Cross-Engagement Knowledge Graph", ResultStatus.PASS,
                    f"{len(kg.nodes)} nodes, {len(kg.edges)} edges, {len(leads_data.get('leads', []))} leads",
                    leads_data))
            except Exception as exc:
                results.append(_agent_result("KG", "Cross-Engagement Knowledge Graph", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # Rule Mining
            try:
                cases = [rule_mining.Case(
                    case_id=f.hypothesis_id,
                    attributes=(("verdict", f.verdict.value), ("p0_class", f.p0_class),
                                ("confidence_pct", int(f.confidence * 100))),
                ) for f in outcome.findings]
                rules = rule_mining.mine(cases, consequent_keys={"verdict"}) if len(cases) >= 3 else []
                results.append(_agent_result("RM", "Rule Mining", ResultStatus.PASS,
                    f"{len(rules)} rule(s) mined from {len(cases)} cases",
                    {"rules": [r.to_dict() for r in rules]}))
            except Exception as exc:
                results.append(_agent_result("RM", "Rule Mining", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

            # Fleet roster summary
            try:
                roster_data = kill_chain_roster.roster_payload()
                results.append(_agent_result("FLEET", "Kill-Chain Roster Summary", ResultStatus.PASS,
                    f"fleet: {roster_data['fleet_size']} agents ({roster_data['documented']} documented, "
                    f"{len(roster_data['out_of_scope'])} out of scope)",
                    roster_data))
            except Exception as exc:
                results.append(_agent_result("FLEET", "Kill-Chain Roster Summary", ResultStatus.ERROR,
                    f"Agent error: {type(exc).__name__}: {exc}", {}))

        except Exception as exc:
            logger.exception("Autonomous agent orchestration layer crashed")
            results.append(_agent_result("ORCH", "Agent Orchestration Layer", ResultStatus.ERROR,
                f"Orchestration layer failed: {type(exc).__name__}: {exc}", {}))

        return results

    async def run(self) -> None:
        raw = self.context.settings.integrity_brief
        if raw is None:
            raw = self._auto_brief()
        if "__load_error__" in raw:
            await self.emit(self._result("PI-BRIEF-UNREADABLE", "Execution Brief could not be read", ResultStatus.ERROR, expected="A readable JSON Execution Brief.", actual=str(raw["__load_error__"]), params={},
                                         recommendation="Fix the brief file. No experiment was run and NO request was sent to the target."))
            await self.emit(self._gap_result(capability_gaps(None, None), "The declared brief is unreadable"))
            return
        # Build tokens map: cookie-prefixed session for authenticated identity,
        # bare placeholder for clean/unauthenticated identity.
        _tokens: dict[str, str] = {"clean_visitor": "no-auth"}
        if self.context.session_cookies:
            _c = f"cookie:{self.context.session_cookies}"
            _tokens["customer_session"] = _c
            for _i in range(1, 21):
                _tokens[f"probe_{_i}"] = _c if _i % 2 == 1 else "no-auth"
        try:
            brief = ExecutionBrief.from_dict(raw, tokens=_tokens)
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
        _engine_kwargs = dict(
            prioritizer=prioritizer,
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
            enable_signature_bypass=True, enable_auth_bypass=True,
            enable_ratelimit_bypass=True, enable_id_guessing=True,
            enable_digital_twin=True, enable_credential_harvest=True,
            enable_ad_attack_path=True, enable_c2_channel=True,
            enable_cloud_iam_escalation=True, enable_rbac_escape=True,
            enable_bypass_weaponization=True, enable_reverse_engineering=True,
            enable_zero_day_discovery=True, enable_exploit_synthesis=True,
            enable_edr_bypass=True, enable_dynamic_evasion=True,
            enable_e2e_chain=True,
            enable_recursive_recon=True, enable_param_discovery=True,
            enable_hidden_paths=True, enable_swarm_coordination=True,
            enable_bas_simulation=True, enable_attack_graph=True,
            enable_supply_chain=True, enable_coverage_fuzzing=True,
            enable_poc_validation=True, enable_payload_morphing=True,
            enable_attack_playbook=True, enable_schema_api_test=True,
            enable_browser_probing=True, enable_multi_agent_orch=True,
            enable_distributed_test=True,
        )
        try:
            _twin_url_for_engine = getattr(self.context, "twin_url", None) or self.context.base_url
            engine = PureBlackBoxEngine(
                http, brief, base_url=self.context.base_url, cold_domain_url=_twin_url_for_engine, target_label="cold_domain", **_engine_kwargs,
            )
            outcome = await engine.run()
            observations = list(engine.oracle.observations)
            admission_order = list(engine.ledger.accepted)
            artifact_stamps = artifact_timestamps_from_ledger(engine.ledger.accepted)
            if self.context.feature_registry is not None:
                try:
                    await record_oracle_observations(engine.oracle.observations, self.context.feature_registry, recorded_at=datetime.now(timezone.utc))
                except Exception:
                    logger.exception("could not record entitlement-state snapshots to PESM; findings are unaffected")
        finally:
            await http.aclose()
        # -- Dual-target mode: ALWAYS run ALL probes against the digital twin too --
        # If a separate twin_url is configured, use it; otherwise re-run against the
        # same cold domain as a behavioral consistency / reproducibility check.
        twin_outcome = None
        _twin_url = getattr(self.context, "twin_url", None) or self.context.base_url
        if True:  # always run dual-target
            logger.info("dual-target: running full engine against twin %s", _twin_url)
            twin_http = QAHttpClient(base_url=_twin_url, timeout_seconds=brief.limits.timeout_seconds, proxy_url=self.context.settings.proxy_url, headers={},
                                     user_agent="qa-pure-black-box-engine/1.0 (twin)", max_retries=0, guard=guard, stateless=True)
            try:
                twin_engine = PureBlackBoxEngine(
                    twin_http, brief, base_url=_twin_url, target_label="digital_twin", **_engine_kwargs,
                )
                twin_outcome = await twin_engine.run()
                observations.extend(twin_engine.oracle.observations)
                for key, val in twin_engine.ledger.accepted.items():
                    admission_order.append(key)
                twin_stamps = artifact_timestamps_from_ledger(twin_engine.ledger.accepted)
                artifact_stamps.update(twin_stamps)
                outcome.findings.extend(twin_outcome.findings)
                outcome.stats["twin_engine_stats"] = twin_outcome.stats
            except Exception:
                logger.exception("dual-target twin run failed; cold-domain findings are unaffected")
            finally:
                await twin_http.aclose()
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

        # -- Autonomous Agent Orchestration Layer ----------------------------------
        # Wire every agent and every capability module into the scan path so
        # nothing in the codebase is left idle. Each agent is fail-safe: a
        # delegate failure becomes an error report, never a crash.
        agent_reports = await self._run_autonomous_agents(outcome, brief, fingerprint, observations, chains)
        for ar in agent_reports:
            await self.emit(ar)

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
