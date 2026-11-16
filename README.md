# RedPilot — Test Clone (Enterprise Controls Stripped)

> **This is the unrestricted developer test clone.** Enterprise controls (scope guard, brief
> validation, provenance ledger, purity audit, confirmation gate) are **stripped or bypassed** so
> the engine can be run against any domain from a cold start with no brief file, no signed scope,
> and no configuration. The operator is solely responsible for authorization.
>
> For the production codebase with all safety controls enforced in code, see
> [`danieldegedo-art/RedPilot`](https://github.com/danieldegedo-art/RedPilot).

---

## What this clone does differently

| Production (`RedPilot`) | This clone (`RedPilot-Test-Clone`) |
|---|---|
| Signed contract + domain verification before any run | `host_permitted()` always returns `True` |
| Execution Brief required and validated by enterprise controls | Auto-brief generated from just a URL |
| Brief rejected if controls unavailable (fail-closed) | `FailOpenControlAdapter` accepts any valid dict |
| 5 modules by default (`STANDARD` scope) | All 20 modules enabled (`FULL_REGRESSION` default) |
| Agents and capability modules advisory / planning only | All 35 agents + all capability modules fire autonomously |
| Rate limit: configured per engagement | `OpenScopePolicy`: 10M requests / 10K req/s |
| Cold discovery: not available without brief | 7-step cold discovery reconstructs a brief from a raw domain |
| No `/scan` endpoint | Paste a URL, press run |

---

## Quick start — the `/scan` endpoint

```bash
cd backend

# Option A: hit the API directly (server must be running)
curl -X POST http://127.0.0.1:8420/api/v1/runs/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://your-authorized-target.com"}'

# Option B: CLI wrapper (starts polling automatically)
python scan.py https://your-authorized-target.com
```

That single URL triggers the full pipeline:

1. **Auto-brief** — generates a minimal `ExecutionBrief` from the domain
2. **Cold discovery** — 7-step surface reconstruction (sitemap, robots, OpenAPI, link harvest,
   form harvest, payment-keyword scan, JS endpoint extraction)
3. **PureBlackBoxEngine** — all 45 capability probes enabled, all 43 experiment classes:
   - Core: `PBB-U`, `PBB-F`, `PBB-H`, `PBB-C`, `PBB-G`, `PBB-X`, `PBB-R`, `PBB-E`
   - Standalone: `PBB-D`, `PBB-OPEN`, `PBB-LEAK`
   - Bypass: `PBB-SIG`, `PBB-AUTH`, `PBB-RATE`, `PBB-IDOR`
   - Offensive (B68-B80): `PBB-TWIN`, `PBB-CRED`, `PBB-ADPATH`, `PBB-C2`, `PBB-IAM`, `PBB-RBAC`,
     `PBB-BPWPN`, `PBB-REVENG`, `PBB-ZDAY`, `PBB-XPLOIT`, `PBB-EDRBP`, `PBB-EVADE`, `PBB-E2E`
   - Tool-integrated (B82-B96): `PBB-RRECON`, `PBB-PARAM`, `PBB-HIDDEN`, `PBB-SWARM`, `PBB-BAS`,
     `PBB-AGRAPH`, `PBB-SUPPLY`, `PBB-CFUZZ`, `PBB-POCVAL`, `PBB-MORPH`, `PBB-PLAY`, `PBB-SCHEMA`,
     `PBB-BROWSE`, `PBB-MORCH`, `PBB-DTEST`
4. **Dual-target validation** — ALL probes (offensive + tool-integrated) run against BOTH the
   digital twin AND the cold domain, with findings tagged by target for side-by-side comparison
5. **Autonomous agent layer** — all 65 kill-chain agents (A2–A67) and all capability modules in
   6 phases
6. **Cognitive analysis + intelligent discovery** — 20 cognitive sub-modules fire post-engine
7. **All 20 test modules** in `FULL_REGRESSION` scope

---

## Autonomous agent layer

The `_run_autonomous_agents()` method in `PaymentIntegrityModule` fires every agent and every
previously-orphaned capability module after the engine produces findings. Each call is fail-safe
wrapped (errors become `ERROR` results, never a crash).

**Phase 1 — Recon:**
A3 (surface discovery), A4 (workflow mapper), A21–A24 (payment-provider / webhook-fraud /
coupon-promo / subscription-lifecycle specialists), A37 (threat intel), A36 (OSINT, narrowed),
A33–A35 (contract auditor / reverser / mobile operator), A31/A32 (reported OUT_OF_SCOPE)

**Phase 2 — Attack / Analysis:**
A8 (differential testing), A9 (business-logic / contract inference), A11 (race & state
transition), A38 (symbolic solver)

**Phase 3 — Proof / Assessment:**
A13 (severity & impact), A28 (impact quantifier), A14 (novelty / dedup), A15 (narrative report),
A29 (chain-trace renderer)

**Phase 4 — Learning / Orchestration:**
A19 (feedback learning), A30 (capability synthesis), A39 (graph analyst / chokepoints),
A20 (fleet orchestrator)

**Phase 5 — Knowledge Graph + remaining:**
Cross-engagement knowledge graph, rule mining, fleet roster summary

### Bypass probes (test clone only)

These four probes are enabled only in this test clone. The production repo's safety contract
forbids them ("no signature/auth/rate-limit bypass; no ID guessing").

| Probe | Hypothesis | What it does |
|---|---|---|
| `PBB-SIG` | Signature bypass | Sends absent / empty / alg:none / truncated / wrong-key signatures against signature-requiring endpoints |
| `PBB-AUTH` | Auth bypass | Sends absent / empty / malformed / null bearer tokens against authenticated endpoints |
| `PBB-RATE` | Rate-limit bypass | Drives an identity to its quota cap, then tries X-Forwarded-For / X-Real-IP / User-Agent spoofing |
| `PBB-IDOR` | ID guessing | Derives sequential / adjacent / mutated candidate IDs from a legitimate reference and tries them as a different identity |

Each probe follows the same fail-safe pattern as the existing experiments: errors become
`UNKNOWN`, never a crash. A hit becomes `SUSPECTED_PAYMENT_INTEGRITY_ISSUE`; a clean result
becomes `RULED_OUT`.

### Offensive capability probes (B68–B80, test clone only)

| Probe | Hypothesis | What it does | Adapted from |
|---|---|---|---|
| `PBB-TWIN` | Digital twin fidelity | Dual-session fingerprint comparison with fidelity score | XM Cyber digital twin |
| `PBB-CRED` | Credential exposure | Regex + Shannon entropy + Nuclei template detection across 20+ paths | GitGuardian, TruffleHog |
| `PBB-ADPATH` | AD/LDAP exposure | AD endpoint probing, LDAP injection, Negotiate/NTLM detection | BloodHound, PingCastle |
| `PBB-C2` | C2 channel viability | WebSocket upgrade, SSRF with 5 targets, streaming detection | Mythic, Sliver, Havoc |
| `PBB-IAM` | Cloud IAM escalation | SSRF to AWS/GCP/Azure/Alibaba metadata, K8s SA tokens, provider detection | Wiz, Prisma Cloud |
| `PBB-RBAC` | RBAC escape | Admin endpoint access, role parameter manipulation, method override | Pentera |
| `PBB-BPWPN` | Bypass weaponization | Baseline-then-bypass with 6 encoding variants + Nuclei templates | Nuclei, XBOW |
| `PBB-REVENG` | Reverse engineering | JS bundle analysis, endpoint/secret extraction, source map detection | Ghidra, IDA Pro |
| `PBB-ZDAY` | Zero-day discovery | Coverage-guided mutation (AFL++ inspired) + Nuclei SSTI/path-traversal templates | AFL++, OSS-Fuzz, Nuclei |
| `PBB-XPLOIT` | Exploit synthesis | Kill-chain stage mapping + BloodHound attack graph analysis | Metasploit, XBOW, BloodHound |
| `PBB-EDRBP` | EDR/AV bypass | 3 payloads × 6 evasion techniques with ATT&CK mapping | Atomic Red Team, Caldera, SCYTHE |
| `PBB-EVADE` | Dynamic evasion | 8 fingerprint dimensions, detection rate measurement | Cymulate, SafeBreach, AttackIQ |
| `PBB-E2E` | End-to-end kill chain | 9-stage MITRE kill chain with attack graph + blast radius | Pentera, XBOW, Caldera |

### Tool-integrated probes (B82–B96, test clone only)

| Probe | Hypothesis | What it does | Adapted from |
|---|---|---|---|
| `PBB-RRECON` | Recursive recon | BBOT-style modular recon pipeline: subdomain, tech fingerprint, endpoint harvest | BBOT, Artemis, NucleiFuzzer |
| `PBB-PARAM` | Parameter discovery | XSSRocket/NucleiFuzzer parameter mining + template injection scanning | XSSRocket, NucleiFuzzer, ParamSpider |
| `PBB-HIDDEN` | Hidden path discovery | AdminPBuster-style hidden admin panel and sensitive path brute-force | AdminPBuster, CyberStrike, Dark-Moon |
| `PBB-SWARM` | Swarm coordination | XBOW narrow-agent independent validation of suspected findings | XBOW, PentAGI, HexStrike |
| `PBB-BAS` | Breach & attack simulation | 8 ATT&CK technique simulations with detection gap scoring | Cymulate, SafeBreach, AttackIQ, Pentera |
| `PBB-AGRAPH` | Attack graph analysis | BloodHound-style directed graph with DFS path finding + choke points | BloodHound, XM Cyber, PingCastle, Wiz |
| `PBB-SUPPLY` | Supply chain scanning | GitGuardian/TruffleHog 30+ regex patterns + dependency manifest exposure | GitGuardian, TruffleHog, Gitleaks |
| `PBB-CFUZZ` | Coverage-guided fuzzing | AFL++ 20-strategy mutation engine with crash + info-leak detection | AFL++, OSS-Fuzz, NucleiFuzzer |
| `PBB-POCVAL` | PoC validation | Shannon/Strix-style independent reproduction of suspected findings | Shannon, Strix, Xalgorix |
| `PBB-MORPH` | Payload morphing | Dark-Moon/Decepticon adaptive payload transformation (6 encoding variants) | Dark-Moon, Decepticon, AIRecon |
| `PBB-PLAY` | Attack playbook execution | Caldera/Atomic Red Team ATT&CK playbook execution | Caldera, Atomic Red Team, SCYTHE |
| `PBB-SCHEMA` | Schema API testing | OpenAPI/GraphQL schema extraction + undocumented endpoint discovery | Shannon, Strix, REA |
| `PBB-BROWSE` | Browser automation probing | Client-side JS analysis + payment-flow behavioral testing | BugTrace-AI, NyxStrike, CyberStrike |
| `PBB-MORCH` | Multi-agent orchestration | T3MP3ST 8-operator + RedAmon LangGraph-style coordination | T3MP3ST, RedAmon, Decepticon, PentesterFlow |
| `PBB-DTEST` | Distributed parallel testing | Pentera-style parallel race-condition + state-consistency testing | Pentera, CyberStrike, PentesterFlow |

### Integrated capability modules (`integrated_capabilities.py`)

| Class | Source tools | Capability |
|---|---|---|
| `ModularReconPipeline` | BBOT, Artemis, NucleiFuzzer | Chained recon: subdomain → fingerprint → endpoint → vuln match |
| `TemplateMatcher` | Nuclei, NucleiFuzzer | YAML-style template matching with matchers and extractors |
| `AgentOrchestrator` | XBOW, PentAGI, Dark-Moon | Narrow-scope specialist agent dispatch |
| `AttackGraphBuilder` | BloodHound, XM Cyber | Directed finding graph with DFS path finding |
| `AttackSimulator` | Pentera, Cymulate, SafeBreach, AttackIQ | BAS with 15 ATT&CK techniques across 4 scenarios |
| `ExploitValidator` | Metasploit, Core Impact | Exploit chain validation and impact scoring |
| `C2Simulator` | Mythic, Sliver, Havoc | C2 channel protocol simulation |
| `EDRTestFramework` | Atomic Red Team, Caldera, SCYTHE | Detection control testing with ATT&CK mapping |
| `SecretScanner` | GitGuardian, TruffleHog, Gitleaks | 30+ pattern deep secret detection |
| `ClientAnalyzer` | Ghidra, IDA Pro, Binary Ninja, Radare2 | JS bundle analysis: endpoint/secret/auth-flow extraction |
| `SmartFuzzer` | AFL++, OSS-Fuzz | 20-strategy coverage-guided mutation engine |
| `SpecializedAttacks` | XSSRocket, Decepticon, HexStrike | XSS, SSRF, SSTI, CORS, IDOR attack payloads |
| `APISecurity` | Shannon, Strix | OpenAPI/GraphQL schema testing |
| `WorkflowOrchestrator` | PentesterFlow, CyberStrike, NyxStrike | Multi-phase workflow with dependency tracking |
| `PersistentKnowledgeStore` | RedAmon, REA | Cross-engagement knowledge persistence |

### Advanced orchestration modules (`advanced_orchestration.py`)

| Class | Source tools | Capability |
|---|---|---|
| `AdaptiveTaskPlanner` | XBOW, Caldera | Objective → DAG decomposition with priority scoring |
| `SpecialistAgentPool` | Dark-Moon, PentAGI | 7 specialist agent types with task routing |
| `ContinuousAttackSimulator` | Cymulate, SafeBreach | 15 ATT&CK techniques × 4 attack scenarios |
| `AttackTreeEngine` | BloodHound, XM Cyber | Graph-based attack-path analysis with composite risk |
| `AdversaryEmulationEngine` | Caldera, Atomic Red Team | 4 adversary profiles (APT29, FIN7, etc.) |
| `IntelligentFuzzerOrchestrator` | AFL++, OSS-Fuzz | 8 mutation strategies with coverage tracking |
| `ExploitChainCompiler` | Metasploit, Core Impact | Chain compilation, validation, impact scoring |

### Dual-target validation (B81)

ALL offensive AND tool-integrated probes run against BOTH the digital twin AND the original cold
domain. Findings are tagged with `target_label` (`"digital_twin"` or `"cold_domain"`) for
side-by-side comparison. Adapted from XM Cyber's continuous validation pattern.

### Adapted techniques from all 56 researched tools

| # | Tool | Category | Technique adapted | Where applied |
|---|---|---|---|---|
| 1 | BBOT | Recon | Recursive modular recon pipeline, event-driven findings | PBB-RRECON, `ModularReconPipeline` |
| 2 | Artemis | Recon | Karton framework task chaining, tech fingerprinting | PBB-RRECON, `ModularReconPipeline` |
| 3 | NucleiFuzzer | Recon+Scan | ParamSpider→Nuclei template pipeline | PBB-PARAM, PBB-CFUZZ, `TemplateMatcher` |
| 4 | XSSRocket | Recon+Attack | Wayback URL mining, parameter extraction | PBB-PARAM, `SpecializedAttacks` |
| 5 | AdminPBuster | Discovery | Hidden admin panel brute-force wordlists | PBB-HIDDEN |
| 6 | Nuclei | Scanning | YAML template matchers/extractors, SSTI/path templates | `TemplateMatcher`, PBB-BPWPN, PBB-ZDAY |
| 7 | XBOW | Orchestration | Narrow-scope agent decomposition, autonomous planning | PBB-SWARM, `AgentOrchestrator`, `AdaptiveTaskPlanner` |
| 8 | PentAGI | Orchestration | Multi-agent Docker-isolated pentesting pipeline | PBB-SWARM, `SpecialistAgentPool` |
| 9 | HexStrike | Orchestration | MCP-integrated specialist agent dispatch | PBB-SWARM, `AgentOrchestrator` |
| 10 | Dark-Moon | Orchestration | 10-agent autonomous pentest crews | PBB-MORPH, `SpecialistAgentPool` |
| 11 | Decepticon | C2+Attack | LangGraph C2 framework, payload transformation | PBB-MORPH, PBB-MORCH, `C2Simulator` |
| 12 | T3MP3ST | Orchestration | 8-operator coordination pattern | PBB-MORCH, `WorkflowOrchestrator` |
| 13 | RedAmon | Knowledge | LangGraph+Neo4j persistent knowledge, agent coordination | PBB-MORCH, `PersistentKnowledgeStore` |
| 14 | REA | Knowledge | Cross-engagement learning, recon enrichment | `PersistentKnowledgeStore` |
| 15 | Cymulate | BAS | BAS exposure scoring, continuous validation | PBB-BAS, PBB-EVADE, `ContinuousAttackSimulator` |
| 16 | SafeBreach | BAS | Hacker's Playbook attack simulation library | PBB-BAS, `ContinuousAttackSimulator` |
| 17 | AttackIQ | BAS | ATT&CK-mapped control validation | PBB-BAS, `ContinuousAttackSimulator` |
| 18 | Pentera | BAS+Distributed | Distributed attack orchestration, continuous pentesting | PBB-BAS, PBB-DTEST, `AttackSimulator` |
| 19 | BloodHound | Attack graph | Directed graph traversal, choke-point detection | PBB-AGRAPH, PBB-XPLOIT, `AttackGraphBuilder`, `AttackTreeEngine` |
| 20 | XM Cyber | Attack graph | Digital twin continuous validation | PBB-AGRAPH, B81 dual-target, `AttackTreeEngine` |
| 21 | PingCastle | AD health | AD health scoring patterns | PBB-ADPATH, `AttackGraphBuilder` |
| 22 | Wiz | Cloud | Agentless cloud scanning, provider detection from headers | PBB-IAM, `AttackGraphBuilder` |
| 23 | Prisma Cloud | Cloud | K8s SA token check, cloud IAM analysis | PBB-IAM |
| 24 | GitGuardian | Secrets | 30+ regex secret patterns, severity classification | PBB-SUPPLY, PBB-CRED, `SecretScanner` |
| 25 | TruffleHog | Secrets | Shannon entropy detection, high-entropy string scoring | PBB-SUPPLY, PBB-CRED, `SecretScanner` |
| 26 | Gitleaks | Secrets | Regex-based secret scanning with TOML rule format | PBB-SUPPLY, `SecretScanner` |
| 27 | AFL++ | Fuzzing | 20-strategy coverage-guided mutation, crash detection | PBB-CFUZZ, PBB-ZDAY, `SmartFuzzer`, `IntelligentFuzzerOrchestrator` |
| 28 | OSS-Fuzz | Fuzzing | Crash pattern detection, info-leak patterns | PBB-CFUZZ, `SmartFuzzer` |
| 29 | Ghidra | RE | P-code IR analysis patterns, endpoint extraction | PBB-REVENG, `ClientAnalyzer` |
| 30 | IDA Pro | RE | Binary analysis patterns, disassembly heuristics | PBB-REVENG, `ClientAnalyzer` |
| 31 | Binary Ninja | RE | LLIL/MLIL lifting patterns | PBB-REVENG, `ClientAnalyzer` |
| 32 | Radare2 | RE | r2pipe analysis, string extraction | PBB-REVENG, `ClientAnalyzer` |
| 33 | Metasploit Pro | Exploit | Module taxonomy, exploit chain composition | PBB-XPLOIT, `ExploitValidator`, `ExploitChainCompiler` |
| 34 | Core Impact | Exploit | Multi-vector exploit validation, impact scoring | PBB-XPLOIT, `ExploitValidator`, `ExploitChainCompiler` |
| 35 | Mythic | C2 | C2 profile multiplexing, WebSocket channels | PBB-C2, `C2Simulator` |
| 36 | Sliver | C2 | mTLS/WireGuard C2 channel patterns | PBB-C2, `C2Simulator` |
| 37 | Havoc | C2 | HTTP/S C2 with sleep/jitter patterns | PBB-C2, `C2Simulator` |
| 38 | Cobalt Strike | C2 | Malleable C2 profile concept | PBB-C2, `C2Simulator` |
| 39 | Canvas | Exploit | Exploit module dispatch pattern | `ExploitValidator` |
| 40 | Atomic Red Team | Testing | ATT&CK technique unit tests, T-number mapping | PBB-BAS, PBB-PLAY, `EDRTestFramework`, `AdversaryEmulationEngine` |
| 41 | Caldera | Emulation | Adversary profiles (APT29, FIN7), ability dispatch | PBB-BAS, PBB-PLAY, `EDRTestFramework`, `AdversaryEmulationEngine` |
| 42 | SCYTHE | Testing | Detection assessment, purple team scoring | PBB-EDRBP, `EDRTestFramework` |
| 43 | Shannon | API | OpenAPI schema testing, whitebox PoC validation | PBB-SCHEMA, PBB-POCVAL, `APISecurity` |
| 44 | Strix | API | Autonomous PoC generation, GraphQL introspection | PBB-SCHEMA, PBB-POCVAL, `APISecurity` |
| 45 | Xalgorix | Testing | 22-phase verification methodology | PBB-POCVAL, mutation strategies |
| 46 | Invicti | DAST | DAST scanning patterns, proof-based detection | PBB-BROWSE, scan methodology |
| 47 | Acunetix | DAST | AcuSensor technology patterns, JS analysis | PBB-BROWSE, `ClientAnalyzer` |
| 48 | Burp Suite | Proxy | Active/passive scanning pattern, intruder payloads | PBB-PARAM, PBB-CFUZZ |
| 49 | PentestAgent | Orchestration | Autonomous pentesting pipeline | Engine `run()` wiring |
| 50 | PentesterFlow | Workflow | Human-in-the-loop agent coordination | PBB-MORCH, PBB-DTEST, `WorkflowOrchestrator` |
| 51 | CyberStrike | Attack | OWASP WSTG methodology, parallel testing | PBB-HIDDEN, PBB-DTEST, `WorkflowOrchestrator` |
| 52 | NyxStrike | Attack | Browser automation + API testing | PBB-BROWSE, `WorkflowOrchestrator` |
| 53 | BugTrace-AI | Testing | AI-assisted browser automation probing | PBB-BROWSE |
| 54 | AIRecon | Recon | AI-guided recon enrichment | PBB-MORPH |
| 55 | Cybermes | Testing | Multi-agent security testing coordination | PBB-MORCH |
| 56 | RedTeam-Tools | Collection | Curated offensive tool taxonomy | EXPERIMENT_CLASSES design |

---

## What RedPilot is

A narrowly-scoped, black-box **payment / entitlement business-logic QA and bug-bounty engine**.
RedPilot proves whether a paywall or entitlement can be defeated by *business-logic* flaws —
composed entirely from experiments an authorised external customer can run (synthetic identities,
the vendor's own sandbox payment instrument, and the server-enforced paid feature as the only
source of truth). It is a QA tool in the same category as Horizon3.ai / Pentera / XBOW for the
payment-logic domain — **not** an exploitation or adversary-simulation framework.

**Method.** A differential-oracle proof against the vendor's *own* test payment instrument
("our test card, $0.00 charged") — not credential attacks or auth bypass.

**Declared non-goals.** Not a Cobalt Strike / Brute Ratel-style adversary-simulation framework;
not a prompt-injection or LLM/AI-agent red-teaming tool. There is **no live LLM or external-AI
call anywhere in the codebase** — `benchmark/llm_replacement_layer.py` exists specifically to
avoid one, so payment response bodies never leave the process.

---

## Authorization notice

The production RedPilot enforces authorization in code (signed contract, domain verification,
scope guard, provenance ledger). **This test clone has those gates removed.** You must
self-enforce:

- Run **only** against systems you own or are explicitly authorized to test.
- Use sandbox / test-mode payments only.
- You are responsible for operating within the law.

---

## Architecture

```
app/
  testing/integrity/     PureBlackBoxEngine + the method:
                         engine, oracle, oracle_calibration, session (guarded customer session),
                         brief (Execution Brief), attack_chain, race_window, replay, regression,
                         findings, narrative, knowledge_graph, rule_mining, symbolic_solver,
                         contract_inference, feedback_loop, differencer, dedup, chokepoints,
                         capability_synthesis, fleet_orchestration, impact_assessment,
                         race_window, payment_fingerprint, threat_intel, ...
  testing/agents/        the agent layer (26 wrapped agents in 5 groups):
                         recon (7), attack (4), proof (5), orchestration (4), domain_packs (6)
                         + 9 CAPABILITY_SATISFIED (served directly by their capability module)
  testing/integrity/integrated_capabilities.py  16 capability classes from 35+ tools
  testing/integrity/advanced_orchestration.py   7 orchestration classes (XBOW/Caldera patterns)
  testing/integrity/kill_chain_roster.py    the fixed 65-agent fleet roster (A2–A67, declarative)
  testing/integrity/fleet_orchestration.py  orchestrator — emits plans/leads only
  testing/runner.py      cognitive analysis (20 sub-modules) + intelligent discovery layer
  testing/modules/       all 20 test modules (all enabled by default)
  testing/registry.py    FULL_REGRESSION scope = all 20 modules
  core/control_port/     fail-open adapter (enterprise controls stripped in this clone)
  api/v1/runs.py         /scan endpoint (cold-domain entry point)
  schemas/run.py         ScanRequest schema (just a URL)
scan.py                  CLI: python scan.py <url>
```

**Enterprise controls in this clone.** The `enterprise_controls/` directory still exists but is
not enforced. `FailOpenControlAdapter` is the active adapter: `host_permitted()` returns `True`,
`parse_brief()` accepts any valid dict, `OpenScopePolicy` allows 10M requests at 10K req/s, the
evidence ledger admits anything with a provenance record, and the confirmation gate is unavailable
(findings stay `PARTIALLY_VALIDATED`, never `CONFIRMED_P0`). This is logged as `CRITICAL` /
`degraded: true` in every run's stats.

---

## How the engine works

RedPilot never reads a target's logs, database, admin or internal state. Its only I/O is a
guarded customer session (identity token only). The method (the "external control pattern"):

1. **Controls first.** A clean identity must be DENIED and a legitimate (sandbox) payer must be
   ALLOWED. If the oracle cannot establish both, no later result is trusted.
2. **Scenario** per hypothesis on a fresh synthetic identity, tampering only with what a customer
   controls.
3. **Chain composition.** The chain engine composes declared, individually-harmless primitives
   into a no-payment sequence: guided forward search, iterative error-driven field learning,
   bounded concurrency probes, convergence detection, and deep TOCTOU.
4. **Confirmation** requires the gate (unavailable in this clone; findings stay
   `PARTIALLY_VALIDATED` at most).

---

## Setup & run

### Minimal (engine + benchmark only)

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install "cryptography>=42,<46"

cd backend
export PYTHONPATH="tests/verification_infrastructure/shims:tests/verification_infrastructure:."
python3 tests/verification_infrastructure/hardened_benchmark/run_abraxas.py --controls
```

### Full platform (API + /scan endpoint)

```bash
pip install -r backend/requirements.txt   # FastAPI, SQLAlchemy, httpx, pydantic, ...
cd backend && uvicorn app.main:app --port 8420

# Then in another terminal:
python scan.py https://your-authorized-target.com
```

### Offline test suite

```bash
pip install pytest pytest-asyncio
cd backend && python3 tests/verification_infrastructure/mini_pytest.py $(find tests -name 'test_*.py' | sort)
```
