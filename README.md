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
3. **PureBlackBoxEngine** — all 17 capability probes enabled, all 8+7 experiments
   (`PBB-U`, `PBB-F`, `PBB-H`, `PBB-C`, `PBB-G`, `PBB-X`, `PBB-R`, `PBB-E` + standalone
   `PBB-D`, `PBB-OPEN`, `PBB-LEAK`, `PBB-SIG`, `PBB-AUTH`, `PBB-RATE`, `PBB-IDOR`)
4. **Autonomous agent layer** — all 35 kill-chain agents (A2–A39) and all capability modules in
   5 phases
5. **Cognitive analysis + intelligent discovery** — 20 cognitive sub-modules fire post-engine
6. **All 20 test modules** in `FULL_REGRESSION` scope

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
  testing/integrity/kill_chain_roster.py    the fixed 35-agent fleet roster (declarative)
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
