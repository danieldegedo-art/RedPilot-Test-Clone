# RedPilot

A narrowly-scoped, black-box **payment / entitlement business-logic QA and bug-bounty engine**. RedPilot proves
whether a paywall or entitlement can be defeated by *business-logic* flaws — composed entirely from experiments an
authorised external customer can run (synthetic identities, the vendor's own sandbox payment instrument, and the
server-enforced paid feature as the only source of truth). It is a QA tool in the same category as
Horizon3.ai / Pentera / XBOW for the payment-logic domain — **not** an exploitation or adversary-simulation framework.

---

## ⚠️ Authorization & legal notice

RedPilot is built to run **only** against systems the operator owns or is explicitly authorised to test (its own
checkout/paywall, a client engagement under a signed scope, or a provider sandbox / test-mode).

- **Rules-of-Engagement gate.** No self-serve mode. A signed contract plus domain/identity verification must exist
  before any run; **the runner refuses any host outside the verified, signed scope.**
- **Safety contract (enforced in code, not aspirational).** Production is refused; no signature/auth/rate-limit
  bypass; no ID guessing; synthetic identities and sandbox/test-mode payments only.
- **Declared non-goals.** Not a Cobalt Strike / Brute Ratel-style adversary-simulation framework; not a
  prompt-injection or LLM/AI-agent red-teaming tool. There is **no live LLM or external-AI call anywhere in the
  codebase** — `benchmark/llm_replacement_layer.py` exists specifically to avoid one, so payment response bodies
  never leave the process.
- **Method.** A differential-oracle proof against the vendor's *own* test payment instrument ("our test card,
  $0.00 charged") — not credential attacks or auth bypass.

Use it only where you are authorised. You are responsible for operating within your signed scope and the law.

---

## Status

- **Engine**: `PureBlackBoxEngine` — role-agnostic, FAIL-CLOSED, confirmation-gated. 16 capstone bosses beaten
  (depth 4 → 22, plus the opaque multi-branch apex NYX), 21 solvable randomized held-out families at 6/6 (0
  false-confirms, 0 clean false-positives), plus two honest boundaries correctly refused.
- `2026-11-13` — apex boss **NYX**: opaque errors (~99.9% errors, 0 grants under a 3,000-probe sweep) + a
  freshness-windowed 3-capability quorum, with every Stripe guard implemented correctly. Forced the B49
  convergence probe (schema-driven field satisfaction + multi-branch assembly + synchronised concurrent minting).
  See `docs/NYX_BOSS_CYCLE.md`.
- `2026-11-13` — depth-22 boss **Chronos**: a DEEP in-chain TOCTOU race (prefix-then-burst) folded into the chain.
- `2026-11-07` — depth-20 boss **Pangaea**: numeric business-logic + cross-tenant BOLA capabilities.
- `2026-11-07` — depth-18 **Cosmos** (async-callback correlation binding); depth-16 **Olympus** (SSRF relay signing).

---

## What it can do (capability ladder)

Every capability was forced by a MISS→fix→FIND loop on a harder boss, then re-verified out-of-sample on a fresh
randomized family with **0 false positives**. Each builds a real, general black-box capability — never a
hard-coded path.

| # | Capability | Held-out family |
|---|---|---|
| 1 | Guided forward chain search (grow one spine, no factorial blow-up) | compose 12/12 |
| 2 | Iterative multi-field learning (satisfy every server-named input) | multifield 6/6 |
| 3 | Follow the `Location` response header | headernonce 6/6 |
| 4 | Construct an HMAC request signature from a provisioned key | — |
| 5 | Freshness-bound signing (server nonce + timestamp) | freshsig 6/6 |
| 6 | Asymmetric Ed25519 keypair generation + registration + signing | asymsig 6/6 |
| 7 | RFC 9421 content-digest binding | digestsig 6/6 |
| 8 | Replay-aware webhook forging (fresh ts + unique idempotency) from a leaked secret | replaysig 6/6 |
| 9 | Algorithm-confusion / RS→HS downgrade (HMAC over a published public key) | algconfusion 6/6 |
| 10 | Relayed-request / SSRF signing (sign over the forwarded inner path) | relaysign 6/6 |
| 11 | Async-callback correlation binding (issued correlation id as webhook-id) | asynccallback 6/6 |
| 12 | Business-logic numeric mutation (negative/zero total, client price, currency confusion) | numeric 6/6 |
| 13 | Multi-identity / cross-tenant BOLA (victim-response harvest + fallback sweep) | bola2 6/6 |
| 14 | Bounded concurrency / TOCTOU burst (shallow limit-overrun) | raceburst 6/6 |
| 15 | **Deep in-chain TOCTOU** (establish the prefix, then burst the terminal one-shot) | deeprace 6/6 |
| 16 | Schema-driven field satisfaction under opaque errors (the target never names a field) | NYX (ablated) |
| 17 | Multi-branch sub-chain assembly + convergence detection (many paths → one quorum) | NYX (ablated) |
| 18 | Freshness-synchronised concurrent minting (a same-window quorum a sequential spine busts) | NYX (ablated) |

Capabilities 16–18 (the **B49 convergence family**) are verified on the **NYX** capstone with per-flaw controls and
per-capability ablations: each is individually load-bearing (disable schema-satisfaction → miss; mint sequentially
→ miss), and the all-correct variant yields 0 (no false positive). They are general (brief-schema-driven, not
hard-coded to NYX); a randomized held-out family for them is a documented follow-up.

Provider-model families from real per-provider research (not signing variants): **keymanagement** (un-authz'd
detokenize / AES-at-rest angle) 6/6, **mandate** (GoCardless bank-debit) 6/6, **dunning** (Chargebee/Recurly state
machine, no crypto) 6/6.

**Honest boundaries (correct refusals, never faked):** a correctly-implemented signed webhook whose secret is never
observable (0/4); a single-yield `sleep(0)` race too tight for a bounded burst to win over the network (0/4, even
with the race probe forced on); and every undiscoverable-input variant (0). A bounded burst wins realistic
DB-round-trip windows only; an atomic / unique-constrained one-shot is unbeaten.

---

## How it works

RedPilot never reads a target's logs, database, admin or internal state. Its only I/O is a guarded customer
session (identity token only). The method (the "external control pattern"):

1. **Controls first.** A clean identity must be DENIED and a legitimate (sandbox) payer must be ALLOWED. If the
   oracle cannot establish both, no later result is trusted → `UNKNOWN`/`BLOCKED`.
2. **Scenario** per hypothesis on a fresh synthetic identity, tampering only with what a customer controls.
3. **Confirmation** only through the gate: control-denied → feature USED by a never-paid identity → an independent
   clean-session reproduction, with admitted evidence. No `CONFIRMED_P0` without a confirmation token.
4. Everything else is `RULED_OUT` / `UNKNOWN` / `PARTIALLY_VALIDATED` — never a guess about the backend.

The chain engine composes the declared, individually-harmless primitives into a no-payment sequence: a guided
forward search grows one ordered spine; iterative error-driven field learning satisfies each server-named input
(ids, nonces, digests, signatures) from harvested or legitimately-constructed values; and a bounded, opt-in
concurrency probe overruns check-then-act limits — including a **deep** TOCTOU that first re-establishes the
discovered prefix on a fresh identity, then bursts the terminal one-shot with that prefix's context. A further
opt-in, FAIL-CLOSED **convergence probe** (B49) composes SEVERAL independent sub-chains whose outputs converge at a
single terminal step: it satisfies each step's inputs from the authorised brief's declared schema — so an opaque
target that never names a field no longer blinds learning — and mints the required capabilities as a synchronised
concurrent burst, so a same-window freshness quorum is met where a sequential spine busts it.

---

## Architecture & agents

```
app/
  testing/integrity/     PureBlackBoxEngine + the method:
                         engine, oracle, oracle_calibration, session (guarded customer session),
                         brief (Execution Brief + RoE), confirmation via the control port,
                         attack_chain, race_window, replay, regression, findings, narrative, ...
  testing/agents/        the agent layer (26 wrapped agents in 5 groups):
                         recon (7), attack (4), proof (5), orchestration (4), domain_packs (6)
  testing/integrity/kill_chain_roster.py    B37: the fixed 35-agent fleet roster (declarative, scope-gated)
  testing/integrity/fleet_orchestration.py  B33: FAIL-CLOSED orchestrator — emits plans/leads only
  enterprise_controls/   the safety spine: scope guard (token-bucket RoE), provenance ledger
                         (admits only redacted, in-scope evidence), purity audit, quarantine guards
  core/control_port/     the control adapter (confirmation gate, evidence ledger, fail-open/closed policy)
```

**Agents.** The engagement fleet is a *fixed, declarative* roster of 37 agents (A1–A39 minus two cross-cutting
core capabilities; A1/A17 are documented gaps), **35 activatable**. It is not a spawner — there is no runtime agent
creation and no dynamic capability. 26 are real wrapped agents grouped as recon / attack / proof / orchestration /
domain-packs; 9 are satisfied directly by their capability module. Each agent carries a **scope status**, so an
out-of-scope capability (e.g. the declined AD/cloud attack-path operators) is never activatable, and the
orchestrator (`fleet_orchestration`, B33) consults the roster before scheduling — it composes plans and leads over
the pre-registered payment-oracle capabilities and **dispatches nothing itself** (FAIL-CLOSED).

**Safety spine.** Every outbound call passes the scope guard (host allowlist + a token-bucket rate/volume cap);
every piece of evidence passes the provenance ledger (rejected unless redacted and in-scope); the purity audit
enforces that engine/method code imports no benchmark, test, or quarantined white/grey-box code. `cryptography` is
the only third-party runtime import of the core (standard client crypto for Ed25519/HMAC).

---

## Boss coverage

Each boss is a synthetic, correctly-defended paywall with exactly one honest reachable path; the engine must FIND
the no-payment chain (NYX: converge a multi-branch quorum rather than grow a single spine), and removing any single
flaw must drop it to 0 (each flaw load-bearing), with the all-correct variant yielding 0 after an exhaustive search. All counts are measured by running the code.

| Boss | Depth | Signature challenge | Calls |
|---|---|---|---|
| Aurelia | 4 | recon + ordering-gated chain, HMAC-webhook dead-end | 287 |
| Helios | 5 | reverse-engineered route + two-reference/one-time-nonce commit | 425 |
| Obsidian | 6 | `Location`-header capability + signed-webhook dead-end | 477 |
| Citadel | 7 | zero-trust, client-signed request step | 515 |
| Aegis | 8 | two DPoP-style freshness-signed steps | 598 |
| Vault | 9 | asymmetric Ed25519 signed steps + key registration | 815 |
| Obelisk | 10 | RFC 9421 content-digest-bound signing | 887 |
| Leviathan | 11 | every control at once + replay-aware forged webhook | 1,118 |
| Rampart | — | a *beatable* signed webhook (leaked secret); correct one unbeaten | forge ✓ |
| Sentinel | 12 | needle: one buried algorithm-confusion flaw in a correct ceremony | 998 |
| Pantheon | 14 | deny-by-default maze, 4 load-bearing flaws + hidden capability-URL | 1,187 |
| Olympus | 16 | two services + SSRF hop, sign over the relayed inner path | 1,499 |
| Cosmos | 18 | service mesh + forged async webhook callback (correlation-bound) | 1,751 |
| Pangaea | 20 | double callback hop + numeric business-logic + cross-tenant BOLA | 2,479 |
| **Chronos** | **22** | **double forge prefix + a DEEP in-chain TOCTOU race (prefix-then-burst)** | **3,451** |
| **NYX** | **quorum** | **opaque errors (~99.9%, 0 grants) + a freshness-windowed 3-capability quorum (schema-driven, synchronised concurrent mint)** | **993** |

Guardrails (re-verified every change): enterprise-hard population detection **1.0** / false-positive **0.0**;
purity audit **0 violations**; offline suite **831 passed / 0 failed** (3 errored only because optional DB/web
deps are absent — not defects).

---

## Setup & run

### MacBook Air (Early 2015), macOS Monterey 12.7.6

The core engine + benchmark run on Python alone with a single dependency (`cryptography`); the repository ships
stub `httpx` / `pydantic` shims so no web or database stack is needed. No Docker, no Node, no network.

```bash
# 1. Install Homebrew if you don't have it (https://brew.sh), then a modern Python:
brew install python@3.11

# 2. From the repository root, create and activate a virtual environment:
python3.11 -m venv .venv
source .venv/bin/activate

# 3. Install the one runtime dependency:
pip install --upgrade pip
pip install "cryptography>=42,<46"

# 4. Run a boss (from the backend/ directory). The PYTHONPATH wires in the test shims:
cd backend
export PYTHONPATH="tests/verification_infrastructure/shims:tests/verification_infrastructure:."

# the newest capstone (NYX — opaque errors + a freshness-windowed multi-branch quorum) with full controls:
python3 tests/verification_infrastructure/hardened_benchmark/run_nyx.py --controls

# any other boss:
python3 tests/verification_infrastructure/hardened_benchmark/run_chronos.py --controls
python3 tests/verification_infrastructure/hardened_benchmark/run_pangaea.py --controls
python3 tests/verification_infrastructure/hardened_benchmark/run_cosmos.py

# a randomized held-out family (fresh seeds each line is self-contained):
python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_families15.py
```

A convenience runner at the repository root runs a chosen boss (or all of them):

```bash
./run-benchmark.sh chronos        # one boss
./run-benchmark.sh all            # every boss + every held-out family
```

The Apple-supplied `python3` on Monterey also works if it is 3.9 or newer; Homebrew's `python@3.11` is recommended
for speed and a clean virtual environment. Each boss run is a few seconds to ~2 minutes on 2015 hardware.

### Full offline test suite (optional)

```bash
pip install pytest pytest-asyncio
cd backend && python3 tests/verification_infrastructure/mini_pytest.py $(find tests -name 'test_*.py' | sort)
```

### Full platform (optional, advanced — not for the 2015 MacBook)

A FastAPI service (`backend/app/api`) and an optional ML cognition layer ship with the code but are **not**
required for the engine or benchmark. They pull a heavy dependency set (`backend/requirements.txt`: FastAPI,
SQLAlchemy, Postgres driver, Optuna, scikit-learn, FAISS, …) and expect Postgres; `backend/Dockerfile` and
`docker-compose.yml` are provided for containerising the API + database. (The Electron dashboard the original
project paired with the API is intentionally **not** bundled here, to keep the repository terminal-first and
light.) Skip this section entirely unless you specifically want the HTTP API — the engine and every boss run with
`cryptography` alone.

---

## Repository layout

```
README.md               this file (top-level prose; see docs/ for the scorecards and the NYX cycle)
run-benchmark.sh         one-command benchmark runner
docker-compose.yml       optional API + Postgres orchestration (not needed for the benchmark)
.gitignore
docs/
  BENCHMARK_SCORECARD.md pure-benchmark scorecard (consumed by the purity test suite)
  NYX_BOSS_CYCLE.md      the NYX Harder-Boss→MISS→fix→FIND→Upgrade cycle (boss + B49 convergence probe)
backend/
  app/                   the engine, agent layer, and enterprise-controls safety spine
  benchmark/             the LLM-replacement layer and scoring (no live AI)
  tests/verification_infrastructure/
    hardened_benchmark/  the 16 bosses (boss_*.py / run_*.py) and the randomized held-out families (gauntlet_*)
    shims/               stub httpx / pydantic so the benchmark needs no web stack
  requirements.txt       full-platform dependencies (optional; the benchmark needs only `cryptography`)
  requirements-dev.txt   test-runner dependencies (optional)
  Dockerfile             full-platform container (optional)
```
