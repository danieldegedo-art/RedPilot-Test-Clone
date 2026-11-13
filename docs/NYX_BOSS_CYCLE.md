# BOSS "NYX" — Harder Boss → Clean MISS → Fix → FIND → Upgrade

A reproducible record of one capability-raising cycle on the hardened black-box benchmark: a new apex target
(**NYX**) was built hard enough to defeat the current engine with a *clean miss*, the engine was then upgraded with
one new, fail-closed capability family, and it now *finds and reproduces* the planted no-payment bypass — with
every flaw proven load-bearing and no false alarm.

Everything here is **synthetic and in-process**: NYX is a local `asyncio` HTTP target on `127.0.0.1`; there is no
external system, no real payment, and no network. The engine is driven exactly as it is against any benchmark
target, under the same ScopeGuard RoE budget and the same ConfirmationGate.

Run it:

```
cd backend
PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
    python3 tests/verification_infrastructure/hardened_benchmark/run_nyx.py --controls
```

---

## 1. What makes NYX the apex target

NYX is built to put Chronos / Pangaea / Olympus / Pantheon in the shadow by (a) implementing **every** guard those
targets left open, correctly, and (b) hardening the surface along the `qybaihe/bla` ("Blind LLM Agents")
doctrine — **Poison → Exhaust → Hallucinate** — translated to an HTTP payment API.

### Every Stripe guard, implemented correctly (so the miss is clean, not a false negative on a toy)

| Guard (from the Stripe research) | How NYX implements it | What it closes |
|---|---|---|
| Webhook authenticity | HMAC-SHA256 over the **raw** body, `t=`/`v1=` scheme, 300 s tolerance, per-endpoint `whsec_`; **secret never leaked** | forged-event settlement (Pangaea's flaw was a *leaked* secret) → unforgeable black-box dead-end |
| Server-side status verification | the return/success URL is **never** trusted; entitlement only from the server-held PaymentIntent `status == succeeded` | the "fake success redirect" bypass |
| PaymentIntent lifecycle + 3DS/SCA + Radar | `requires_confirmation → requires_action → succeeded`; only `succeeded` grants | "half-paid looks paid" |
| Amount / currency reconciliation | the server **recomputes** the amount from the catalog; client amount/currency ignored | numeric + currency-confusion tampering |
| Event re-fetch + idempotency + event-id dedup | per-event-id dedup set on the webhook path | replay / duplicate |
| BOLA ownership checks | every capability is org-scoped; a foreign cap is refused `403` | cross-tenant / cross-identity |
| Strict mandate / SSRF allowlist / atomic one-shots | mandate must be `active`; mesh routes denied; no check-then-act window | mandate, SSRF, TOCTOU |

### Two anti-RE properties (the Poison / Hallucinate core)

- **Opaque errors (Poison).** NYX **never names a missing or invalid field**. Every rejection is a generic
  `422 {"error":"unprocessable_entity","trace_id": <random>}`. The current engine learns required inputs from the
  server's own validation errors (its field-learning keys off `res.body["field"]`), so opacity blinds it.
- **Freshness-windowed quorum (Exhaust / Hallucinate).** The enterprise grant requires a **quorum of three
  independent capabilities** (`ledger_cap` + `risk_cap` + `settle_cap`), each minted by its **own** sub-chain, that
  must be minted inside one **tight freshness window** (mint latency `0.12 s` ≫ window `0.05 s`). A sequential
  assembler busts the window every time; only a **synchronised concurrent** mint lands all three in one window.

Measured hardening (a 3 000-probe adversarial sweep of the kinds a brute-forcer throws):

```
99.90% errors (2997/3000), access granted = 0
```

### The one load-bearing flaw — a no-payment ENTERPRISE bypass

Buried behind all of the above: the settlement quorum **trusts the three capabilities' client-declared `rate`**.
Three zero-rated capabilities net **$0 due**, and the entitlement resolver grants **most-generous-wins = enterprise**.
No payment is ever made.

The findable chain (what the independent truth prober drives, and what the upgraded engine rediscovers):

```
signup
  ├─ ledger_open   → ledger_entry[rate=0]   ⇒ ledger_cap   ┐
  ├─ risk_session  → risk_clear[rate=0]      ⇒ risk_cap     ├─ minted CONCURRENTLY (one freshness window)
  └─ mandate_open  → mandate_affirm[rate=0]  ⇒ settle_cap   ┘
     → settlement_finalize(ledger_cap, risk_cap, settle_cap) → enterprise
```

---

## 2. The cycle (measured)

| Stage | Setup | Result |
|---|---|---|
| **Truth** | independent prober drives the chain | real no-payment enterprise bypass **exists = True** |
| **Harder Boss → Clean MISS** | current engine (chain + race + channel probes ON, convergence OFF) | `CONFIRMED_P0 = False` ✓ — opacity blinds learning; the sequential spine busts the window |
| **Fix → FIND** | upgraded engine (convergence probe ON) | `CONFIRMED_P0 = True` ✓ via `settlement_finalize` quorum, 993 calls |

The engine reconstructs all three sub-chains and the convergence:

```
convergence step = settlement_finalize
capabilities     = [ledger_cap, risk_cap, settle_cap]
  ledger_cap  = ledger_open  -> ledger_entry
  risk_cap    = risk_session -> risk_clear
  settle_cap  = mandate_open -> mandate_affirm
```

### Every flaw is load-bearing (remove one → gone), and no false alarm

| Control | truth | engine |
|---|---|---|
| `no-ledger-flaw` | False | False |
| `no-risk-flaw` | False | False |
| `no-mandate-flaw` | False | False |
| `no-quorum-flaw` | False | False |
| **ALL-CORRECT** | **False** | **False** (no false positive) |

### The current engine cannot find NYX under *any* difficulty setting (necessity of the upgrade)

| Current engine (convergence OFF) | result |
|---|---|
| opacity ON / window ON | False |
| opacity OFF / window ON | False (the window still busts the sequential spine) |
| opacity OFF / window OFF | False (the target is too large for the brute spine's call budget) |

### Each new capability is individually load-bearing (ablated inside the new probe; target stays HARD)

| Upgraded engine | result |
|---|---|
| schema-satisfaction OFF | False — opacity then blinds it |
| concurrent-mint OFF | False — the freshness window then busts it |
| **full capability** | **True** |

---

## 3. The System Upgrade — B49 multi-branch convergence probe

`app/testing/integrity/engine.py :: PureBlackBoxEngine._convergence_probe` (opt-in via
`enable_convergence_probe`, **fail-closed**: a no-op when off, exactly like the B46 chain and B48 race probes). It
adds one cohesive capability family, each part proven load-bearing above:

- **C1 — schema-driven field satisfaction.** Required inputs come from the **authorised brief's** declared
  `request_fields` / `response_fields` (the public API reference an authorised tester already holds), not from the
  target naming a missing field. An opaque target no longer blinds field learning. *(Purity: the brief schema is
  customer-declared surface, the same provenance as the rest of the brief; no internal/seeded state is read.)*
- **C2 — multi-branch assembly + convergence.** It detects the terminal step that converges several capabilities,
  maps each capability to its producing sub-chain via `response_fields`, and builds each sub-chain. This is beyond
  the chain probe's single greedy spine.
- **C3 — freshness-synchronised minting.** The capability-producing steps are fired as a bounded **simultaneous
  burst** (within the guard's existing token-bucket capacity — not an RoE loosening), so a same-window freshness
  quorum is satisfied where a sequential spine cannot.

Confirmation is **unchanged**: a `CONFIRMED_P0` still requires the real protected-feature oracle to flip for a
never-paid identity **and** an independent clean-session reproduction through the ConfirmationGate. A
correctly-implemented target (server-recomputed amount, real paid basis, atomic/same-window quorum) yields no false
positive — demonstrated by the ALL-CORRECT and per-flaw controls above.

---

## 4. No regression, purity clean

- **Existing apex targets still found** after the engine change: Pangaea (depth-20 chain, 2 479 calls), Aurelia
  (depth-4, 287 calls) — unchanged.
- **Purity audit** (`scripts/purity_audit.py`): **437 files, 0 violations** across forbidden literals / imports /
  boundary / env-reads / unguarded-http-clients / control-boundary.
- The new probe stays on the **declared surface**, uses only harvested + brief-declared **black-box** values, is
  **opt-in / fail-closed**, and does not alter the ConfirmationGate or the oracle.

---

## 5. Honest scope (what this does and does not prove)

- **Shared authorship + loopback.** As the base scorecard flags, the engine's author also wrote the targets, and all
  timing is local loopback. NYX narrows the truth-side bias the same way the rest of the hardened suite does: its
  ground truth is computed by an **independent prober** driving the public API, never by reading the flaw flags or
  the engine's oracle. It does not remove shared authorship.
- **The freshness window is a modelled timing flaw**, calibrated for loopback (`0.12 s` mint latency vs `0.05 s`
  window). It demonstrates the *capability* (synchronised concurrent assembly beats a freshness quorum a sequential
  scanner cannot); a real target's window would differ.
- **On "ranking above XBOW."** XBOW reached #1 on HackerOne's US leaderboard in mid-2025 (vendor-reported,
  volume-based, human-reviewed). NYX does **not** make a live-leaderboard claim. It proves, on a reproducible
  benchmark, a *capability class* — autonomous black-box discovery of a multi-branch, freshness-gated,
  opaque-error business-logic bypass with no false positives — in the bounded payment/entitlement domain this tool
  is scoped to. "No confirmed P0" never means "no P0 exists": a flaw outside the modelled classes is reported as a
  gap, not ruled out.
