# BOSS "ABRAXAS" — the Enterprise Apex → Clean MISS → Fix → FIND → Upgrade

A reproducible record of the largest single capability-raising cycle on the hardened black-box benchmark. A new
apex target — **ABRAXAS**, "the god above the gods" — was built to the hardening standard of the biggest payment
platforms (Stripe, PayPal/Adyen, Apple App Store, Google Play), with **every** published control implemented
*correctly* and an anti-reverse-engineering shell that leaves **no open door and no usable signal**. It defeats the
current engine with a **clean miss**. The engine was then upgraded with one new, fail-closed capability **family**
(B50, four sub-capabilities), and it now **finds and reproduces** the planted no-payment ENTERPRISE bypass — with
every flaw proven load-bearing and no false alarm.

Everything here is **synthetic and in-process**: ABRAXAS is a local `asyncio` HTTP target on `127.0.0.1`; there is
no external system, no real payment, no network. The engine is driven exactly as against any benchmark target,
under the same ScopeGuard RoE budget and the same ConfirmationGate.

Run it:

```
cd backend
PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
    python3 tests/verification_infrastructure/hardened_benchmark/run_abraxas.py --controls
```

---

## 1. The thesis: the enterprise crypto perimeter is *necessary but not sufficient*

ABRAXAS is engineered to make the standard payment-security playbook look like a **floor, not a ceiling**. Every
control the leading platforms publish is implemented here the way the primary sources say to — and **none of them
is the flaw**. The paywall falls to *business-logic composition* that lives entirely behind the crypto perimeter.

| Enterprise control (as published) | How ABRAXAS implements it — correctly | Reference |
|---|---|---|
| Webhook authenticity = **three independent layers** | HMAC-SHA256 over the **raw** bytes (`v1` scheme), 300 s freshness tolerance, **and** durable event-id dedup — "none substitutes for the others"; secret never leaked | [OWASP Webhook Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html) |
| **Server-side** status verification | entitlement only from the server-retrieved PaymentIntent `status == succeeded`; the return/success URL is never trusted | Stripe guidance |
| Amount / currency reconciliation | the amount is **recomputed** server-side from the catalog; client amount/currency ignored | Stripe |
| **App Store-style signed-transaction** settlement | `settlement/jws`: the signed transaction's cert chain must terminate at the trusted root **and carry the required marker OIDs** with the exact chain length, verified against the transaction's own signed time — chaining-to-root alone is forgeable; the marker OIDs are what make it sound; key never leaked → unforgeable dead-end | [go-iap #348 / PR #350](https://github.com/awa/go-iap/issues/348) |
| **Device-attestation**-gated instant purchase | `purchase/direct`: a fresh, server-verified attestation bound to a one-time nonce (Play Integrity / App Attest / DeviceCheck class) — a synthetic client can't forge it; and a *genuine* attestation would still prove only device integrity, never entitlement | [Play Integrity](https://developer.android.com/google/play/integrity/overview), [Guardsquare](https://www.guardsquare.com/blog/android-and-ios-app-attestation) |
| Risk scoring + **3DS / SCA step-up** | a short-lived step-up challenge is required at settlement (Radar-style "request 3DS when risk != normal") | [Stripe Radar rules](https://docs.stripe.com/keys/restricted-api-keys) |
| **Scoped / restricted** credentials (BFLA) | every internal/admin/mesh route refused; a dense 15-service mesh deny-list | [Stripe restricted keys](https://docs.stripe.com/keys/restricted-api-keys) |
| Idempotency / replay | single-use mint handles, one-shot capability references, event-id dedup | [PayPal-Request-Id](https://developer.paypal.com/api/make-api-requests), [Adyen](https://docs.adyen.com/development-resources/mtls) |
| Object/function/property authorization | every capability is org-scoped (BOLA closed); client-settable fields recomputed | [OWASP API Top-10 2023](https://www.indusface.com/learning/owasp-api-top-10/) |

The published attestation literature states the thesis outright: *"backend signature verification still succeeds
because the JWT itself is genuine, so your server still needs its own business-logic checks."* ABRAXAS is the proof
by construction — the entire crypto perimeter is sound, and the composition flaw survives all of it.

### The anti-reverse-engineering shell (closed doors only — nothing to learn)

Built along the deception-control playbook (uniform responses + honeytokens + graduated step-up):

- **Uniform, constant-shape rejection.** Every business / validation / authorization / not-found rejection
  collapses to one opaque answer — `422 {"error":"unprocessable_entity","trace_id":<random>}` — no field, no
  code, no status variation. An analyser cannot tell "missing field" from "wrong owner" from "stale" from "unknown
  route". This is what blinds the engine's error-driven field learning (which keys off `res.body["field"]`).
- **Honeytoken decoy mesh.** `config` documents several convergence-shaped settlement routes; all but one are
  canaries that look identical on the wire and never grant.
- **Short-lived step-up challenge.** The real settlement needs a fresh nonce (TTL ~0.10 s) that expires before the
  slow attestation DAG finishes if fetched up-front.
- Measured hardening under a **3,000-probe adversarial sweep: 99.90 % errors (2997/3000), access granted = 0.**

---

## 2. The one load-bearing flaw, behind four orthogonal hard axes

Each axis is a class that public analyses report autonomous web agents (the XBOW family) struggle with, translated
to the payment/entitlement domain:

- **Axis 1 — dependency-ordered mint DAG** *(multi-step business logic)*. The quorum capabilities are not
  independent: `risk_clear` consumes `ledger_cap`; `mandate_affirm` consumes `treasury_cap`. The producing graph is
  2-wide, 3-deep. A flat "mint everything at once" burst fires dependent mints before their inputs exist; a
  sequential assembler mints the two terminal caps too far apart and busts the freshness window.
- **Axis 2 — TOCTOU settlement window** *(the "verify-then-settle" / N-way-burst class)*. Capabilities can only be
  minted at the honestly quoted rate. A legitimate `amend` can later lower a rate but flags the cap for
  re-attestation. `fabric/activate` validates (reattest-clean + fresh), then after a capture round-trip re-reads
  the rate — trusting the now-mutable value and never re-checking reattest. The only route to a $0 net is to amend
  the caps to 0 **inside** the capture window: a check-then-act race. ([x402 analysis](https://arxiv.org/pdf/2605.30998), [NDSS'26 poster](https://www.ndss-symposium.org/wp-content/uploads/ndss26-poster-51.pdf))
- **Axis 3 — honeytoken decoy convergence** *(anti-hallucination / false-positive trap)*. Two higher/equal-fan-in
  routes (`settlement/finalize`, `consortium/clear`) look identical and never grant; a composer that commits to the
  single highest-fan-in step burns its budget on decoys. A confirmation-gated engine cannot false-positive on a
  decoy either — the decoy never flips the oracle.
- **Axis 4 — short-lived step-up challenge** *(freshness-bound late binding)*. The settlement needs a fresh nonce
  that expires faster than the DAG takes to build; it must be acquired **last**, immediately before the terminal.

**The findable no-payment chain** (what the independent prober drives and the upgraded engine rediscovers):

```
signup
  L0:  ledger_open, treasury_open, risk_session, mandate_open                 (opens, concurrent)
  L1:  ledger_entry[rate=Q] => ledger_cap   treasury_post[rate=Q] => treasury_cap     (concurrent)
  L2:  risk_clear[rate=Q, ledger_cap] => risk_cap   mandate_affirm[rate=Q, treasury_cap] => settle_cap  (concurrent, one fresh window)
  LATE: fabric/challenge => activation_nonce      (acquired last; it would expire if fetched early)
  ==>  fabric/activate(risk_cap, settle_cap, activation_nonce) || amend(risk_cap,0) amend(settle_cap,0)   (interleaved race)
  ==>  enterprise   ->   GET /insights/pro proves it
```

The settlement quorum trusts the caps' client-amendable `rate` at capture; two zero-rated caps net **$0 due** and
the entitlement resolver grants **most-generous-wins = enterprise**. No payment is ever made.

---

## 3. The cycle (measured)

| Stage | Setup | Result |
|---|---|---|
| **Truth** | independent prober drives the full chain | real no-payment enterprise bypass **exists = True** |
| **Harder Boss → Clean MISS** | current engine (channel + chain + race + **B49 convergence** ON, **fabric OFF**) | `CONFIRMED_P0 = False` ✓ |
| **Fix → FIND** | upgraded engine (**B50 fabric probe** ON) | `CONFIRMED_P0 = True` ✓ — at `fabric_activate`, ~1,921 calls |

The engine reconstructs the DAG, backtracks past **both** decoys, late-binds the step-up challenge, and wins the
race:

```
candidates tried  = ['settlement_finalize', 'consortium_clear', 'fabric_activate']   (highest fan-in first; both decoys backtracked)
convergence step  = fabric_activate
capabilities      = ['risk_cap', 'settle_cap', 'activation_nonce']
DAG layer 0       = ledger_open + mandate_open + risk_session + treasury_open   (concurrent)
DAG layer 1       = ledger_entry + treasury_post                                (concurrent)
DAG layer 2       = mandate_affirm + risk_clear                                 (concurrent)
race used         = True        late-bound challenge = activation_nonce
```

### Every flaw is load-bearing (remove one → gone), and no false alarm

| Control | truth | engine |
|---|---|---|
| `no-ledger-flaw` | False | False |
| `no-risk-flaw` | False | False |
| `no-toctou-flaw` | False | False |
| `no-rate-trust-flaw` | False | False |
| **ALL-CORRECT** | **False** | **False** (no false positive) |

### The current engine cannot find ABRAXAS under any difficulty relaxation short of trivial

| Current engine (B49 convergence ON, fabric OFF) | result |
|---|---|
| all HARD | False |
| no DAG depth | False — decoy + window + challenge still defeat it |
| no DAG depth, no decoy | False — it has no amend/race capability |
| no DAG depth / decoy / window | False — B49 never lowers a rate |
| no DAG depth / decoy / window / challenge | False — still never lowers a rate |

### Each new capability is individually load-bearing (ablated inside the new probe; target stays HARD)

| Upgraded engine (B50) | result |
|---|---|
| G1 — DAG antichain scheduling OFF (flat burst) | False — dependent mints fire before their inputs |
| G2 — interleaved race OFF (sequential amend) | False — the stale-attestation check turns it away |
| G3 — multi-candidate OFF (decoy only) | False — it commits to the decoy |
| G4 — fresh-challenge late-binding OFF | False — the step-up nonce expires before settlement |
| **full capability** | **True** |

---

## 4. The System Upgrade — B50 settlement-fabric probe (four sub-capabilities)

`app/testing/integrity/engine.py :: PureBlackBoxEngine._fabric_probe` (opt-in via `enable_fabric_probe`,
**fail-closed**: a no-op when off, exactly like the B46 chain, B48 race and B49 convergence probes). It is a strict
superset of the B49 convergence probe, adding one cohesive capability family — each part proven load-bearing above:

- **G1 — topological antichain scheduling.** For a convergence candidate, the required capabilities are resolved
  *transitively* from the declared schema (a mint op's path placeholders **and** its `request_fields` that are
  themselves produced capabilities become prerequisites). The op set is layered by dependency (Kahn) and each layer
  is fired **concurrently**, so cross-branch inputs exist before the mints that consume them *and* the terminal
  capabilities land in one freshness window.
- **G2 — interleaved multi-endpoint race.** If the terminal is refused at the honest rate and a declared
  rate-mutating op applies to the consumed capabilities, the terminal op and the rate reductions are fired as one
  **simultaneous burst**, so the reductions land inside the terminal's check-then-act window.
- **G3 — ranked multi-candidate search with backtracking.** Convergence candidates are ranked by fan-in and tried
  in order, so a higher-fan-in decoy that never grants does not starve the real, lower-fan-in step.
- **G4 — fresh-challenge late binding.** A terminal input produced by a dependency-free, challenge-named op is
  treated as a short-lived step-up challenge and acquired **last** — immediately before the terminal (and
  re-acquired before the race burst) — rather than up-front in a DAG layer.

Confirmation is **unchanged**: a `CONFIRMED_P0` still requires the real protected-feature oracle to flip for a
never-paid identity **and** an independent clean-session reproduction through the ConfirmationGate. The probe stays
on the **declared surface**, uses only harvested + brief-declared **black-box** values, is **opt-in / fail-closed**,
and does not alter the oracle or the gate. A correctly-implemented target (server-recomputed amount, atomic capture,
real paid basis, step-up bound to a real payment) yields no false positive — demonstrated by the ALL-CORRECT and
per-flaw controls.

### It forces the whole engine, not one trick

ABRAXAS is the first boss that exercises the full stack in one chain: **recon** (differentiating the real
convergence from the honeytoken mesh under a signal-free shell), **brainstorming / thinking** (ranked candidate
enumeration + backtracking), **chaining** (the dependency DAG), **speed / parallelism** (layer-concurrent minting +
the interleaved burst — the dimension XBOW is strongest on, now required to clear a freshness window), and the
bounded **attack-chain composition** (`integrity/attack_chain.py`) + **fleet/kill-chain** layers, all held inside
the payment-oracle classes and the ConfirmationGate.

---

## 5. No regression, purity clean

- **Existing apex targets still found** after the engine change: NYX (B49 convergence, clean MISS → FIND unchanged),
  Pangaea, Aurelia.
- **Purity audit** (`scripts/purity_audit.py`): **440 files, 0 violations** across forbidden literals / imports /
  boundary / env-reads / unguarded-http-clients / control-boundary.
- Engine + purity-enforcement unit suites green (`tests/test_pure_engine.py`, `tests/test_purity_enforcement.py`).

---

## 6. Honest scope (what this does and does not prove)

- **Shared authorship + loopback.** As the base scorecard flags, the engine's author also wrote the targets, and
  all timing is local loopback. ABRAXAS narrows the truth-side bias the same way the rest of the suite does: its
  ground truth is computed by an **independent prober** driving the public API, never by reading the flaw flags or
  the engine's oracle. It does not remove shared authorship.
- **The TOCTOU window, freshness window and nonce TTL are modelled timing properties**, calibrated for loopback
  (`mint latency 0.12 s`, `freshness window 0.05 s`, `capture gap 0.08 s`, `nonce TTL 0.10 s`). They demonstrate the
  *capabilities* (dependency-ordered concurrent assembly; an interleaved check-then-act race; late binding of a
  short-lived challenge); a real target's windows would differ.
- **On "ranking above XBOW."** XBOW reached #1 on HackerOne's US leaderboard in mid-2025 (vendor-reported,
  volume-based, human-reviewed). ABRAXAS does **not** make a live-leaderboard claim. It proves, on a reproducible
  benchmark, a *capability class* — autonomous black-box discovery of a dependency-ordered, TOCTOU-raced,
  decoy-screened, step-up-gated, opaque-error business-logic bypass with no false positives — precisely the classes
  independent analyses report autonomous web agents weakest on (context-heavy business logic, multi-step race
  conditions, and blind/indeterminate signal), in the bounded payment/entitlement domain this tool is scoped to.
  "No confirmed P0" never means "no P0 exists": a flaw outside the modelled classes is reported as a gap, not ruled
  out.
