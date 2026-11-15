# BOSS "PLEROMA" — the Reconciliation Apex → Clean MISS → Fix → FIND → Upgrade

A reproducible record of the capability-raising cycle that puts ABRAXAS in the shadow. A new apex target —
**PLEROMA**, the Gnostic *fullness* that contains and transcends every lesser aeon (ABRAXAS is one power within it) —
was built to defeat the current engine with a **clean miss**, the engine was then upgraded with one new, fail-closed
capability **family** (B52, three sub-capabilities), and it now **finds and reproduces** the planted no-payment
ENTERPRISE bypass — every flaw proven load-bearing and no false alarm.

Everything here is **synthetic and in-process**: PLEROMA is a local `asyncio` HTTP target on `127.0.0.1`; there is
no external system, no real payment, no network. The engine is driven exactly as against any benchmark target,
under the same ScopeGuard RoE budget and the same ConfirmationGate.

Run it:

```
cd backend
PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
    python3 tests/verification_infrastructure/hardened_benchmark/run_pleroma.py --controls
```

---

## 1. The thesis: the whole enterprise/sovereign perimeter is the FLOOR; billing leaks in the RECONCILIATION GAP

ABRAXAS proved the enterprise *crypto* perimeter is necessary-but-not-sufficient. PLEROMA raises that to a second,
larger domain the previous bosses never modelled: the asynchronous **usage-metering + entitlement-reconciliation**
business logic that sits on top of any perimeter. PLEROMA keeps ABRAXAS's **entire** perimeter — implemented
**correctly**, so every one of those routes is an unforgeable dead-end that NEVER grants — and buries the one
load-bearing bypass in the gap between asynchronous settlement authorities.

### Every ABRAXAS/sovereign control, implemented correctly (so the miss is clean, not a false negative on a toy)

| Control (correct, never the flaw) | How PLEROMA implements it | Reference |
|---|---|---|
| Convergence / fabric settlement (`settlement/finalize`, `consortium/clear`, `settlement/atomic`) | require caps that cannot be minted without a real captured basis, and recompute server-side → never grant to an unbacked caller | ABRAXAS; OWASP API Top-10 2023 |
| App-Store-style signed transaction (`settlement/jws`) + device attestation (`purchase/direct`) | HMAC over the canonical body / nonce under a never-leaked signing key → unforgeable | [Apple App Store Server API](https://developer.apple.com/videos/play/wwdc2023/10141/) |
| Payment-versus-payment ATOMIC settlement (`settlement/atomic`, S1) | all-or-nothing; needs two real legs | [CLS / PvP](https://en.wikipedia.org/wiki/CLS_Group) |
| Zero-knowledge per-meter usage proof (`settlement/zkproof`, S3) | correct per-meter verification; unforgeable → dead-end | [Privacy-preserving metering (Rial–Danezis)](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/privacy_in_metering-mainwpes.pdf) |
| Standard-Webhooks settlement, server-side status, amount recomputation, BOLA/BFLA mesh deny, uniform opaque 422 | all retained from ABRAXAS, all correct | OWASP Webhook Cheat Sheet |

### The new domain: asynchronous multi-authority reconciliation (grounded in primary docs)

- **Orb "query-based billing"** — the invoice is a *query* over an immutable event log; amendments apply as a
  **read-path overlay**; a closed accounting period's late activity becomes a **catch-up adjustment** to the next
  period. ([docs.withorb.com/architecture/query-based-billing](https://docs.withorb.com/architecture/query-based-billing))
- **Microsoft Marketplace metering** — the publisher must only emit usage **above the base fee**, so the metering
  authority is structurally **blind** to base usage; reconciliation is a first-class state with a `Mismatch`
  between submitted and processed quantity. ([learn.microsoft.com](https://learn.microsoft.com/en-us/partner-center/marketplace-offers/marketplace-metering-service-apis))
- **Stripe Entitlements** — a permission is created on first activation and **persists** while the subscription is
  active; feature changes propagate only at the next billing cycle. ([docs.stripe.com/billing/entitlements](https://docs.stripe.com/billing/entitlements))

Measured hardening (a 3,000-probe adversarial sweep of the kinds a brute-forcer throws):

```
99.90% errors (2997/3000), access granted = 0
```

### The one load-bearing flaw — a no-payment ENTERPRISE bypass in the reconciliation gap

Buried behind the entire correct perimeter: the settlement reconciliation **trusts a client-declared zero-rate
credit overlay** that the close **locks into the closed period's authoritative aggregate**, and **finalizes** an
enterprise grant on a non-positive net due with **no real captured payment**. No payment is ever made.

The findable chain (what the independent truth prober drives, and what the upgraded engine rediscovers):

```
signup
  period/open                         → period P (state=open; authoritative net_due = enterprise price)
  usage/{P}/overlay(rate=0)           → F1: client-declared zero-rate credit overlay, trusted with no paid basis
  period/{P}/close                    → F2: close LOCKS the unbacked overlay into the authoritative aggregate (→0)
  settlement/reconcile(period=P)      → F3: reconcile TRUSTS the frozen aggregate (not a re-derivation);
                                        F4: it FINALIZES enterprise on net_due≤0 with ZERO real captured basis
  → enterprise (finalized, active)    →   GET /insights/pro proves it
```

---

## 2. The cycle (measured)

| Stage | Setup | Result |
|---|---|---|
| **Truth** | independent prober drives the chain | real no-payment enterprise bypass **exists = True** |
| **Harder Boss → Clean MISS** | current engine (channel + chain + race + B49 convergence + **B50 fabric** ON, reconciliation OFF) | `CONFIRMED_P0 = False` ✓ |
| **Fix → FIND** | upgraded engine (**B52 reconciliation probe** ON) | `CONFIRMED_P0 = True` ✓ via the `period_open → usage_overlay → period_close → settlement_reconcile` lifecycle |

### Why the current engine (even with the B50 fabric probe) cleanly misses

The B50 settlement-fabric composer looks for a terminal step that **converges ≥2 produced capabilities** and wins by
racing a rate-reduction into a check-then-act window. PLEROMA's grant step, `settlement/reconcile`, consumes a
**single** period handle — it is **not** a ≥2-capability convergence, so the fabric/convergence composers never even
select it — and the win is a **sealed-before-settled ORDER** (overlay while open → close → reconcile), **not** a
race. The ABRAXAS convergence/fabric routes are all present but **correct** here, so the fabric probe composes its
DAG, tries its decoys, and is turned away at every one. The uniform opaque 422 blinds the chain probe's error-driven
field learning throughout.

### Every flaw is load-bearing (remove one → gone), and no false alarm

| Control | truth | engine |
|---|---|---|
| `no-overlay-trust-flaw` (`overlay_unbacked` off) | False | False |
| `no-close-lock-flaw` (`close_locks_overlay` off) | False | False |
| `no-reconcile-trust-flaw` (`reconcile_trusts_aggregate` off) | False | False |
| `no-basis-free-grant-flaw` (`reconcile_grants_without_basis` off) | False | False |
| **ALL-CORRECT** | **False** | **False** (no false positive) |

### The current engine cannot find PLEROMA under any difficulty relaxation short of trivial

| Current engine (B50 fabric ON, reconciliation OFF) | result |
|---|---|
| all HARD | False |
| opaque errors OFF | False — there is still no ≥2-capability convergence to compose |
| opaque OFF + reconcile-any-state | False — the bypass is a stateful lifecycle, not a convergence |

### Each new capability is individually load-bearing (ablated inside the new probe; target stays HARD)

| Upgraded engine (B52) | result |
|---|---|
| lifecycle reconstruction OFF | False — no owned closed period to reconcile |
| credit overlay OFF | False — the authoritative net due stays the full enterprise commitment |
| seal-before-settle order OFF | False — the overlay after close is rejected, so nothing is locked in |
| **full capability** | **True** |

---

## 3. The System Upgrade — B52 reconciliation-gap probe (three sub-capabilities)

`app/testing/integrity/engine.py :: PureBlackBoxEngine._reconciliation_probe` (opt-in via
`enable_reconciliation_probe`, **fail-closed**: a no-op when off, exactly like the B46 chain, B48 race, B49
convergence and B50 fabric probes). It adds one cohesive capability family — a class beyond the B50 fabric probe,
because the bypass lives not in a ≥2-capability convergence but in a **stateful resource lifecycle** and an
eventually-consistent **reconciliation gap**:

- **C1 — resource-lifecycle reconstruction.** From the declared surface it reconstructs an *open* op that mints a
  period/resource handle, a rate-bearing *overlay/credit* op on that handle, a *close/seal* op on that handle, and a
  terminal *reconcile* op that consumes the handle. *(Purity: all four are declared operations; only harvested /
  brief-declared black-box values are used.)*
- **C2 — aggregate credit overlay.** It applies the rate-bearing overlay op at **rate 0** to drive the period's
  authoritative aggregate to ≤ 0 — the reconciliation-layer analogue of the numeric/zero-rate class, against a
  whole-period aggregate rather than a single capability.
- **C3 — seal-before-settle ordering.** It applies the overlay **while the period is open**, then **closes**, then
  **reconciles** — the one order in which the unbacked overlay is locked into the closed period's authoritative
  aggregate and survives settlement.

Confirmation is **unchanged**: a `CONFIRMED_P0` still requires the real protected-feature oracle to flip for a
never-paid identity **and** an independent clean-session reproduction through the ConfirmationGate. A
correctly-implemented target (overlay requires a real basis, close defers an unbacked overlay, reconcile re-derives
from real captured bases / requires a real basis to finalize) yields no false positive — demonstrated by the
ALL-CORRECT and per-flaw controls above.

---

## 4. No regression, purity clean

- **Existing apex targets still found** after the engine change: ABRAXAS (B50 fabric, clean MISS → FIND unchanged),
  NYX (B49 convergence, unchanged).
- **Purity audit** (`scripts/purity_audit.py`): **443 files, 0 violations** across forbidden literals / imports /
  boundary / env-reads / unguarded-http-clients / control-boundary.
- The new probe stays on the **declared surface**, uses only harvested + brief-declared **black-box** values, is
  **opt-in / fail-closed**, and does not alter the ConfirmationGate or the oracle.

---

## 5. Honest scope (what this does and does not prove)

- **Shared authorship + loopback.** As the base scorecard flags, the engine's author also wrote the targets, and all
  timing is local loopback. PLEROMA narrows the truth-side bias the same way the rest of the suite does: its ground
  truth is computed by an **independent prober** driving the public API, never by reading the flaw flags or the
  engine's oracle. It does not remove shared authorship.
- **Faithful modelling, not real infrastructure.** PLEROMA models each real platform's reconciliation *logic and
  state* (read-path overlay, closed-period catch-up, base-blind metering, authoritative re-derivation); it does not
  run a real Kafka/ClickHouse pipeline or a real HSM. The business-logic flaw behind the perimeter is real and
  independently prober-findable.
- **Scope unchanged.** Every control is a correct defensive control; the one flaw is "entitlement with no cleared
  payment"; every engine capability reasons only over the declared surface; the oracle and ConfirmationGate are
  unchanged. PLEROMA remains squarely inside the bounded payment/entitlement QA domain this tool is scoped to.
  "No confirmed P0" never means "no P0 exists": a flaw outside the modelled classes is reported as a gap, not ruled
  out.
