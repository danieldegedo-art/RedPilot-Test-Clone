# Real-Glue-Code Recall Scorecard

RedPilot's **first real-world recall number**, measured on a frozen, independently-sourced,
anonymized corpus of real disclosed payment/entitlement business-logic flaws the engine had
never seen.

Generated 2026-11-13 (Phase 1) / 2026-11-14 (Phase 2) by
`tests/verification_infrastructure/real_recall_gauntlet/run_gauntlet.py` (every number is
produced by running the engine BLIND over a real 127.0.0.1 socket). Raw runs under
`tests/verification_infrastructure/real_recall_gauntlet/results/`.

**Headline:** sealed-TEST recall **0.40 → 0.70** at **0 false positives**. Two honest
components, kept separate in §PHASE 2: richer-but-realistic recon (declaring customer-facing
glue routes) lifts today's engine 0.40 → 0.50, and the new **behaviour-based discovery**
capability lifts it **0.50 → 0.70 on identical briefs** — earned on held-out glue code,
including a flaw **class the engine was never shown** (`proof_of_control`), with no regression.

**Harder baseline + earned lift (2026-11-14):** a NEW **enterprise-hardened, grey-box** corpus
re-froze the bar. Today's engine on the sealed hardened TEST set scored **0.40 grey-box / 0.20
black-box** (down from 0.70 on the simple corpus — the honest cost of hardening). One new
flag-gated, fail-closed capability (the **B60 grey-box sequencing probe**), developed against DEV
misses only and measured **BLIND** on the sealed TEST, then raised it **0.40 → 0.70 (7/10)** — at
**0 false positives, 0 internal-route hits**, correct RoE-ceiling abstention, four-rule PASS on
every run, and **no regression**. Three TEST misses remain, each with a named next capability. See
**§PHASE 1-HARDENED (GREY-BOX)** and **§PHASE 2 earned lift** at the end, and
`docs/HARDENED_CORPUS_PLAN.md` (committed before measurement).

---

## The brutal truth this corpus exists to kill

Every prior RedPilot green (the purity benchmark, the DEMIURGE/boss cycle, the families
gauntlets) is on **synthetic, self-authored, loopback** targets: one author wrote the engine,
the targets, and the planted flaw. On a cold real domain that bias makes those 1.0s almost
meaningless as evidence of finding an **unknown** flaw on a **real** surface. This scorecard
removes the flaw's provenance from the author: every target reproduces a **real, publicly
disclosed** payment/entitlement business-logic vulnerability **that has a public fix**, drawn
from independent open-source projects. The engine is on trial against them.

## Read these limits FIRST (so the number is not over-read)

- **Reconstruction, not the original codebases.** Targets are faithful Python reconstructions
  of each advisory's *missing/incorrect check and request sequence* — not the original Ruby/
  PHP/TS code. Independence is in the **flaw's provenance** (a real disclosure + public fix,
  not invented by me) and in reconstructing to the real root cause, **not** in the host code.
  This is weaker than AnonVul (which runs real external code) but far stronger than all-synthetic.
- **Residual shared-authorship on the ENGINE side.** The same person who reconstructs the
  targets also edits the engine in Phase 2. The guard is the sealed DEV/TEST split + the rule
  that Phase-2 changes must generalize to **held-out** TEST instances/classes and never
  special-case a literal (surface strings are anonymized per seed so no literal survives DEV→TEST).
  It is a guard, not a proof; a truly external holdout would be stronger.
- **Loopback, not a live provider.** Engine↔target is a real TCP socket (real HTTP/1.1, real
  latency, real connection teardown) — not in-process calls. But it is `127.0.0.1`, and there
  is **no live Stripe/Mollie/etc.**; the glue logic is reconstructed locally. A live
  provider-test-mode run needs operator-supplied scope/credentials (not available in this
  sandbox).
- **Small corpus.** 11 flaw families, 18 instances (+ their patched counterparts). Each number
  is a small-sample estimate. The point of Phase 1 is a FROZEN, honest *baseline*, not a
  tight confidence interval.
- **RoE carve-out is real and intentional.** Flaws reachable only by forging a provider
  signature, bypassing auth, or guessing ids are **out of RedPilot's authorised method** and
  are reported as the *ceiling*, not as recall misses. See §Honest ceiling.
- RedPilot's RoE / fail-closed / sandbox-only / signed-scope contract is fully intact; this is
  a QA measurement harness, nothing is run against any live or third-party system.

## Method (un-fudgeable by construction)

- **Dual (differential) oracle.** Every family ships `flaw_on` and `patched`. A find only
  counts if the engine confirms on `flaw_on`; any confirm on `patched` is a false positive.
- **Independent hidden truth prober.** Ground truth per instance is computed by a prober that
  drives the target's public API as an omniscient attacker, with **zero** reference to the
  engine's oracle or to the `flaw_on` flag beyond constructing the instance. Every in-scope
  `flaw_on` instance below has `truth=True` AND its `patched` twin has `truth=False`
  (`dual_oracle_valid` holds for all — no invalid targets).
- **Anonymization (AnonVul-style).** Route paths and wire field names are brand/version/
  advisory-stripped and **vary per seed** from a semantics-preserving synonym pool. Names are
  chosen without reference to the engine's keyword sets. TEST strings ≠ DEV strings.
- **Blind.** The engine receives only an `ExecutionBrief` (an authorized happy-path recon
  view) + the base URL. It is never told the class, the target, or whether the flaw is on.
  Glue-code-only routes and attack-only fields are **not** declared — the engine must discover
  them. The brief declares only what a recorded authorized paid session + the public pricing
  page would reveal.
- **TODAY's full engine.** All shipped probes ON: channel, chain, race, convergence, fabric,
  reconciliation, federation (`harness.TODAY_ENGINE_PROBES`). No Phase-2 upgrade is in this set.

## Corpus provenance — every target is a real, independently-disclosed flaw with a public fix

| Family | Real advisory | Package (ecosystem) | Mechanism | Public fix | Engine class | Scope |
|---|---|---|---|---|---|---|
| `amount_binding` | GHSA-c2fq-w6qj-3hj4 | Solidus (Ruby/Rails) | server trusts client-supplied payment amount → underpayment | Solidus 4.7.1 / 4.6.3 (server-authoritative amount) | PBB-F price-binding | in-scope |
| `unconfirmed_payment` | GHSA-8r29-2mp2-pmrw | @payloadcms/plugin-ecommerce (npm) | order treated as paid without a captured payment | verify payment before confirming order | PBB-U unconfirmed-pay | in-scope |
| `cross_tenant_grant` | GHSA-h3rm-78g3-j7cp | @better-auth/stripe (npm) | subscription action trusts a client-named beneficiary org | authorize reference/org id against caller | PBB-G cross-tenant | in-scope |
| `cross_identity_redeem` | GHSA-vgwx-9pm9-8qvj | Solidus (Ruby/Rails) | a payment is redeemable by a non-owning identity | bind payment to its owner | PBB-X cross-identity | in-scope |
| `coupon_reuse` | GHSA-3p9j-442x-hjp7 | microweber (PHP) | single-use coupon redeemable repeatedly | microweber 1.2.11 enforces single-use | glue: coupon lifecycle | in-scope |
| `discount_disabled_api` | GHSA-qjfx-fvx7-3wvw | microweber (PHP) | disabled coupon still honored via API | API honors the enabled flag | glue: coupon lifecycle | in-scope |
| `alt_flow_entitlement` | GHSA-xm43-3m56-w3wf | Ghost (npm) | paid entitlement via a cheap alternate (donation) flow | donation flow no longer grants membership | glue: alternate-flow | in-scope |
| `completed_order_mutate` | GHSA-5597-7rmh-97q5 | Sylius (PHP) | an already-completed order can be mutated (free upgrade) | terminal-state order is immutable | glue: order state-machine | in-scope |
| `credit_balance_race` | GHSA-pgcq-8grm-5rx9 (+ GHSA-5gmm-hjfj-8ff7) | paymenter (PHP) | non-atomic credit check → concurrent double-spend | paymenter 1.5.5 (lock in a real transaction) | near PBB-C, but a race on an undeclared route | in-scope |
| `proof_of_control` | GHSA-jg6q-3qfh-r9f8 | @insumermodel/mppx-condition-gate (npm) | access from a *claimed* ownership with no proof | require server-issued proof of a real purchase | near PBB-OPEN/U, via an undeclared claim route | in-scope |
| `webhook_forgery` | GHSA-xff3-5c9p-2mr4 / CVE-2026-41432 | New API (Go) | empty webhook secret → forge provider events → grant | require a non-empty secret + verify status | provider-event authenticity | **ceiling (out of RoE)** |

Related confirmations observed in the same disclosure seam (not reconstructed; they reinforce
that the seam is real): shopper GHSA-9rh9-hf3w-9fgg (discount over-redemption race), n8n
GHSA-jf52-3f2h-h9j5 and sylius/mollie GHSA-rc52-c4hv-w89p and WooCommerce-Stripe
GHSA-7cxm-23jc-4x3x (webhook signature bypass — all ceiling), Sylius GHSA-6955-hrm5-c4qp
(payment-method restriction bypass), Sylius GHSA-mr9r-h354-966r (payment IDOR — ceiling, id guessing).

## DEV / TEST split (TEST is SEALED — measured, never tuned)

- **DEV** (studyable; Phase-2 development only): `amount_binding`#101, `cross_tenant_grant`#102,
  `unconfirmed_payment`#106, `coupon_reuse`#103, `alt_flow_entitlement`#104,
  `credit_balance_race`#105, `completed_order_mutate`#107, `webhook_forgery`#108 (ceiling).
- **TEST** (sealed): different seeds. Contains **seen-class/unseen-instance** cases
  (`amount_binding`#201, `unconfirmed_payment`#202, `cross_tenant_grant`#203, `coupon_reuse`#205,
  `alt_flow_entitlement`#207, `completed_order_mutate`#208, `credit_balance_race`#209) AND
  **held-out classes absent from DEV** (`cross_identity_redeem`#204, `discount_disabled_api`#206,
  `proof_of_control`#210), plus `webhook_forgery`#302 (ceiling). Held-out classes test the
  vocabulary ceiling; unseen instances test surface/name overfit.

## BASELINE — today's engine, BLIND, on the sealed TEST set

| Metric | Value | Detail |
|---|---|---|
| **Recall (in-scope)** | **0.40** | TP=4, FN=6, of 10 in-scope positives |
| **Precision** | **1.0** | TP=4, FP=0 |
| **False positives** | **0** | over 11 patched controls |
| **False-positive rate** | **0.0** | 0 of 11 patched targets confirmed |
| **Ceiling abstention** | **1/1** | engine did NOT forge the webhook (correct) |
| **Internal-route hits** | **0** | engine never touched `/internal`,`/admin`,`/__*` (purity clean) |
| Transport | real socket | `127.0.0.1` TCP, real HTTP/1.1, ~141–143 engine calls/target |

Per-instance (TEST):

| Family | seed | truth | engine confirmed | outcome |
|---|---|---|---|---|
| amount_binding | 201 | True | `PBB-F` | **TP** |
| unconfirmed_payment | 202 | True | `PBB-U` | **TP** |
| cross_tenant_grant | 203 | True | `PBB-G` | **TP** |
| cross_identity_redeem | 204 | True | `PBB-X` | **TP** (held-out class) |
| coupon_reuse | 205 | True | — | FN |
| discount_disabled_api | 206 | True | — | FN (held-out class) |
| alt_flow_entitlement | 207 | True | — | FN |
| completed_order_mutate | 208 | True | — | FN |
| credit_balance_race | 209 | True | — | FN |
| proof_of_control | 210 | True | — | FN (held-out class) |
| webhook_forgery | 302 | True | — | ceiling-abstain (correct) |

DEV mirror (consistency check, not the headline): recall 0.43 (3/7), precision 1.0, FP 0.
The SAME families find/miss on DEV seeds as on TEST seeds — so the boundary is a property of
the engine, not of a lucky surface.

## Why each find was found, and each miss was missed (honest mechanism)

**Found (4/10)** — all share three properties: the flaw class is one of the fixed 10, it sits
on the canonical `signup→checkout→pay→return→feature` flow the engine models, and the tampered
field is observable in an authorized happy-path trace (so the brief legitimately maps it):
- `amount_binding` → PBB-F: the engine's price-binding experiment submits a tampered amount;
  the amount field is a real checkout param, so it binds.
- `unconfirmed_payment` → PBB-U: the canonical "declined payment + claimed-success return"
  probe fires directly.
- `cross_tenant_grant` → PBB-G: the beneficiary field is happy-path-observable (a legit user
  names their own org), so the cross-tenant experiment can tamper it.
- `cross_identity_redeem` → PBB-X: the engine owns both sessions, so it redeems one identity's
  payment as another.

**Missed (6/10)** — each fails at least one of those properties; the flaw lives in **glue code
the engine does not model**:
- `coupon_reuse`, `discount_disabled_api` — coupon/promo lifecycle is a **declared BLOCKED gap**
  in the purity scorecard; the engine has no coupon probe, and the coupon route+code are
  undeclared glue it never discovers.
- `alt_flow_entitlement` — the grant comes from an unrelated **donation** flow; the engine
  models the subscription flow, not arbitrary alternate flows that side-effect entitlement.
- `completed_order_mutate` — an **order state-machine** violation (mutating a terminal order);
  the engine has no notion of per-order lifecycle state.
- `credit_balance_race` — a **concurrency race on an undeclared credit route**; the engine's
  race probe fires bursts at known ops, not at a glue route it never bound.
- `proof_of_control` — grant via an undeclared **claim** route; the engine's OPEN/unpaid
  heuristics key on the modelled feature flow, not an arbitrary claim endpoint.

These six are precisely the material for Phase 2. (Phase 2 declares the customer-facing glue
routes as realistic recon and adds behaviour-based discovery; it then catches
`alt_flow_entitlement`, `completed_order_mutate` and the held-out `proof_of_control`, lifting
sealed-TEST recall to 0.70 — see §PHASE 2 below.)

## Honest ceiling (what stays out of reach, and why)

- **Provider-event authenticity / webhook forgery / signature bypass** (New API, n8n,
  sylius/mollie, WooCommerce-Stripe): reachable only by forging a signature — **forbidden by
  RedPilot's RoE**. The engine's correct behavior is to ABSTAIN; it does (1/1). These are real
  flaws but permanently outside RedPilot's authorised method. Not recall misses.
- **IDOR / id-guessing** (Sylius payment IDOR): RoE forbids id guessing — ceiling.
- **Flaws invisible to a black-box differential** (internal-only state with no external
  entitlement effect): unprovable by construction; reported UNKNOWN/BLOCKED, never confirmed.
- The ceiling is **not** 0% unreachable and **not** 100% reachable: a meaningful slice of real
  payment vulns is signature/auth/id-class and stays out by design. Honest expectation on a
  cold domain: RedPilot addresses the **black-box business-logic** slice, not the crypto/auth slice.

---

# PHASE 2 — behaviour-based discovery: the measured lift

Phase 2 adds one new engine capability — **discovery by behaviour, not name** (`engine.py`
`_behavior_grant_probe` / `_behavior_escalate_probe`, gated by `enable_behavior_probe`,
default **OFF**). Instead of binding roles from operation NAMES, it treats every DECLARED
operation that is not a canonical-flow role or a feature as a candidate, drives it with
benign/known values, and raises a CONFIRMED_P0 **only** when the real Protected-Feature
Oracle shows an entitlement it should not: a never-paid identity using a paid feature
(PBB-U), or a basic payer reaching the top tier (PBB-F). Operation *roles* are inferred
behaviourally (call it, watch the oracle flip); only field-filling uses the brief's recon
labels. Confirmation is the UNCHANGED ConfirmationGate (control denied + scenario allowed +
clean-session reproduction). It was developed against **DEV** misses only.

### A note on recon realism (why there are two baselines)
Phase-1's baseline used a **sparse** brief: only the core payment flow. But customer-facing
glue routes (coupon redemption, donations, order management, store credit, licence claim)
*are* things a real authorised recon trace includes. So Phase 2 also declares those routes —
**unlabelled** (method+path+observed field names, no role, no flaw hint) — which is more
realistic recon, not target-reshaping (targets are byte-for-byte unchanged). To keep the
engine lift honest and separate from the recon change, we measure a **realistic-recon
baseline** (today's engine on the richer brief) and attribute only the delta above it to the
new probe.

### Measured matrix (sealed TEST, BLIND, real socket; DEV shown for consistency)

| Recon | Engine | Sealed TEST recall | DEV recall |
|---|---|---|---|
| core-flow only | today (all shipped probes) | 0.40 (4/10) | 0.43 (3/7) |
| core-flow only | + behaviour probe | 0.40 (4/10) | — |
| + customer glue routes (realistic) | today | 0.50 (5/10) | 0.43 (3/7) |
| **+ customer glue routes (realistic)** | **+ behaviour probe (Phase 2)** | **0.70 (7/10)** | **0.71 (5/7)** |

Precision **1.0**, false positives **0**, FP-rate **0.0**, RoE-ceiling abstention **1/1**,
internal-route hits **0** in *every* row. The `core-flow + behaviour` row proves the probe is
**fail-closed**: with no glue routes declared it has no candidates and is a strict no-op
(0.40 = the Phase-1 baseline, unchanged).

### Per-find attribution on sealed TEST (realistic recon)

| Family | today | +behaviour (Phase 2) | what the probe did |
|---|---|---|---|
| amount_binding / unconfirmed_payment / cross_tenant_grant / cross_identity_redeem | ✅ | ✅ | (already found; canonical-flow, in-vocab) |
| alt_flow_entitlement | ✅ (chain/channel) | ✅ (also PBB-F) | donation route grants pro to an unpaid identity |
| **completed_order_mutate** | ❌ | **✅ PBB-F** | basic payer escalates to top tier via the discovered order-amend route — **seen class (DEV), unseen instance** |
| **proof_of_control** | ❌ | **✅ PBB-U + PBB-F** | unpaid identity granted via the discovered claim route — **HELD-OUT class, absent from DEV** |
| coupon_reuse / discount_disabled_api | ❌ | ❌ | needs a dedicated *replay/over-limit* probe + a valid code — the grant probe is the wrong oracle (a legit coupon also grants on first use) |
| credit_balance_race | ❌ | ❌ | needs a credit balance the black-box flow offers no way to obtain + a concurrency probe |

The Phase-2 delta over the realistic-recon baseline is **+2 flaws** (`completed_order_mutate`,
`proof_of_control`). `proof_of_control` is the key result: it is a flaw **class the engine was
never shown** (TEST-only), caught by a probe generalised from the DEV "an operation grants
entitlement" pattern — generalisation, not memorisation. Surface strings are anonymised and
differ from the DEV instances, so no literal carried over.

### No regression (the mission's hard gate)
- Purity benchmark suite: **11/11 passed** (`test_purity_benchmark.py`).
- Flagship boss **DEMIURGE**: clean **MISS → FIND** preserved; all per-flaw controls, the five
  capability ablations, the efficiency rider, and the roster-dispatch controls (incl. the
  `disabled_agents` keyword path) pass; no-false-alarm ALL-CORRECT stays False/False.
- Internal-route hits **0** and false positives **0** on every patched counterpart, every row.
- The new probe is default-OFF, so every existing suite runs byte-identical behaviour; the
  guarded calls short-circuit (`if self._enable_behavior_probe and ...`).

### Real-socket data point
Every measurement in this scorecard — Phase 1 and Phase 2, the whole corpus, not one data
point — runs the engine against the target over a **real 127.0.0.1 TCP socket** (real HTTP/1.1
request parsing, real latency, real connection teardown via `_TrackedServer`), not in-process
function calls. The remaining caveat is loopback vs a **live PSP**: there is no live
Stripe/Mollie; the glue logic is reconstructed locally. A live provider-test-mode run needs
operator-supplied scope/credentials (not available in this sandbox).

## Honest ceiling (what stays out of reach, and why) — updated

- **Provider-event authenticity / webhook forgery / signature bypass** (New API, n8n,
  sylius/mollie, WooCommerce-Stripe): reachable only by forging a signature — **forbidden by
  RedPilot's RoE**. Correct behaviour is to ABSTAIN; it does (1/1). Not recall misses.
- **IDOR / id-guessing** (Sylius payment IDOR): RoE forbids id guessing — ceiling.
- **Coupon / discount lifecycle** (`coupon_reuse`, `discount_disabled_api`): two things are
  missing, not one. (1) a **valid promo code** (a recon/authorisation input). (2) even given a
  code, the unpaid-grant probe is the WRONG oracle here: a *legitimate* single-use coupon also
  grants an entitlement on its first redemption, so confirming on "an unpaid identity redeemed a
  code and got access" would **false-positive on the patched target**. Catching these honestly
  needs a dedicated **replay / over-limit probe** (redeem beyond the coupon's limit, or after it
  is disabled, and confirm the *extra* grant) with its own FP control — genuine future work. We
  did NOT bolt this onto the grant probe precisely because it would have cost the 0-FP property.
- **Credit-balance concurrency race** (`credit_balance_race`): needs both a black-box path to
  *obtain* store credit and a concurrency probe bound to the *discovered* spend route. Genuine
  future capability work; races are also the least reliable to confirm honestly, so we did not
  force a flaky win.
- **Flaws invisible to a black-box differential** (internal-only state, no external entitlement
  effect): unprovable by construction; reported UNKNOWN/BLOCKED, never confirmed.

## The honest answer: point it at a cold real domain — what's the number now, and why believe it?

**~0.70 recall of the in-RoE, black-box business-logic flaws, at 0 false positives** — up from
~0.40 before Phase 2 — with the remainder either **out of RoE** (signature/auth/id-class) or
needing a **recon input** (a valid coupon code) or a **deeper capability** (credit-race
concurrency). The engine now finds not only the flaws on the canonical payment flow, but also
flaws in **customer-facing glue routes it has never seen**, by inferring an operation's role
from how it moves entitlement state rather than from its name.

Why believe it: the lift is measured on a **sealed** set the engine was not tuned against;
it includes a flaw **class never shown to the engine** (`proof_of_control`); it holds across
different anonymised seeds and across the DEV/TEST split; false positives stayed **0** on
every patched counterpart; and there is **no regression** on the existing bosses/benchmark.
Confidence in the specific 0.70 is **medium** (11-family corpus, reconstructions not original
code, loopback not live PSP); confidence in the *direction and mechanism* (behaviour-based
discovery genuinely generalises to unseen glue, 0 FP, no regression) is **high**. This remains
well below the self-authored 1.0s and in/above AnonVul's best real-world band (~23–41%), which
is the honest frame.

## Reproduce

```
cd backend
P=tests/verification_infrastructure/shims:tests/verification_infrastructure:\
tests/verification_infrastructure/real_recall_gauntlet:\
tests/verification_infrastructure/real_recall_gauntlet/targets:.
# Phase-1 baseline (core-flow recon, today's engine):
PYTHONPATH=$P python3 tests/verification_infrastructure/real_recall_gauntlet/run_gauntlet.py \
  --split test --recon sparse --engine today
# Phase-2 (realistic recon, + behaviour probe):
PYTHONPATH=$P python3 tests/verification_infrastructure/real_recall_gauntlet/run_gauntlet.py \
  --split test --recon full --engine phase2
```

## Status

- **Phase 1 COMPLETE and FROZEN:** corpus provenance + DEV/TEST split + honest sealed-TEST
  baseline (recall 0.40, precision 1.0, FP 0, purity clean). Corpus frozen; TEST never tuned against.
- **Phase 2 COMPLETE:** behaviour-based discovery added (fail-closed, default-off). Sealed-TEST
  recall **0.40 → 0.70** (0.50 → 0.70 isolating the engine lift from the recon change), 0 FP,
  no regression, purity clean, generalising to a held-out flaw class. Remaining misses are the
  honest ceiling above (RoE, recon-input, or deeper-capability bound).
- **Open future work (honest, not blocking):** give the engine a promo-code recon input + a
  grant-replay probe (coupon classes); a credit-obtain + concurrency-on-discovered-op probe
  (credit race); a live provider-test-mode socket run.

---

# PHASE 1-HARDENED (GREY-BOX) — the enterprise-hardened tranche + the honest pre-upgrade number

Generated 2026-11-14 by the same BLIND runner over the same real `127.0.0.1` socket, on a NEW
**enterprise-hardened, grey-box** corpus (`--corpus hardened`). Plan + proof + pre-registration
were committed BEFORE any target was built or measured: `docs/HARDENED_CORPUS_PLAN.md`. Raw runs:
`results/hardened_today_all.json` (grey-box/full recon) and `results/hardened_today_sparse_test.json`
(black-box/sparse recon). This section does not retune or narrow the simple corpus above — it only
ADDS a harder corpus and re-freezes a harder baseline.

## Posture: AUTHORIZED GREY-BOX within a four-rule HARD FLOOR

Confirmation is a non-destructive grey-box **differential** (cross-subject / cross-role /
cross-state / expected-vs-actual) through the **UNCHANGED** `ConfirmationGate` — allowed to use
authenticated multi-identity sessions and the vendor's PUBLISHED API spec, never a forging,
guessing, bypass, or destructive probe. The four-rule hard floor is asserted **fail-closed as a
precondition of every run** (`four_rule_gate.py`) and attested per-run:

| Rule | How it is enforced | Result (every hardened run) |
|---|---|---|
| 1. No internal access | `/internal`,`/admin`,`/__*`,`/_debug` are honeypots; any hit fails the run | PASS — internal-route hits **0** |
| 2. No source code | the engine receives only the `ExecutionBrief` + base URL; brief rejects source/internal-doc provenance (`observed_via` ∈ published/authorized only) | PASS |
| 3. No network blueprints | the brief declares only customer-facing/published surface + allowed_hosts; blueprint keys rejected | PASS |
| 4. No admin credentials | the engine signs up its own ordinary synthetic tenants; no admin/root identity | PASS |

`grey_box_within_four_rules: true` on all 19 hardened records.

## Corpus provenance — eight hardened mechanisms, each a real disclosed flaw with a public fix

All reconstructions (not original code — see Limits); each flaw flips **exactly one** check behind
six genuinely-enforced enterprise defenses; each patched twin is itself a hardened **decoy** (scary
async/replay/claim/shadow surface, fully correct) and the 0-FP control.

| Family | Kind | Real advisory | Buried flaw (one flipped check) |
|---|---|---|---|
| `h_async_auth` | payment | Aimeos **GHSA-v4g2-cm5v-cxv7** | an authorized/non-settled payment treated as captured |
| `h_replay_regrant` | payment | mppx **GHSA-8mhj-rffc-rcvw / CVE-2026-34210** | idempotency-key reuse re-grants (pay once, replay → extra entitlement) |
| `h_state_skip` | payment | Solidus **GHSA-qwqm-3jx5-rr8m** | client-supplied target state jumps the order to "complete"/entitled |
| `h_federated_skip` | payment | OwnPay **GHSA-7wwh-c3v9-fc55** | entitlement side trusts a payment reference without gateway verification |
| `h_claim_stepup` | payment | mppx-condition-gate **GHSA-jg6q-3qfh-r9f8** (+ Ghost **GHSA-xm43-3m56-w3wf**) | a claim behind a real step-up still grants on an unproven ownership claim |
| `gb_bola_object` | authz | OpenWISP IPAM **GHSA-x287-5c68-36wp** | one tenant reads another tenant's object (missing ownership check) |
| `gb_bopla_massassign` | authz | Snipe-IT **GHSA-5448-v74m-7mv7** | mass assignment lets an ordinary caller set the privileged `plan` field |
| `gb_shadow_api` | authz | DefectDojo **GHSA-9jr7-2hgp-vhp8** | a deprecated/shadow route omits the control the current route enforces |
| `webhook_forgery` (ceiling) | ceiling | New API **GHSA-xff3-5c9p-2mr4 / CVE-2026-41432** | signature forgery → correct behaviour is ABSTAIN (out of RoE) |

Advisory text was verified via reachable mirrors (wiz.io, gitlab advisories, nvd.nist.gov, corgea,
solidus.io, Google Groups, GitHub PR pages); the primary GHSA pages and `osv.dev` were not
reachable from the sandbox network — recorded, not hidden. Every target is a **reconstruction**
(no original OSS code / no live PSP in this sandbox); real-code and live-socket remain the honest
outstanding provenance gaps.

## DEV / sealed TEST split (TEST is SEALED — measured, never tuned)

- **DEV** (seeds 401–408): one instance per mechanism.
- **TEST** (seeds 501–510, sealed; different seeds): the eight mechanisms + two unseen-instance
  repeats (`h_async_auth` 509, `gb_bopla_massassign` 510) + the `webhook_forgery` 590 ceiling.
- **HOLDOUT** (author-blind): generated by a separate session; measured EXACTLY ONCE at the very
  end of Phase 2, after all tuning is frozen (see Status).

## PRE-UPGRADE RESULT — today's engine, BLIND, on the sealed hardened TEST set

| Recon | Engine | Sealed-TEST recall (critical class) | Precision | FP | FP-rate | Internal hits | Ceiling abstain | Four-rule |
|---|---|---|---|---|---|---|---|---|
| black-box (sparse) | today (all shipped probes) | **0.20 (2/10)** | 1.0 | 0 | 0.0 | 0 | 1/1 | PASS |
| **grey-box (published spec)** | today (all shipped probes) | **0.40 (4/10)** | 1.0 | 0 | 0.0 | 0 | 1/1 | PASS |
| grey-box (published spec) | the shipped **behaviour probe** (`phase2`) | **0.40 (4/10)** | 1.0 | 0 | 0.0 | 0 | 1/1 | PASS |
| grey-box (published spec) | **+ B60 grey-box sequencing probe (`greybox`, Phase 2)** | **0.70 (7/10)** | 1.0 | 0 | 0.0 | 0 | 1/1 | PASS |

The shipped behaviour probe (the legacy Phase-2 capability) gives **no lift** on the hardened set
(0.40 → 0.40) and **0 FP** — it was developed on the legacy canonical surface and does not reach
the six hardened misses (each needs a capability it lacks: terminal-state value enumeration,
challenge→claim sequencing, a self-owned-ref precondition, an alternate-path/proof-field oracle, a
cross-tenant object differential, or bounded idempotency-replay). So the pre-upgrade hardened
baseline is a genuine plateau for the existing engine: **grey-box 0.40 / black-box 0.20**, and any
rise must be EARNED by new, flag-gated, fail-closed capability. Raw: `results/hardened_phase2_all.json`.

### PHASE 2 earned lift — the B60 grey-box sequencing probe (0.40 → 0.70, blind, 0 FP)

A new engine capability `enable_greybox_probe` (default **OFF** → legacy/benchmark/boss behaviour
byte-identical; zero regression by construction) generalises the behaviour probe along three
**literal-agnostic** axes, **developed against DEV misses only**: (a) an **own-order ref
precondition** (the never-paid identity creates its OWN order so a ref/receipt field is filled with
the engine's own reference — never a guessed/foreign id); (b) a **semantic terminal-state
vocabulary** tried on state-labelled fields (`complete`/`active`/`paid`/`settled`/… — engine-
authored synonyms, not a target literal); (c) a **2-op challenge→consumer dependency** (a step-up
token is read from its declared producer op and fed into the consumer). Confirmation is the
UNCHANGED ConfirmationGate.

Measured BLIND on the sealed TEST set (never inspected during development; TEST seeds/strings
differ from DEV, so no literal transfers): **recall 0.40 → 0.70 (7/10)**, precision 1.0, **FP 0**,
FP-rate 0, internal hits 0, ceiling abstain 1/1, four-rule PASS. DEV mirror: 0.25 → 0.625 (5/8).
Raw: `results/hardened_greybox_dev.json`, `results/hardened_greybox_test.json`.

| Family (TEST) | before (today/phase2) | greybox | How it was earned (grey-box, in-RoE) | Real differential? |
|---|---|---|---|---|
| `h_state_skip` (503) | FN | **TP** | own order ref + a terminal-state value (`complete`) drives the state-machine skip | yes — gate-confirmed on flaw_on, patched rejects the jump (422) → clean |
| `h_federated_skip` (504) | FN | **TP** | the engine's OWN unpaid order reference presented to the entitlement-confirm op (no forgery, no foreign id) | yes — patched fails closed (payment not verified) → clean |
| `h_claim_stepup` (505) | FN | **TP** | a legitimately-solved step-up token (read from its producer op) + a bare claim | yes — patched demands a server-issued proof (403) → clean |
| already found ×4 | TP | TP | `h_async_auth` ×2, `gb_bopla_massassign` ×2 (unchanged) | yes |
| `gb_bola_object` (506) | FN | FN | needs a cross-tenant object differential (a second own identity reading the first's object) | — |
| `gb_shadow_api` (508) | FN | FN | needs an alternate-path/proof-field oracle (a deprecated route returning the protected proof) | — |
| `h_replay_regrant` (502) | FN | FN | needs a bounded idempotency-replay/over-limit probe | — |

**Adversarial self-review of the three new finds.** Each is CONFIRMED_P0 through the UNCHANGED gate
on the flaw_on target and produced **nothing** on the patched twin (every `neg=TN`, FP=0), matches
the independent prober's in-RoE finding, and uses only the engine's own identities/references — no
forging, guessing, or destructive probe. They are real external differentials, not artifacts. The
lift generalised from DEV to the sealed TEST (the same three mechanisms, different anonymised
seeds) — generalisation, not memorisation.

**Updated proven-ceiling scaffolding — the three remaining TEST misses.** None are RoE-barred (the
RoE ceiling is `webhook_forgery`, abstained 1/1). All three are **unmodeled-but-grey-box-reachable**
with a named capability: `gb_bola_object` (cross-tenant object-read differential), `gb_shadow_api`
(alternate-path proof-field oracle), `h_replay_regrant` (idempotency replay/over-limit probe) — the
next fail-closed, flag-gated increments, each with its own 0-FP control.

DEV mirror (grey-box, consistency check, not the headline): recall 0.25 (2/8), precision 1.0, FP 0.

**The drop is real and is the point.** On the simple canonical corpus today's engine scores 0.70;
on the enterprise-hardened corpus it scores **0.40 grey-box / 0.20 black-box** — the hardening
genuinely buries the access-without-payment flaw behind webhook/async confirmation, idempotency,
step-up, server-authoritative pricing, rate limits, and tenant binding. **0 false positives on all
11 patched/decoy controls, 0 internal-route hits, correct ceiling abstention** in every row.

### Per-target: pre-registration vs outcome (every surprise explained)

| Family (TEST) | Pre-registered (today) | Black-box | Grey-box | Honest reconciliation |
|---|---|---|---|---|
| `h_async_auth` | MISS | **TP** | **TP** | Surprise. The `authorize` hold is a documented payment op; the existing convergence/fabric multi-op probe drives checkout→authorize and the oracle flips. Found even black-box → my pre-reg under-rated the shipped multi-op probe on a documented op. A real gate-verified differential (patched clean). |
| `gb_bopla_massassign` | MISS (likely) | FN | **TP** | Matches "miss (black-box)"; grey-box FIND. Declaring `profile_update` (published spec) + the engine's field-harvesting (it reuses the harvested `plan` field) triggers the mass-assign. The **+0.20 grey-box lift is exactly this** — the posture, not a new capability. |
| `h_federated_skip` | UNCERTAIN | FN | FN | The shipped federation probe did not reach this reference-trust skip (its mint/token pattern differs). A Phase-2 target. |
| `h_state_skip` | MISS (likely) | FN | FN | Confirmed miss — no per-order state-machine model; fabric `_amend` did not catch the state jump. |
| `h_claim_stepup` | MISS (likely) | FN | FN | Confirmed miss — claim route behind a step-up; needs behaviour/alt-flow discovery. |
| `h_replay_regrant` | MISS | FN | FN | Confirmed miss — needs a replay/over-limit probe keyed on the idempotency credential. |
| `gb_bola_object` | MISS | FN | FN | Confirmed miss — no cross-tenant object-read differential today. |
| `gb_shadow_api` | MISS | FN | FN | Confirmed miss — the fixed channel catalog does not match the anonymised shadow route. |

Net: pre-registered ~0.0–0.25; **measured black-box 0.20 (in range); grey-box 0.40 (above range)**.
The over-performance is one documented effect — grey-box published-spec recon lets the EXISTING
engine reach two state/property mechanisms — not an engine upgrade. No post-hoc reclassification:
the pre-registration is in `docs/HARDENED_CORPUS_PLAN.md`, committed before measurement.

### Adversarial self-review of the four finds (real differential, not artifact?)

Each of the four TPs (`h_async_auth`×2, `gb_bopla_massassign`×2) is a CONFIRMED_P0 through the
UNCHANGED ConfirmationGate on the flaw_on target (control denied → scenario allowed → clean-session
reproduction) and produced **nothing** on the patched twin (FP=0). Each corresponds exactly to the
independent prober's in-RoE finding. They are real external differentials, not artifacts. The
`authorize`-op find is a legitimate grey-box discovery of auth-hold-as-paid; the `profile_update`
find is a legitimate property-level-authorization (mass-assignment) discovery.

### The six remaining TEST misses — classified (proven ceiling scaffolding)

None are RoE-barred (the RoE ceiling is `webhook_forgery`, correctly abstained 1/1). All six are
**unmodeled-but-grey-box-reachable** — the in-RoE prober reaches each with the engine's own
identities/references — i.e. genuine Phase-2 capability targets, each with a named mechanism:
`h_state_skip` (state-machine inference), `h_claim_stepup` (alt-flow/claim discovery behind a
step-up), `h_replay_regrant` (idempotency-keyed replay/over-limit probe), `h_federated_skip`
(cross-service reference-trust probe), `gb_bola_object` (cross-tenant object-read differential),
`gb_shadow_api` (deprecated/shadow-route differential). This is the pre-upgrade half of the
proven-ceiling table; Phase 2 turns each into FIND or a demonstrated out-of-reach reason.

## No regression (the mission's hard gate) — verified in this sandbox, AFTER the Phase-2 engine edit

- **Purity audit:** 487 files audited, **0 violations** (uncovered/stale/forbidden-literals/
  forbidden-imports/boundary/env-reads/unguarded-http/control-boundary all 0) — the new B60 probe
  code passes every purity gate.
- **Purity benchmark** (`run_purity_benchmark.py`): detection 1.0, **FP 0, false-assurance 0,
  internal-hits 0**.
- **Flagship boss DEMIURGE:** clean **MISS → FIND** preserved after the engine edit (CONFIRMED_P0
  False with federation OFF, True with the upgraded engine), internal/mesh hits 0.
- **Zero regression by construction:** `engine.py` gained only an additive, **default-OFF** flag
  (`enable_greybox_probe=False`) plus new methods reachable only when that flag is set, so every
  existing run (today / phase2 / DEMIURGE / purity benchmark / legacy gauntlet) executes
  byte-identical behaviour; `brief.py`, `_core.py`, the legacy `manifest.py`, `surface.py` are
  unchanged, and `harness.py`/`run_gauntlet.py` gained only additive `greybox`-mode wiring. The
  pytest suites (`test_purity_benchmark` 11/11, `test_purity_enforcement` 39/39, full 792) could
  not be re-run here (pytest + sqlalchemy/fastapi are not installed in this sandbox), but the
  substantive gates above pass and the default-OFF flag preserves their behaviour.

## The honest answer under grey-box: point it at a cold ENTERPRISE-HARDENED domain — the number?

**Pre-upgrade** (today's engine, authorized grey-box within the four rules): **~0.40** recall of the
generalized forbidden-access class on the sealed hardened TEST set (**0.20 black-box**) — the honest
cost of hardening, down from 0.70 on the simple canonical corpus. **Post-upgrade** (one new
flag-gated, fail-closed capability earned against DEV misses and measured BLIND on the sealed TEST):
**0.70 (7/10)** at **0 false positives, 0 internal hits, correct RoE-ceiling abstention, no
regression** — the enterprise-hardened number is now back at the simple-corpus level, but on a
genuinely harder surface and with a stronger evidential bar (four-rule gate, author-blind HOLDOUT
pending). The three remaining misses are not RoE-barred; each has a named next capability. Confidence
in the direction and mechanism (hardening buries the flaw; a literal-agnostic grey-box sequencing
probe genuinely generalises DEV→TEST at 0 FP; no regression) is **high**; confidence in the specific
0.70 is **medium** (8-mechanism corpus, reconstructions not original code, loopback not live PSP,
author-blind HOLDOUT not yet measured — it is the true generalisation test and remains outstanding).

## Status (Phase 1-Hardened + Phase 2 in progress)

- **Phase 1 COMPLETE and FROZEN:** grey-box hardened corpus (8 real-advisory mechanisms, 6 enforced
  defenses, dual-oracle valid) + four-rule fail-closed gate + DEV/sealed-TEST split + committed
  pre-registration + the honest pre-upgrade number (0.40 grey-box / 0.20 black-box, 0 FP, no
  regression, purity clean, ceiling abstained). TEST never tuned against.
- **Phase 2 IN PROGRESS — first earned lift landed:** the B60 grey-box sequencing probe (flag-gated,
  default-OFF, developed against DEV misses only) lifts sealed-TEST recall **0.40 → 0.70 (7/10)**,
  BLIND, at 0 FP / 0 internal hits / no regression. Three TEST misses remain, each with a named
  next fail-closed capability (BOLA cross-tenant object differential; alternate-path proof-field
  oracle; idempotency replay/over-limit probe). Pursue these against DEV, re-measure BLIND on TEST
  until recall plateaus and every remaining miss has a demonstrated out-of-reach reason.
- **OUTSTANDING:** the author-blind HOLDOUT — a separate session authored partial targets on branch
  `claude/redpilot-holdout-blind` but hit the shared-account 5-hour rate limit before finishing;
  its flaw internals were never inspected by the engine author. Complete it (re-run the sibling
  after the limit resets), then measure it EXACTLY ONCE at the very end, after all tuning is frozen,
  and report that number as the headline generalisation result.
