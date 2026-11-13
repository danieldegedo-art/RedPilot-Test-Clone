# Real-Glue-Code Recall Scorecard

RedPilot's **first real-world recall number**, measured on a frozen, independently-sourced,
anonymized corpus of real disclosed payment/entitlement business-logic flaws the engine had
never seen.

Generated 2026-11-13 by `tests/verification_infrastructure/real_recall_gauntlet/run_gauntlet.py`
(every number below is produced by running TODAY's full engine BLIND over a real 127.0.0.1
socket). Raw run: `tests/verification_infrastructure/real_recall_gauntlet/results/baseline.json`.

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

These six are precisely the material for Phase 2 (behavior-based discovery + a growing
fail-closed flaw-class vocabulary).

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

## The honest answer: point it at a cold real domain — what's the number?

**Baseline (today, pre-Phase-2): ~40% recall of the in-RoE, black-box business-logic flaws,
at ~0 false positives, with another slice of real flaws out of scope by RoE.** The engine
reliably finds flaws that (a) fall in its fixed 10 classes and (b) sit on the canonical payment
flow with an observable tampered field; it reliably misses flaws living in custom glue code
(coupons, alternate flows, order state machines, credit races, claim routes). This sits in the
same band as AnonVul's best real-world business-logic agent (~23–41%) and is **far** below the
1.0 of the self-authored benchmarks — which is the honest point. Confidence in the specific
0.40 is **medium** (small corpus, reconstruction not original code); confidence in the
*direction* (in-vocab+canonical = found, glue = missed, 0 FP, correct RoE abstention) is **high**
(stable across seeds and across the DEV/TEST split).

## Reproduce

```
cd backend
PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:\
tests/verification_infrastructure/real_recall_gauntlet:\
tests/verification_infrastructure/real_recall_gauntlet/targets:. \
  python3 tests/verification_infrastructure/real_recall_gauntlet/run_gauntlet.py --split test
```

## Status

- **Phase 1 COMPLETE and FROZEN:** corpus provenance + DEV/TEST split + honest sealed-TEST
  baseline (recall 0.40, precision 1.0, FP 0, purity clean). The corpus is frozen; the TEST
  split must never be narrowed or tuned against.
- **Phase 2 (next):** behavior-based discovery (bind roles by what endpoints DO) + a growing
  fail-closed flaw-class vocabulary driven only by DEV misses, re-measured blind on sealed TEST.
