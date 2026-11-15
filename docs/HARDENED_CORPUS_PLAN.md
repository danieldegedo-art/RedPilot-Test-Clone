# Enterprise-Hardened Grey-Box Corpus — PLAN + PROOF + PRE-REGISTRATION

**Status:** Phase 1 (build the hardened corpus, raise the evidential bar, re-freeze the baseline),
under the **authorized GREY-BOX posture** (ADD-ON REVISION).
Written 2026-11-14, BEFORE building any hardened target and BEFORE any hardened measurement, so
the pre-registered expectations below cannot be fitted to a number after the fact.

This is the committed **plan + provenance proof + pre-registration + four-rule attestation** the
mission's iron laws require (*"Prove each source is real + independent before building"*,
*"Pre-register, then measure"*). It governs the NEW grey-box hardened tranche only; see
`docs/REAL_RECALL_SCORECARD.md` for the frozen Phase-1/Phase-2 story.

---

## 0. Posture: AUTHORIZED GREY-BOX, bounded by the four-rule HARD FLOOR

Confirmation is a **grey-box differential** (cross-subject / cross-role / cross-state /
expected-vs-actual), allowed to use authenticated multi-identity signal and the vendor's
**published API spec** — **never** a destructive, exploit, forging, guessing, or bypass action.
The RedPilot `ConfirmationGate` is **unchanged**: control-denied → scenario-allowed →
clean-session reproduction, using only the engine's **own** authenticated identities and their
**own** references. (The engine was already a cross-subject/cross-state differential that never
forges or guesses; grey-box formalizes that and additionally permits published-spec discovery.)

**The four-rule HARD FLOOR — asserted fail-closed as a precondition of EVERY run** (new
`four_rule_gate` in the gauntlet harness; recorded per-run in the scorecard):

1. **No internal access.** Only surfaces a normal AUTHORIZED user can reach. No internal/
   undocumented services, logs, DBs, queues, buses. (Enforced structurally: `/internal`,`/admin`,
   `/__*`,`/_debug` are honeypots → any hit fails the run; `internal_route_hits` must be 0.)
2. **No source code.** Behaviour + the vendor's PUBLISHED API spec/docs only (the engine receives
   the `ExecutionBrief` + base URL — never source).
3. **No network blueprints.** No topology/architecture/infra maps; reachable surface is
   discovered by authorized use + the published spec, not insider maps. (The brief declares only
   customer-facing/published surface + `allowed_hosts`.)
4. **No administrative credentials.** The engine's synthetic identities are ordinary users /
   tenants / low roles; privilege work is strictly bottom-up. (Gate asserts no identity carries an
   admin/root/superuser role.)

Grey-box changes the OBSERVABILITY/ACCESS level; it does **not** grant new attack primitives and
does **not** relax RoE's no-bypass / no-guess / no-forge / no-destructive rules.

**What grey-box legitimately unlocks (used here):** authenticated multi-identity / multi-role /
multi-tenant sessions as the engine's OWN synthetic accounts; the published API spec for
discovery (shadow/deprecated/undocumented-but-reachable endpoints, parameter & object-property
inventory); observed responses, headers, status codes, structured errors, and bounded timing as
non-destructive differential signal.

---

## 1. The generalized critical class (optimize this) and what STAYS OUT

**Generalized critical class (north-star):** *forbidden cross-subject / cross-role / cross-tenant
/ cross-state access* — a server-ENFORCED restriction (a paid entitlement, another subject's
object, a privileged field, a role-gated function, a retired route's access) defeated by BUSINESS
LOGIC, confirmable by a non-destructive grey-box differential. Access-without-payment is the
central, most-developed case (payment/entitlement families); grey-box only makes it easier to
confirm.

**STAYS OUT — the engine must keep ABSTAINING (0 FP), justified by RoE + Spec §20.1 + the
non-destructive QA identity (NOT by "we can't observe it"):** active injection/exploit payloads
(SQL/NoSQL/command/template/deserialization), XSS/CSRF, SSRF-as-exploit, path-traversal-to-RCE,
memory-safety; authentication bypass, credential/session/TOKEN forgery or cracking, SIGNATURE
forgery, id brute-forcing/enumeration, rate-limit bypass; DoS/resource exhaustion, detection
evasion, prompt-injection/LLM red-teaming. The existing `webhook_forgery` family is the standing
proof of correct abstention (signature forgery → engine must NOT confirm).

---

## 2. PROOF — every hardened target maps to a REAL, independently-disclosed flaw with a public fix

Two tranches, eight mechanisms. Reconstructions are faithful to each advisory's *missing/incorrect
check*, not to the host code (see §Limits).

### 2a. Payment / entitlement — access-without-payment, now hardened + grey-box

| Tag | Buried flaw (access without a qualifying payment) | Real advisory (independent) | Ecosystem | Public fix |
|---|---|---|---|---|
| `h_async_auth` | A payment that is **authorized / not yet settled** (a hold / non-succeeded async state) is treated as completed → entitlement without a captured payment. | **GHSA-v4g2-cm5v-cxv7** (Aimeos `ai-client-html`): digital goods downloadable "without valid payment, e.g. if the payment didn't succeed". Corrob.: Medusa #13849 (Stripe `processing` treated as authorized); Paddle "provision only on the completed event". | Composer/PHP | fulfil only after the payment is verified to have really succeeded (terminal captured state). |
| `h_replay_regrant` | **Idempotency-key reuse re-grants.** A single-use confirmation credential is replayable, re-applying the grant with no new qualifying payment. | **GHSA-8mhj-rffc-rcvw / CVE-2026-34210** (`mppx`): "did not check Stripe's `Idempotent-Replayed` header; an attacker could pay once and consume unlimited resources by replaying the credential." | npm | fixed 0.4.11 — detect the replayed response and reject reuse. |
| `h_state_skip` | **State-machine skip to "entitled".** A client-supplied target state jumps the order/subscription straight to completed/active, skipping the pay transition. | **GHSA-qwqm-3jx5-rr8m** (Solidus): "checkout state skip via unvalidated state parameter — pass a later valid state to skip intermediate transitions." | RubyGems | only accept a state already reached/passed; else 422 (Solidus security releases 2026-09-09). |
| `h_federated_skip` | **Multi-service / federated confirm skipped.** The entitlement side accepts a well-formed payment **reference** as proof of completion without verifying it against the gateway (and without binding it to the caller). | **GHSA-7wwh-c3v9-fc55** (OwnPay, PR #623): "`TrustlyGateway::verify()` accepted any non-empty `gateway_trx_id` as completed; now fails closed." Corrob.: FOSSBilling GHSA-7v47-rh46-w923. | PHP | gateway verify fails closed; never trust a bare non-empty reference. |
| `h_claim_stepup` | **Alt-flow / claim grant behind a real step-up.** A claim/redeem route, correctly guarded by a one-time step-up + idempotency, still grants on an **unproven ownership claim** (step-up is anti-automation, not an entitlement check). | **GHSA-jg6q-3qfh-r9f8** (`mppx-condition-gate`): grants from a *claimed* wallet with no proof of control. Corrob.: Ghost **GHSA-xm43-3m56-w3wf** (alternate/donation flow granted paid membership). | npm | require a server-issued proof tied to a real purchase. |

### 2b. Grey-box authorization — the broadened forbidden-access surface

| Tag | Buried flaw (forbidden access, grey-box-confirmable with the engine's OWN identities) | Real advisory (independent) | Ecosystem | Public fix |
|---|---|---|---|---|
| `gb_bola_object` | **Broken object-level authorization.** One tenant reads/uses another tenant's object via a reference the engine legitimately holds for its OWN second tenant (no guessing). | **GHSA-x287-5c68-36wp** (OpenWISP IPAM): "a member of one org can export another org's subnet and all its IPs." Corrob.: InvoiceShelf CVE-2026-55610; stigmem-node GHSA-6gqw-jqv7-v88m. | PyPI/Django | add org/ownership validation at the data-access layer. |
| `gb_bopla_massassign` | **Property-level / mass-assignment escalation.** A low-role identity sets a privileged field (plan/role/entitlement) it must not, via an ordinary update → forbidden state (access without payment). | **GHSA-5448-v74m-7mv7** (Snipe-IT): "privilege attributes insufficiently protected against mass assignment." Corrob.: Netmaker CVE-2023-32079; Spree CVE-2013-2506. | Composer/PHP | allow-list writable fields; reject privileged fields from the caller. |
| `gb_shadow_api` | **Improper inventory / shadow & deprecated API.** A deprecated route (declared in the published spec) grants access the current route's control denies. | **GHSA-9jr7-2hgp-vhp8** (DefectDojo): "APIv1 lacks access controls, deprecated, never fixed." Corrob.: Gitea incomplete-fix parallel-path (control on one route, missing on a parallel route). | PyPI/Django | apply the same authorization check on every route to the resource; retire the uncontrolled path. |

**Independence & verification caveat (honest).** Each advisory was authored by a third party, not
by RedPilot — the flaw's *provenance* (real disclosure + public fix) is independent; only the host
code is reconstructed. The sandbox network does not resolve `osv.dev` or serve GitHub advisory
pages directly; each advisory was confirmed via multiple reachable mirrors (wiz.io, gitlab
advisories, nvd.nist.gov, corgea, solidus.io, Google Groups, GitHub PR pages). Primary GHSA pages
were not reachable from the sandbox — recorded, not hidden.

---

## 3. The hardened grey-box spine (defenses enforced CORRECTLY in BOTH flaw_on and patched)

A new base class `HardenedCommerce` (`targets/_hardened.py`) extends the correct-by-default
`BaseCommerce` with the enterprise defenses, all genuinely enforced. **`_core.py` is unchanged.**
Each flaw target flips **exactly ONE** check; its patched twin flips nothing. Weakening a defense
to make a heuristic bind would be faking. The six defenses:
(1) async/server-authoritative confirmation (grant bound to real capture, not the client return);
(2) idempotency/replay keys on the grant; (3) a one-time step-up challenge before the sensitive
step; (4) server-authoritative pricing + strict validation; (5) rate limiting / bounded
concurrency; (6) tenant/identity binding on every transition. Plus, for 2b, a published-spec
surface with object references, writable-field allow-lists, and a declared-deprecated route.

**Calibration guarantee.** On every target (flaw_on and patched) a legitimate cheapest-plan
success payment leaves the payer entitled and a clean identity denied, so `_establish_controls`
succeeds and the oracle is proven discriminating — every instance is a clean TP/FN, never an
UNKNOWN that could mask a miss, and the 0-FP property stays meaningful. **Dual oracle:** an
independent in-RoE, grey-box `probe_truth` (uses only the engine's own identities/references; no
forge/guess/destruct) returns `True` on flaw_on and `False` on patched, or the target is invalid.

---

## 4. Triple-sealed split (DEV / sealed TEST / author-blind HOLDOUT)

- **DEV** (studyable; Phase-2 dev only): one instance per mechanism (8).
- **TEST** (SEALED — measured, never tuned): different anonymised seeds; the 8 mechanisms plus
  some seen-mechanism/unseen-instance cases, plus hardened **decoys** (correct targets with scary
  async/replay/claim/shadow surface that must stay RULED_OUT → 0 FP).
- **HOLDOUT** (author-blind): generated by a **separate Claude session** that authors its own
  hardened grey-box targets (its own flipped checks, seeds, possibly novel in-RoE variants) to the
  same contract. This session commits to **never** inspecting the HOLDOUT flaw internals and
  measures HOLDOUT **exactly once, at the very end**, after all tuning is frozen. All anonymised
  per seed; TEST/HOLDOUT strings differ from DEV so no literal transfers.

---

## 5. PRE-REGISTRATION — expected find/miss under TODAY's engine on the hardened TEST set

Recorded before measurement. TODAY's engine = all shipped probes ON (channel, chain, race,
convergence, fabric, reconciliation, federation); behaviour probe OFF. **Ceiling hypothesis: none
of these eight is RoE-barred** — each is reachable by an authorised grey-box tester without
forging, bypassing, guessing, or destroying, so a miss is an unmodeled-but-reachable capability
gap, not a ceiling.

| Mechanism | Expected (today) | Why / which Phase-2 capability would earn it |
|---|---|---|
| `h_async_auth` | **MISS** | grant rides a non-settled state the engine never drives; needs state-machine inference of the confirm step (A) / async handling (B). |
| `h_replay_regrant` | **MISS** | needs a replay/over-limit probe keyed on an idempotency credential, distinguishing re-grant from first grant (C). |
| `h_state_skip` | **MISS (likely)** | client-supplied state jump; no per-order state model. Uncertainty: fabric `_amend` may set a state field. |
| `h_federated_skip` | **UNCERTAIN** | extends the shipped federation theme; the federation probe may already reach a cross-service reference skip. |
| `h_claim_stepup` | **MISS (likely)** | undeclared claim route behind a step-up; needs route discovery + the behaviour/alt-flow capability (D). |
| `gb_bola_object` | **MISS** | no cross-tenant object-read differential today; needs a grey-box BOLA probe over the engine's own two tenants. |
| `gb_bopla_massassign` | **MISS (likely)** | privileged-field write on an update; the escalate probe tampers checkout plan/amount, not an arbitrary update field. |
| `gb_shadow_api` | **MISS (likely)** | deprecated-route access; the channel catalog is fixed and will not match the anonymised shadow route. |

**Pre-registered aggregate hypothesis:** hardened-TEST recall of the generalized critical class
under TODAY's engine is **~0.0–0.25** (0–2 of 8), far below the 0.70 the simple payment corpus
shows — with precision 1.0, **0 false positives** on all patched twins and decoys, **0
internal-route hits**, ceiling abstention preserved on `webhook_forgery`, and the four-rule gate
PASS on every run. The drop is the point: it is the honest pre-upgrade number that makes Phase 2
un-fudgeable, and it sets up the proven-ceiling table (each remaining miss classified
unmodeled-fixable / RoE-barred / not-grey-box-reachable).

---

## 6. Honest limits (so the number is not over-read)

- **Reconstruction, not original code.** Faithful Python reconstructions over a real 127.0.0.1
  socket — not the original Ruby/PHP/TS/Go/Python services (standing those up needs live PSPs,
  full frameworks, DBs, and network the policy disallows). Every hardened target is flagged
  **reconstruction**; real-OSS-code and a live authorized-sandbox socket remain the honest
  outstanding provenance gaps, wired only "where feasible".
- **Loopback, not a live provider.** Real socket, real HTTP/1.1, but `127.0.0.1`; no live PSP.
- **Residual engine-side shared authorship** is guarded by the sealed DEV/TEST split and, newly,
  the **author-blind HOLDOUT** — the strongest guard available here.
- **Small per-mechanism sample**, deliberately enlarged (multiple instances + held-out mechanisms
  + HOLDOUT) to shrink per-target author influence, but still a small-sample estimate per cell.
