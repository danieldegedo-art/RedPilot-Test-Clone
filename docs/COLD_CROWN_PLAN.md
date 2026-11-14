# OPERATION COLD CROWN — PLAN + PROOF + PRE-REGISTRATION

**Status:** Phase 1 (build the COLD black-box gauntlet posture + re-freeze a COLD baseline), then a
first Phase-2 increment (autonomous cold-start surface discovery). Written **2026-11-14, BEFORE
building the cold infrastructure and BEFORE any cold measurement**, so the pre-registered
expectations below cannot be fitted to a number after the fact.

This is the committed **plan + provenance proof + pre-registration + cold-floor attestation** the
mission's iron laws require. It governs the new COLD black-box tranche. The frozen grey-box
Phase-1/Phase-2 story (sealed-TEST recall 0.40 → 0.80) is in `docs/REAL_RECALL_SCORECARD.md` and is
**not** retuned or narrowed here — COLD CROWN only ADDS a strictly harder posture and re-freezes a
harder baseline.

---

## 0. What is new vs. the shipped grey-box result (the honest delta)

The shipped enterprise-hardened result is **grey-box**: the engine is handed an `ExecutionBrief`
that declares, per operation, the **method + path + wire field-names + the semantic role**
(`start_checkout`, `return_flow`, …), and declares each **feature** with `requires_plan`,
`proof_field`, `consumes_quota`, and `observed_via: public_api_reference`. In other words the
grey-box brief hands the engine the *published API spec plus the role/oracle labels*. That is a
legitimate posture — but it is **not cold**.

**COLD CROWN removes the handed-in surface entirely.** In the cold posture the engine is given
**exactly one thing: the base URL**, plus the RoE attestation and `allow_signup: true`. The brief
declares **no operations, no features, no plans, no field-names, no roles, no oracle, no flaw
label**. The engine must reconstruct the entire reachable surface, the state machine, each
operation's role, the plan order, and the paid-feature oracle **purely from authorized interaction
with the product**, then find the buried forbidden-access flaw — all without ever forging, guessing
an id/token, bypassing a control, or touching a non-customer surface.

| Dimension | Shipped grey-box | COLD CROWN (this tranche) |
|---|---|---|
| Routes (method+path) | handed in (brief `surface`) | discovered from the product's own root affordance |
| Which route is checkout / pay / return / a feature | labelled (`name`, role) | **inferred by behaviour** |
| `requires_plan` / `proof_field` / `consumes_quota` | labelled per feature | **inferred by the clean-vs-paid differential** |
| Plan tiers + order | labelled (`plans`) | **inferred from the public pricing response** |
| Request field wire-names | labelled per op | taken from the product's own forms/responses (what a browser sees), **mapped to logical roles by behaviour** |
| Glue-route purpose (authorize/step-up/claim/shadow) | labelled | unlabelled candidate ops; role inferred by behaviour |
| Flaw class / target / on-off | never | never |

Everything to the right of the second column is work the engine must now do itself. This is
strictly harder than the grey-box posture and is the honest meaning of "cold / zero-knowledge."

---

## 1. THE COLD FLOOR — asserted fail-closed as a precondition of every cold run

A new `cold_floor_gate` (gauntlet harness, scorer-side) asserts ALL of the following on the exact
brief the engine will receive, and **fails closed** if any would be violated. Recorded per-run in
the scorecard.

1. **Domain only.** The brief carries `allowed_hosts` (the cold domain), `allow_signup`, the RoE
   attestation, `primary_currency`, and `limits` — and **nothing else**: `operations == {}`,
   `features == {}`, `plans == {}`, `identities == {}`. No surface, no spec, no field-names, no
   roles handed in. (If any is non-empty the run is not cold → fail closed.)
2. **No source / no blueprints / no credentials.** No source/repo/topology/infra/db/credential
   keys anywhere in the brief (the same forbidden-key set the four-rule gate enforces, reused).
3. **No internal/admin/hidden surface.** `/internal`, `/admin`, `/__*`, `/_debug` are honeypots on
   the target; any hit fails the run. The engine discovers surface by authorized use only; the
   ScopeGuard independently blocks internal/admin/debug paths, so `internal_route_hits` must be 0.
4. **Bottom-up identities only.** The engine mints its own ordinary synthetic tenants through the
   product's public sign-up; no admin/root/superuser identity is ever declared or used.

The cold floor is **stricter** than the shipped four-rule grey-box floor: rule 1 additionally
forbids a handed-in surface/spec, which the four-rule floor permitted (`public_api_reference`).

### How surface discovery stays honest (not a disguised spec hand-in)

The engine learns the surface the way a real authorized user's client does — **by using the
product**:
- It issues `GET <base>/` (the product root — the one entry every web product has; hitting the
  site root is authorized use, not scanning). The product returns its **app-bootstrap catalog**:
  the method + path of its customer routes and the wire field-names its forms/responses use —
  exactly what a browser's rendered forms + network traffic reveal to any user. This models "the
  self-service product itself," which the mission explicitly permits.
- The catalog carries **no** semantic labels: not which route is checkout/pay/return/a feature,
  not `requires_plan`/`proof_field`, not the plan tiers, not the privileged field, not the
  shadow-route's deprecation, and never a flaw/advisory hint. Those are exactly what the engine
  must infer by behaviour.
- The same bootstrap is served by **both** `flaw_on` and `patched` targets (it is ordinary product
  behaviour, byte-identical across the twins), so it can never be a flaw hint and cannot move the
  0-FP property.

This is the honest line: the product tells a client *where its endpoints are and what their inputs
are called* (public, true of every real product); it does **not** tell the client *which endpoint
is vulnerable, what gates it, or how to defeat it*. A stricter pure-HATEOAS crawl (follow only
`_links` reachable from each authorized state) is documented as future hardening; this tranche uses
the bootstrap catalog and infers all roles/oracles by behaviour.

---

## 2. PROOF — provenance (reuse of the already-independent hardened mechanisms; no new unverifiable claims)

The cold tranche runs over the **same eight enterprise-hardened mechanisms** whose real,
independent advisory provenance was established and documented in `docs/HARDENED_CORPUS_PLAN.md §2`
(Aimeos GHSA-v4g2-cm5v-cxv7; mppx GHSA-8mhj-rffc-rcvw / CVE-2026-34210; Solidus
GHSA-qwqm-3jx5-rr8m; OwnPay GHSA-7wwh-c3v9-fc55; mppx-condition-gate GHSA-jg6q-3qfh-r9f8 + Ghost
GHSA-xm43-3m56-w3wf; OpenWISP IPAM GHSA-x287-5c68-36wp; Snipe-IT GHSA-5448-v74m-7mv7; DefectDojo
GHSA-9jr7-2hgp-vhp8), plus the `webhook_forgery` ceiling control (New API GHSA-xff3-5c9p-2mr4 /
CVE-2026-41432). The independence is in the **flaw's provenance** (a real disclosure + public fix,
authored by a third party), which is unchanged by the cold posture.

**Why no new families this session (honest limit).** The iron law requires proving each source is
real + independent *before building*. The advisory sources (`osv.dev`, GitHub advisories,
`nvd.nist.gov`, vendor mirrors) are **not reachable from this sandbox** (verified: `osv.dev` →
timeout, `github.com/advisories` → 403, `nvd.nist.gov` → timeout). Rather than invent families with
unverifiable provenance — which would break the iron law — this tranche **reuses the eight
already-proven mechanisms** and makes the corpus genuinely harder along the axis that does *not*
require new provenance: the **cold posture** (the engine loses the entire handed-in surface) and
the demand for **autonomous discovery + role inference**. Corpus *breadth* via new real advisories
is deferred to a session with advisory-network access; it is named here, not hidden.

Each target remains a **reconstruction** over a real `127.0.0.1` socket (no original OSS code, no
live PSP in this sandbox). Real-OSS-code and a live provider-test-mode socket remain the honest
outstanding provenance gaps, flagged per target in the scorecard (`real_code=False`,
`live_sandbox=False`, `transport=loopback`).

---

## 3. The cold spine (what changes on the target, and what must NOT)

The hardened spine (`targets/_hardened.py`) gains **one** addition: a customer-reachable
**app-bootstrap** served at `GET /` (and `GET /<prefix>` for the per-seed API prefix) that returns
the catalog of customer routes (method + path) and the wire field-names visible to a browser. It is
served **identically** by `flaw_on` and `patched`, adds **no** route the brief's grey-box surface
did not already imply, reveals **no** role/oracle/flaw label, and does **not** touch any override
hook. The flaw logic and all six enterprise defenses are **byte-for-byte unchanged**. Harvesting a
catalog the product already serves to its own clients is realistic product behaviour, not
target-reshaping: the engine is adapted to the target, never the target to the engine.

**Calibration + dual-oracle guarantees are preserved** exactly as in the hardened plan: on every
target a legitimate cheapest-plan success payment leaves the payer entitled and a clean identity
denied; the independent in-RoE `probe_truth` returns `True` on `flaw_on` and `False` on `patched`
or the target is invalid. The bootstrap addition is re-validated against this on every family.

---

## 4. Triple-sealed split (DEV / sealed TEST / author-blind HOLDOUT)

Unchanged from the hardened plan and reused verbatim:
- **DEV** (seeds 401–408): one instance per mechanism — the only set Phase-2 cold-discovery is
  developed against.
- **TEST** (seeds 501–510 + 590 ceiling, SEALED): the eight mechanisms at different anonymised
  seeds + two seen-mechanism/unseen-instance repeats + the `webhook_forgery` ceiling. Measured
  BLIND, never tuned against. TEST surface strings differ from DEV, so no literal transfers.
- **HOLDOUT** (author-blind): a separate session authors its own hardened cold targets; measured
  **exactly once at the very end**, after all tuning is frozen. Still outstanding (the prior
  sibling was rate-limited before pushing). Completing it is a mission headline; until then the
  sealed TEST blind number is the generalisation evidence.

---

## 5. PRE-REGISTRATION — expected find/miss, recorded BEFORE measurement

### 5a. COLD, pre-upgrade (TODAY's engine, no cold-discovery capability)

TODAY's engine reads only `brief.operations` / `brief.features`. In the cold brief both are empty,
so `_establish_controls` finds **no primary oracle** and returns early: every experiment is BLOCKED
and nothing can be confirmed.

**Pre-registered aggregate:** COLD pre-upgrade sealed-TEST recall of the critical class = **0.00
(0/10)**, precision undefined/1.0 (no positives → no false positives), **FP 0** on all patched
twins/decoys, **0 internal-route hits**, ceiling abstention preserved (`webhook_forgery` → the
engine cannot even reach it → abstain), cold-floor gate **PASS**. The crater is the point: it is
the honest, un-fudgeable floor from which Phase-2 cold-discovery must earn every point.

### 5b. COLD, post-discovery (Phase-2 capability A: autonomous cold-start surface discovery)

A new flag-gated, fail-closed engine capability (`enable_cold_discovery`, default **OFF** → zero
regression by construction) reconstructs the brief from the product's bootstrap + behaviour, then
runs the **unchanged** experiments + grey-box probe through the **unchanged** `ConfirmationGate`.

**Ceiling hypothesis:** cold-discovery can at best recover what the grey-box engine already finds
(the four greybox TPs + the two already-found mechanisms = 8/10 on sealed TEST), and only to the
extent its behavioural reconstruction of the surface is faithful. Per target, pre-registered under
cold-discovery:

| Mechanism (TEST) | grey-box (shipped) | COLD post-discovery (pre-registered) | Why |
|---|---|---|---|
| `h_async_auth` ×2 | TP | **TP (expected)** | authorize-hold op is in the catalog; convergence/fabric drives it once discovered |
| `gb_bopla_massassign` ×2 | TP | **uncertain** | needs the privileged `plan` field harvested from a legit response, then mass-assigned on the discovered update op |
| `h_state_skip` | TP | **uncertain** | needs the order-transition op discovered + a terminal-state value; greybox probe should fire if the op is classified as a glue candidate |
| `h_federated_skip` | TP | **uncertain** | needs the confirm op + own-order reference; greybox probe should fire |
| `h_claim_stepup` | TP | **uncertain** | needs the step-up producer + claim consumer discovered and sequenced |
| `gb_shadow_api` | TP | **uncertain** | needs the deprecated route classified as an alternate-path candidate |
| `gb_bola_object` | FN | **MISS (expected)** | deferred capability D (cross-subject oracle); not built yet |
| `h_replay_regrant` | FN | **MISS (expected)** | deferred capability C (bounded replay/over-limit); not built yet |

**Pre-registered aggregate for cold post-discovery:** between **0.20 and 0.80** on sealed TEST. The
honest expectation is **below** the grey-box 0.80, because cold-discovery must reconstruct roles,
wire-maps, the plan order and the paid-feature oracle by behaviour, and any reconstruction error
cascades to a miss. The number earned is the measured faithfulness of cold-start discovery. HARD
constraints held at every step: **FP 0**, **no regression**, **purity clean**, **cold floor + RoE
intact**, **every confirmation through the unchanged ConfirmationGate**. Every remaining miss is
classified in the proven-ceiling table: reconstruction-gap (name the step), unbuilt-capability
(C/D), RoE-barred, or not-cold-reachable.

---

## 6. Honest limits (so the number is not over-read)

- **Bootstrap-catalog discovery, not a full HATEOAS crawl.** The product serves a route catalog to
  its own clients; the engine consumes it and infers all roles/oracles by behaviour. A stricter
  pure-hypermedia crawl (and structured-error-driven field discovery) is named as future hardening.
- **Reconstruction, not original code; loopback, not a live PSP.** Unchanged from the hardened
  plan. Flagged per target.
- **Reused provenance; no new families this session** (advisory network unreachable — §2).
- **Residual engine-side shared authorship** guarded by the sealed DEV/TEST split and the
  (outstanding) author-blind HOLDOUT.
- **Small per-mechanism sample.** Each number is a small-sample estimate; the point is a frozen,
  honest, reproducible baseline and an earned, measured lift — not a tight confidence interval.
