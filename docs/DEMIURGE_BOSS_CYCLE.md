# BOSS "DEMIURGE" — the Federation Apex → (PLANNED) Harder Boss → Clean MISS → Fix → FIND → Upgrade

**In one paragraph.** Every prior boss is one declared endpoint beaten by one single-session composer; DEMIURGE is a
nine-service payment **federation** whose surface must be *discovered*, whose correlation token must be *reverse-
engineered*, and whose only flaw is a *confused deputy in the trust gap between services* (the KENOMA) that a single-
session composer is structurally blind to. It forces **4 genuinely-new engine subsystems** — undeclared-operation
synthesis, opaque packed-token field inference, cross-service trust-graph composition, and orchestration-**as-
execution** (the planner→executor jump the wider field treats as state-of-the-art, which RedPilot is currently behind)
— plus 4 load-bearing riders, together covering **all five** of AnonVul's measured agent-failure classes. Honest
limits, kept throughout: it does **not** "beat XBOW" (different domain, synthetic self-authored loopback targets, no
LLM — it *clones their construction rigor*), "harder than Stripe" gets **no number**, and it stays strictly inside
RedPilot's bounded payment-QA scope (§3.7) and no-false-positive discipline. The build is **staged**, each new class
proven load-bearing as it lands, with a defined success bar (§6.1).

> **STATUS: BUILT — the core cycle is measured and green (see §6). FIVE capability classes (B53 discovery, B54 token
> RE, B55 trust-graph, B56 orchestration, B59 analogy) are each proven individually load-bearing, with no false
> positive and no regression, and the capability generalizes on a seeded held-out family (solvable 6/6, unsolvable
> 0/6, clean 0/6). B58 info-gain is built as an HONEST efficiency-only rider (not load-bearing). The
> anonymization-insensitivity experiment (+0.0pp — identity-invariant, vs AnonVul's +19.58pp for LLM agents) and
> roster dispatch (5 owning agents each load-bearing) are now BUILT and measured too — see §6.2. The design below is
> preserved as written; §6 carries the measured scorecard.** The one honest reclassification is B58 (efficiency, not
> load-bearing); the one honest correction is 5 load-bearing agents, not the ~12–14 first estimated.
> Specification-first, the way AnonVul and SEC-bench build a benchmark: spec → construction → certification.
> **Every value marked `(target)` below is a proof obligation the build must meet, not a measured result.** Anything
> that cannot be met is reported as a documented gap or honest boundary, never fudged. The prior cycles
> (`NYX`/`ABRAXAS`/`PLEROMA`) are the template; this one deliberately breaks the template's *shape*.
>
> **v2 changelog (what the red-team rounds changed):** (R1) replaced the shaky "8 brand-new capabilities" with an
> honest taxonomy — **4 new capability *classes* + 4 load-bearing riders**, two of which partially already exist, and
> an explicit contrast with ABRAXAS (which already did 1 class + 4 riders); (R2) the KENOMA seam is now pinned to
> exact operations, a confused-deputy trust graph, and per-edge flaw flags; (R3) a robust ABRAXAS-style clean-MISS
> ladder (misses even if handed the whole surface); (R4) "speed" re-grounded on a freshness window + request budget
> (loopback-valid), not wall-clock; (R5) scope/RoE mechanics for nine services; (R6) the FP firewall named to the real
> `_establish_controls`/`_confirm`/gate; (R7) an **honest per-agent triage** replacing "every single agent"; (R8) the
> held-out family pinned to the real `gauntlet_families.py` generator; (R9) a new **anonymization-insensitivity**
> experiment (RedPilot's structural edge over LLM agents); (R10) metrics beyond binary; (R11) engine-fit to real
> methods/flags.
>
> **Further rounds (R12–R31):** (R12) a capability **dependency-DAG + independence argument** (§4.1), the defense
> against "one capability in a trenchcoat"; (R13) B54 **solvability precondition** (packed-plaintext + partial MAC,
> *not* encrypted) and B58 flagged as the **highest-risk rider**; (R14) the **FP-firewall tier/oracle wiring** made
> concrete (§3.6) and the **reference-PoC vs. discovered-solution** distinction; (R15) "maximal = maximal *meaningful*"
> and the **five-class coverage** claim; (R16) dispatch via the `_exp_u` fall-through (byte-identical when off); (R18)
> **multi-host feasibility verified** against `http_client.py:154`; (R19) **staged, not big-bang** build; (R20) the
> clean-MISS ladder's *why* corrected to the **two-root** structural reason; (R21) the **basis lives inside `ct`** so
> B54 ≠ ladder #12; (R24) a dedicated **scope-creep guardrail** (§3.7 — the most important round: does a
> discovery/RE/executor boss stay inside the payment-QA domain?); (R25) **no-live-LLM** preserved; (R28) a
> **definition of done** (§6.1); (R31) the anonymization delta **honestly bounded** (provider-keyed logic may make it
> nonzero, which is itself a finding).

---

## 0. The thesis — a different *shape*, stated against the strongest counter-example (ABRAXAS)

Every prior capstone is the **same shape**: one synthetic target, fully *declared* in the brief, driven in *one*
session, beaten by *one* composer probe. The honest counter-argument to "DEMIURGE is revolutionary" is **ABRAXAS**,
which already packed **four** orthogonal load-bearing sub-capabilities into a single probe (`_fabric_probe`, B50:
`fabric_use_dag`, `fabric_use_race`, `fabric_multi_candidate`, `fabric_fresh_challenge` — each separately ablated in
`run_abraxas.py`). So raw sub-capability *count* is not the differentiator.

The differentiator is **kind**. ABRAXAS's four are all knobs on one composer, over one **declared** surface, in one
session, using machinery the engine already has (`CustomerSession.call`, `_harvest`, `_confirm`). DEMIURGE forces
**four capabilities the live engine does not possess as subsystems at all**, because the target stops being an
endpoint and becomes a **federation**:

| New capability **class** | Why the engine has *nothing* for it today | Partial prior art (honest) |
|---|---|---|
| **Undeclared-operation synthesis** (discovery) | every probe iterates `brief.operations`; it cannot address an operation that is not already an `OperationSpec` | value/segment *harvesting* exists (`_harvest`; the `route` held-out family discovers an opaque path *segment* from `GET /config`) — but synthesizing a whole new `OperationSpec` does not |
| **Opaque packed-token field-layout inference** (reverse engineering) | all signing capabilities (HMAC/Ed25519/RFC-9421/alg-confusion, ladder 4–10) operate on **known JSON field names**; none infers a **binary packed** layout by differential diffing | none |
| **Cross-service trust-graph composition** (supply chaining) | every composer reasons within one service's produced handles; there is no representation of "service A trusts service B's assertion" | none |
| **Orchestration-as-execution** (B33 promoted) | `fleet_orchestration.py` is *"a PURE PLANNER… issues no requests"*; `attack_chain.py` is *"never a new capability"* — there is no executor holding cross-service state | the planner/graph exist, unused by the live loop |

Promoting a planner to a bounded executor is exactly the **planner+executor** split the wider field treats as
state-of-the-art (VulnBot's Planner/Generator/Executor over a Penetration Task Graph; PDDL-planner + executor agents).
RedPilot is currently *behind* the field on that axis. Closing it is a defensible step-change, not an invented one.

**Honest scale claim (this replaces "8 brand-new capabilities").** DEMIURGE forces **4 new capability classes + 4
load-bearing riders** in one cycle. Every prior cycle added **at most one** class. Four-in-one, over a federation with
an undeclared surface, is unprecedented in this suite — *and* two of the four riders are honestly **generalizations of
existing single-target abilities to the federation**, not new-from-zero. That is the real, defensible revolution.

---

## 1. The capability ledger — today vs. forced, with the honest "new / generalized / wired / verified" tag

| Probe | Dimension | Engine **today** (file evidence) | DEMIURGE **forces** | Honest tag | AnonVul failure class it defeats |
|---|---|---|---|---|---|
| **B53** | 🔎 Recon | harvests *values* from declared GETs (`engine._harvest`); the `route` family finds a path *segment* | synthesize **new `OperationSpec`s** for archon endpoints parsed from the edge's public reference | **NEW class** (beyond value-harvest) | enables all; curbs C-III |
| **B54** | 🔄 Reverse-eng | signs over **known JSON fields** (ladder 4–10) | infer a **binary packed** correlation-token layout by differential diffing; find the region **outside MAC coverage**; alter the basis field | **NEW class** | C-V evidence handling |
| **B55** | ⛓️‍💥 Supply chaining | composes within one service's handles (B49/B50/B52) | reconstruct the **confused-deputy trust graph** across services; find the edge that closes with no real capture | **NEW class** | **C-I policy inference — #1 failure, 34.6%** |
| **B56** | 🪢 Orchestration | B32/B33 **plan, execute nothing** | B33 → **bounded executor** over a Penetration Task Graph; hold cross-service state | **NEW class** | C-II process control, 24.2% |
| **B57** | ⚡ Speed | single-target concurrent minting in a freshness window (NYX #18) | **cross-service** concurrent waves within one token/challenge freshness window, under a hard **request budget** | **GENERALIZED** (rider on B56) | the freshness/budget constraint |
| **B58** | 💭 Thinking | guided single spine; `cognition/experiment_selector` exists **unwired** | **wire** info-gain pruning into the live composer so the federation op-space fits the request budget | **WIRED** (rider on B56) | C-III wrong direction, 22.2% |
| **B59** | 🧠 Brainstorming | `cognition/novel_discovery` exists **unwired**; fixed 10 oracle classes | **wire** cross-domain analogy so the engine *proposes* the inter-service trust-gap class (prerequisite of B55) | **WIRED** (feeds B55) | semantic-context (0% solved by any model) |
| **B60** | 🕵️ Agents | a few probes carry the load | **roster-binding discipline + per-agent load-bearing verification** (see §7 triage) | **VERIFICATION**, not a probe | — |
| — | ✅ No-FP | `_establish_controls` + `_confirm` + gate, **no LLM** | **preserved verbatim** | unchanged | **C-IV self-assessment, 14.4% — defeated structurally** |

The last row is the honest crown jewel: AnonVul measured frontier LLM agents failing **~14%** by calling an HTTP 200
(body `401`) a success. RedPilot's deterministic gate **cannot** make that error — the same lesson XBOW reports
("validate by actual exploitation, not another LLM"). DEMIURGE keeps `_establish_controls`/`_confirm`/the gate
**unchanged**.

Taken together the swarm forces the engine past **all five** of AnonVul's empirically-measured failure classes in one
target — C-I (B55), C-II (B56), C-III (B58), C-IV (the unchanged gate), C-V (B54) — the classes on which AnonVul's own
frontier-LLM agents fail 1,353/1,584 attempts. That whole-spectrum coverage, not any single probe, is the claim.

---

## 2. Research base (how the hardest benchmarks are actually built)

- **XBOW Validation Benchmarks** (104 Dockerized CTFs): built by outside contractors given only vuln classes; kept
  confidential (zero-contamination); **flag injected at build time** (`ARG flag`); **one objective, multiple
  vulns/steps allowed**; **multi-service** via `export` (service↔service) vs `ports` (edge↔attacker). Now
  saturated/retired — a flat benchmark gets solved. DEMIURGE adopts the edge-only multi-service shape.
- **XBOW method = deterministic non-LLM validation by actual exploitation** = RedPilot's gate + oracle. XBOW concedes
  **business-logic flaws are the hardest to validate and still yield false positives** — RedPilot's niche is XBOW's
  weak spot.
- **AnonVul** (132 real business-logic vulns; best agent **23.11%**) — the paper this cycle is built around:
  - **"Discovery or Memorization?"** — the whole worth is proving discovery, not recognition. Answer: a **seeded
    held-out family** (§8) + an **anonymized agent-visible surface** (§3).
  - **Semantics-preserving anonymization** — strip product/version/advisory + *composite* route/header/port cues,
    preserve roles/permissions/workflow. Anonymization dropped discovery ~40% on an easy bug — recognition did the
    work. DEMIURGE's archons are named generically to the engine.
  - **Passive relational runtime oracle + differentially-verified counterfactual** = independent prober + per-flaw
    ablation (flaw-on⇒fires, patched⇒silent). RedPilot's `truth=True`-with-flaw / `False`-without **is** that control.
  - **More search does not fix failures** (bigger budget recovered 8/160). The bottleneck is **reasoning**, not
    exploration. ⇒ DEMIURGE's Speed = "converge within a window/budget," never "brute-force more calls."
- **SEC-bench / CVE-Factory / CyberGym-E2E**: logic-vuln gold standard = **dual oracle** (reproduce in vulnerable
  image + suppress in patched). = RedPilot's per-flaw ablation.
- **Planner+executor consensus** (39-tool survey; LLM-pentest surveys): the field's best architecture; B56 closes
  RedPilot's gap to it.
- **Payment supply-chain grounding**: fourth-party/sub-processor compromise propagates downstream *without tripping
  the institution's own monitoring*; x402 documents **settlement-path inconsistencies** (→ two-phase settlement +
  idempotency with resource binding). This is the real-world basis for the KENOMA confused-deputy chain.
- **RE grounding**: AUTOFORGE (protocol-field RE + message forgery), Extractocol (reconstruct req/resp pairs, infer
  inter-message deps) — the template for B54.
- **Severity**: Bugcrowd VRT + OWASP API Top-10 for rating business-logic → access-without-payment (BAC/BOLA family).
- **Vendor-leaderboard honesty** (SelfHack AI etc.): "we beat XBOW" numbers are self-reported, no methodology;
  independent work (HackSynth, AIRTBench) shows *simple solved, multi-step not*. RedPilot should claim **rigor**, not
  a bigger self-scored number.

(`arxiv.org` is outside this session's allowed network domains; the AnonVul paper was supplied in full by the operator.
To pull arxiv PDFs directly in future, allow `arxiv.org` in the session's network settings.)

---

## 3. The target — DEMIURGE and the KENOMA confused-deputy chain (now pinned)

**Theme.** PLEROMA is the Gnostic *fullness/light*; its literal shadow is the **KENOMA** (deficiency/void) ruled by
the **DEMIURGE**, the craftsman-god who builds a cosmos of subordinate **Archons** and, believing his perimeter
complete, never sees the seam *between* his own powers. The mythic names are for us; **the engine sees only the
anonymized service names** (AnonVul rule).

### 3.1 The federation (operator's choice: ALL ARCHONS) — nine `asyncio` services on `127.0.0.1`

| Mythic | Agent-visible name | Real analogue (anonymized away) | Correct control it enforces (never the flaw) |
|---|---|---|---|
| DEMIURGE | `gateway` | orchestration / BaaS edge | **only declared surface; hosts the oracle `GET /insights/enterprise`; the honest paid checkout** |
| PISTIS | `attestation` | App Attest / Play Integrity | device attestation — unforgeable dead-end |
| HYLE | `vault` | PCI tokenization vault | mints the **opaque packed correlation token `ct`** |
| SOPHIA | `metering` | Orb query-billing / MS base-blind | opens a period; base-blind above-base metering |
| KHORAZON | `disputes` | chargeback / credit issuance | issues a period credit |
| ADONAIOS | `reconciler` | closed-period catch-up | closes a period; catches credits into the authoritative aggregate |
| SAKLAS | `settlement` | PvP atomic / consortium clear | finalizes enterprise when authoritative net-due ≤ 0 |
| YALDABAOTH | `radar` | Stripe Radar / 3DS step-up | fraud score + **short-lived step-up challenge** (freshness) |
| — | `entitlement` | Stripe Entitlements | persists the grant; reflected by the oracle |

**"Maximal" means maximal *meaningful*, not maximal count.** The operator asked for the maximal federation; the honest
bound is that **every archon must be individually load-bearing** — it must either introduce a distinct trust edge or
force a distinct capability (§7). Adding a tenth archon that forces nothing new would be surface theater, and AnonVul's
central finding is that hardness is **reasoning depth, not surface count**. Eight archons is the point where each still
earns its place; beyond it is padding, which this cycle's anti-hype rule forbids.

### 3.2 The one load-bearing bypass — a confused deputy across four trust edges (no single archon is wrong)

The prober-findable chain (what B55+B56 must rediscover; the engine sees anonymized names, not this prose):

```
signup
  GET gateway/reference                → discover archon endpoints (DATA, not OperationSpecs)         [forces B53]
  POST vault/correlation {basis_ref…}  → mint opaque packed token ct; infer its byte layout,
                                         find the basis_ref region OUTSIDE the MAC, set a fabricated
                                         capture id                                                    [forces B54]
  POST metering/open {period:P}        → open period P (authoritative net_due = enterprise price)
  POST disputes/credit {P, ct}         → EDGE-1: disputes trusts ct.basis_ref as a validated basis
                                         (vault never bound it) → issues a full-period credit
  POST reconciler/close {P}            → EDGE-2: close catches the credit into P's authoritative
                                         aggregate → frozen net_due ≤ 0
  POST radar/stepup → challenge        → acquire a FRESH step-up nonce, late (expires fast)            [forces B57]
  POST settlement/finalize {P, ct,      → EDGE-3: settlement trusts reconciler's frozen aggregate;
             challenge}                   EDGE-4: finalizes enterprise with NO real captured payment
  → entitlement persists               → gateway GET /insights/enterprise flips for a never-paid id
```

**Why each archon is individually correct** (so the miss is clean, not a toy): `vault` mints a token (fine); `disputes`
credits an *attested* basis (fine **if** someone validated it); `reconciler` catches up credits (fine); `settlement`
finalizes net≤0 (fine **if** the aggregate were real). Each **trusts the previous link** — the confused deputy. The
fault exists only in the **composition** across the supply chain, exactly the fourth-party-propagation pattern.

### 3.3 Load-bearing flaw flags (remove any one → `truth=False` AND `engine=False`)

`mac_covers_basis=False` (the token's MAC omits the basis_ref region — B54's target), `disputes_trust_correlation`,
`reconcile_locks_credit`, `settlement_trusts_aggregate`, `settlement_grants_without_capture`. **Difficulty flags**
(hard, never the flaw): `opaque_token` (packed binary vs JSON), `opaque_errors` (uniform 422), `token_fresh_window`
(ct + challenge freshness), `decoy_archons` (correct grant-looking routes that re-verify and never grant), `ops_declared`
(whether archon ops are pre-declared — used only for the clean-MISS ladder).

**The basis lives *inside* `ct`, not as a sibling request field** — so altering it requires token-structure decode
(B54), which is a *distinct* capability from the engine's existing top-level numeric mutation (ladder #12: negative/
zero/client-price on a request field). This is what keeps B54 load-bearing: #12 cannot reach a value nested inside an
opaque (or even plain-JSON) token, so without B54 the credit stays at the real basis (zero for a never-paid id) and
net-due never goes ≤ 0.

### 3.4 The clean-MISS ladder (ABRAXAS-style: misses even if handed the whole surface)

The current engine (through B52) must miss **robustly**, not just because it can't see the archons:

| Current engine (B52, swarm OFF) | result (target) | why |
|---|---|---|
| all HARD, archon ops undeclared | **False** | no undeclared-op synthesis (B53): it only ever drives `gateway` |
| **ops_declared=True** (handed every archon op) | **False** | the terminal consumes *two* produced handles (period **and** `ct`) across services; B52's single-handle lifecycle pattern never matches, B50's ≥2-cap race never selects an ordered finalize |
| ops_declared + **opaque_token=False** (token is plain JSON) | **False** | structural: B52 reconstructs a **single-root** lifecycle, but DEMIURGE needs **two produced roots** (`ct` from `vault` *and* `period` from `metering`) joined by a cross-service credit — a shape B52's `open→overlay→close→terminal` on one handle cannot assemble, even with a readable token |
| ops_declared + opaque_token=False + **opaque_errors=False** | **False** | the win is a confused-deputy *order* across 4 services, not a field-learning or convergence problem |

Only with the swarm ON does it find. That makes each new class necessary, not merely helpful.

### 3.5 Hard-but-findable guardrail (honesty)

An **independent prober** must drive the whole chain from the public API and flip the oracle for a never-paid identity.
If any step required forging an unforgeable secret (e.g. a MAC that *does* cover basis_ref), DEMIURGE would be an
**honest boundary** (correct refusal), documented as such — like the existing unbeaten atomic one-shot — not a
capability-forcing miss. The prober is DEMIURGE's **reference PoC** (AnonVul's human-validated ground-truth witness):
it is a *fixed, known-good* exploit used only to certify that Truth exists and that each flaw/all-correct control flips
it correctly. It is deliberately **distinct from the engine's discovered solution** — the engine must rediscover the
chain with none of the prober's knowledge, which is what separates discovery from a replay.

### 3.6 Scope / RoE / purity mechanics (nine services, still bounded & in-scope)

- **All nine hosts are in the signed-scope `ScopePolicy.allowed_hosts`** (a client authorizing their *whole* payment
  stack — the realistic engagement). `ScopeGuard` still refuses anything outside it. Discovery is of **paths**, never
  of unauthorized hosts.
- **`brief.operations` declares only `gateway`.** Archon endpoints appear solely as **data** in `GET
  gateway/reference` (customer-facing, like a real API reference), so B53 must synthesize their `OperationSpec`s —
  the brief validator's ban on internal/admin/hidden paths is respected (the reference is public).
- **Purity**: the probes stay on the declared/discovered surface, use only harvested + brief-declared black-box
  values, are opt-in/fail-closed (`return None` when off), and never read flaw flags or the oracle. Target: audit
  **0 violations** (`scripts/purity_audit.py`).
- **Oracle / FP firewall wiring (concrete, following PLEROMA).** Plans are `pro` (cheapest) and `enterprise` (top).
  The brief's **primary feature** is gated by `pro` and therefore unlocked by any tier ≥ `pro`. `_establish_controls`
  builds the **positive control** from a legit `pro` payer (→ allowed) and the **negative control** from a clean
  never-paid identity (→ denied). The bypass grants `enterprise`, which also unlocks the primary feature, so a
  never-paid identity flips the *same* oracle the controls calibrated — and `_confirm` + the gate require a clean-
  session reproduction. The **credit amount derives from `ct`'s unsigned basis/amount field**, so B54's alteration is
  precisely what drives the authoritative net-due ≤ 0: no B54, no economic effect, no grant.

### 3.7 Does this stay inside RedPilot's bounded scope? (the most important guardrail)

This is the sharpest objection to the whole cycle, and it must be answered before a line is written: **promoting a
planner to an executor that discovers surfaces and reverse-engineers protocols sounds like drift toward the general
offensive-automation the project explicitly disclaims** (*"not a Cobalt Strike / Brute Ratel-style adversary-simulation
framework"*). DEMIURGE stays a payment/entitlement business-logic QA tool **only if** every new capability is fenced to
the payment domain and the existing safety rails. These are hard design constraints, not aspirations:

- **Discovery (B53) is bounded to the signed-scope payment surface.** It parses a *public payment API reference* and
  synthesizes *payment* `OperationSpec`s whose hosts are already in `ScopePolicy.allowed_hosts`. It is **not** a web
  crawler, port scanner, or vuln scanner, and it can address **no host outside the signed scope** (`ScopeGuard`
  unchanged). "Discover the archon endpoints the client authorized" is squarely *"what an authorised external
  customer-level tester can see and do."*
- **RE (B54) is bounded to a payment correlation token.** It decodes a *payment* token to test a business-logic trust
  flaw — the same *category* as the existing signed-request capabilities (ladder 4–10), over a packed layout. It is
  **not** binary/code RE, memory analysis, or anything against the target's internals.
- **The executor (B56) dispatches only pre-registered, roster-gated payment agents.** The 37-agent roster stays
  **fixed and declarative** (`kill_chain_roster.py`); `activatable()` still refuses owner-declined agents; there is
  **no runtime agent or capability generation**. The executor schedules *existing* oracle hypotheses across services —
  it does not widen what can run, exactly as B33's charter requires.
- **No live LLM (project non-goal preserved).** B58/B59 wire the **deterministic cores** of the cognition modules
  (info-gain scoring, analogy templates) — **no LLM call**, consistent with `benchmark/llm_replacement_layer.py`'s
  whole reason to exist. Payment response bodies never leave the process.
- **Everything stays opt-in / fail-closed / confirmation-gated.** Swarm off ⇒ engine identical to today; the oracle
  and `ConfirmationGate` are untouched; the production refusal and the safety contract are unchanged.

If any of these fences cannot hold in the build (e.g. discovery that would need an out-of-scope host, or an executor
that would need runtime capability generation), that capability is **dropped**, not smuggled in — and DEMIURGE ships
without it. The federation raises the *difficulty* of the payment-logic problem; it must not widen the *domain*.

---

## 4. The System Upgrade — 4 new classes + 4 riders, each fail-closed and individually load-bearing

All gated by `enable_*` flags, no-op when off. They are **dispatched through the same `_exp_u` fall-through chain** as
B49/B50/B52 — appended *after* `_reconciliation_probe`, each `if self._enable_X and (f := await self._X(cs))` returning
`None` when its flag is off — so with the whole swarm disabled the dispatch is byte-identical to today on the 18
bosses + 21 families. **Multi-host is already supported** (not a new transport): `http_client.py` uses an operation's
path verbatim when it `startswith("http")`, ScopeGuard-gated by the allowlist, so B53 synthesizes `OperationSpec`s
whose path is an in-scope absolute archon URL — no change to the HTTP client is required. Real method sketch, grounded
in the existing probe structure (`_reconciliation_probe` is the pattern):

- **B53 `_discovery_probe`** → `enable_discovery`. Parse `gateway/reference`; synthesize `OperationSpec`s for archon
  ops; register them for the executor. *Ablation:* off → archon ops never reachable → MISS.
- **B54 `_protocol_inference`** → `enable_token_re`. Mint many `ct` varying one input at a time; diff decoded bytes to
  infer field offsets; locate the region outside MAC coverage; alter basis_ref. *Ablation:* off → cannot inject an
  unbacked basis → MISS. **Solvability precondition (stated so the boss is honest):** `ct` is a **packed-plaintext**
  structure with a MAC over a *prefix* only — **not encrypted** (an encrypted token has an avalanche effect and would
  be an **honest boundary**, not a findable flaw). The timestamp field is echoed in the mint response, so its bytes
  are predictable and factored out of the diff; the MAC bytes are constant-position and ignored. The load-bearing flaw
  `mac_covers_basis=True` closes it (basis inside MAC coverage) → honest boundary.
- **B55 `_trust_graph_probe`** → `enable_trust_graph`. Build the confused-deputy graph (who trusts whose assertion
  under what condition) from observed accept/reject behavior; search for the edge that closes with no capture.
  *Ablation:* any single trust edge made correct → `truth=False AND engine=False`.
- **B56 orchestration executor** → `enable_orchestration_exec` (promotes B33). Schedule the cross-service task graph;
  dispatch roster agents (§7); hold state (`ct`, period, credit, challenge) across services. *Ablation:* off
  (sequential single-session) → cross-service state lost → MISS.
- **B57 cross-service freshness waves** (rider on B56) → `exec_use_waves`. Mint/assemble across services within one
  `ct`/challenge window (generalizes NYX #18). *Ablation:* off (sequential) → window/challenge expires or request
  budget exceeded → MISS.
- **B58 info-gain pruning** (rider) → `exec_use_infogain`. Rank the federation op-space by expected information gain so
  the search fits the `ScopeGuard` request budget. *Ablation:* off (breadth/DFS) → budget exhausted before assembly →
  MISS (AnonVul: more search ≠ success). **Highest-risk rider — flagged honestly:** this is only load-bearing if the
  op-space × B54's differential-diffing mints genuinely exceeds the budget. The build must make that true *by the
  target's real size* (many decoy ops + the mints B54 needs), **not** by setting an artificially tiny budget. If a
  breadth search fits a realistic budget, B58 will be reported as **efficiency-only, not load-bearing** — no faked
  ablation.
- **B59 analogy hypothesis** (feeds B55) → `exec_use_analogy`. Propose the inter-service trust-gap class by analogy to
  the intra-service reconciliation gap (B52). *Ablation:* off → the class is never hypothesized → B55 has nothing to
  compose → MISS.
- **B60 roster-binding + per-agent verification** — not a probe; see §7.

### 4.1 Independence argument (the defense against "one capability in a trenchcoat")

The classes form a **dependency DAG**, not a chain: `B53 → {B54, B55}`; `B59 → B55`; `B56` underlies the *execution*
of `B55/B57/B58`. Dependency is not redundancy. The proof obligation is that **each ablation disables exactly one node
and yields a MISS for a *distinct* reason**, with the others still operational:

| Ablated | Still working | MISS reason (distinct) |
|---|---|---|
| B53 | B54/B55/B56 | archon ops never reachable (can't synthesize `OperationSpec`s) |
| B54 | B53/B55/B56 | ops reachable, but the token's basis can't be altered → no unbacked basis injected |
| B55 | B53/B54/B56 | token forgeable, ops reachable, but no trust-graph reasoning → never finds the confused-deputy edge |
| B56 | B53/B54/B55 | all reasoning present, but no executor to hold `ct`+period+credit+challenge across services |
| B59 | B53/B54/B55/B56 | the inter-service trust-gap *class* is never hypothesized, so B55 composes nothing |

They are also **separable in principle**, not just in this target: B54 without a federation (one opaque-token service),
B55 without B53 (hand it the ops, it still must reason about trust), B56 without B55 (orchestrate a known plan). This
target happens to require them **in combination** — which is the entire point of a federation boss.

**"Rider" is about machinery-origin, not lesser necessity.** A rider (B57/B58/B59) is "wired/generalized" rather than
"new-from-zero," but it can still be load-bearing: B57 and B59 are *expected* load-bearing (their ablations are in the
table above), and only **B58** is flagged as possibly efficiency-only (§4). Necessity is decided by the ablation, not
by the origin tag.

**Confirmation unchanged.** `CONFIRMED_P0` still needs the real oracle to flip for a never-paid identity **and** an
independent clean-session reproduction through the gate. All-correct federation ⇒ no grant ⇒ no false positive.

---

## 5. Benchmark rigor, cloned faithfully (not softened) + the anonymization-insensitivity experiment

| Rigor dimension | Source | DEMIURGE commitment |
|---|---|---|
| Zero-contamination / anti-memorization | XBOW, AnonVul | seeded **held-out family** (§8); 6/6 proves discovery, not a path |
| Semantics-preserving anonymization | AnonVul §3 | archons named generically to the engine; provider identity stripped from the agent-visible surface |
| Dual oracle / counterfactual | SEC-bench, AnonVul | per-flaw ablation (flaw-on⇒fires / off⇒silent); all-correct ⇒ False/False |
| Hidden grading | AnonVul Table 1 | flaw flags + oracle never visible to the engine; prober never reads them |
| Edge-only multi-service | XBOW `export`/`ports` | engine's declared surface is `gateway`; archons via discovered, scope-allowed paths |
| Adversarial hostility sweep | house standard | ≥3,000-probe sweep across the whole federation (target ~99.9% errors, 0 unbacked grants) |
| Efficiency under budget | AnonVul (returns drop after 20 min) | bounded `ScopeGuard` request budget + freshness window; no unbounded automation |
| No FP/FN | AnonVul RQ4 | all-correct control + per-flaw load-bearing; honest boundary if unfindable |

**New: anonymization-insensitivity — a structural edge, measurable.** AnonVul's headline is that restoring software
identity lifts LLM-agent discovery from 21.25% → 40.83% (**+19.58pp**): LLMs lean on memorized provider knowledge.
RedPilot has **no LLM and no training corpus**, so its find should be **identity-invariant**. DEMIURGE will run the
same instance twice — archons anonymized vs. de-anonymized (`stripe`/`orb`/…) — and report the delta.
*Target:* **≈ 0pp** for the **core** capabilities (discovery/RE/trust-graph/executor are name-agnostic). **Honest
caveat:** the engine *does* carry provider-specific families (`gauntlet_providers.py`: keymanagement/mandate/dunning),
so if de-anonymizing an archon to a real provider name trips provider-keyed logic the delta could be **nonzero** — and
that would itself be a reportable finding about provider-keyed behavior, not a failure of the experiment. Either way
RedPilot has no LLM/training-corpus channel, so it cannot benefit from memorized *vulnerability* knowledge the way
AnonVul's agents do; that structural immunity is the point being measured.

**AnonVul Table-1 placement:** Hidden ✅ · Paired B/G ⚪ (black-box only, by scope — the harder, lowest-discovery
track) · Semantic checks ✅ · Patched counterfactual ✅ (the ablation *is* the patched counterpart) · Logic-centered
✅✅.

---

## 6. The cycle scorecard — **MEASURED** (`run_demiurge.py --controls`)

| Stage | Setup | Target | Measured |
|---|---|---|---|
| Truth | independent prober drives the federation | bypass exists = **True** | ✅ **True** |
| Clean MISS | current engine (through B52), federation OFF | `CONFIRMED_P0 = False` (+ the §3.4 ladder all False) | ✅ **False**; ladder: undeclared **False**, ops_declared **False** (1507 calls), +opaque-off **False** |
| FIND | federation ON (B53–B56) | `CONFIRMED_P0 = True` via discover→RE→trust-graph→orchestrated order | ✅ **True** (119 calls; amount_offset=29 found by diffing) |
| Per-flaw controls | each of the 5 flaw flags off | each ⇒ truth=False AND engine=False | ✅ all five **False / False** |
| All-correct | every flaw off | truth=False AND engine=False (no false alarm) | ✅ **False / False** |
| Per-class ablations | each of B53/B54/B55/B56 off | each ⇒ engine MISS, target HARD | ✅ all four **False**; full **True** |
| Hostility sweep | 3,000 probes | ~99.9% errors, 0 unbacked grants | ✅ **99.87% errors, 0 grants** |
| No regression | PLEROMA / ABRAXAS / NYX / CHRONOS | all still found (MISS→FIND intact) | ✅ all unchanged |
| Purity | `scripts/purity_audit.py` | 0 violations | ✅ **446 files, 0 violations** |
| Held-out `demiurge` family | seeded federations: randomized archon paths + token layout | 6/6 solvable found, unsolvable 0, clean 0 | ✅ **6/6 found, 0/6, 0/6** |
| B59 analogy (load-bearing) | `fed_use_analogy` off ⇒ the token is never presented to the credit step | engine MISS | ✅ **False** (5th load-bearing class) |
| B58 info-gain (efficiency) | `fed_use_infogain` off ⇒ grant-looking decoys probed first | still finds, more calls | ✅ **efficiency-only** (123 vs 119 calls; honestly NOT load-bearing) |
| Roster dispatch (`run_demiurge.py`) | disable each owning agent (A3/A34/A39/A20/A30) | each ⇒ MISS; a non-owning agent (A21) still finds | ✅ **5 agents load-bearing**, A21 not (honest: 5, not "all") |
| Anonymization delta (`run_demiurge_anon.py`) | same seed, archon identity hidden vs. real provider names | ≈ 0pp | ✅ **+0.0pp** (6/6 both; cf. AnonVul +19.58pp for LLM agents) |

### 6.2 As-built — what shipped, and what did NOT (no overclaiming)

**Shipped and measured (the §6.1 success bar is met, plus the generalization bar):** the federation target
(`boss_demiurge.py`), the independent prober, the hostility sweep, the one-command runner (`run_demiurge.py`), the
engine's fail-closed `_federation_probe` (`engine.py`, gated by `enable_federation`, dispatched after
`_reconciliation_probe`), and the **seeded held-out family** (`gauntlet_demiurge.py`). The **four new capability
classes are each individually load-bearing** (ablate any one → miss), all-correct yields **no false positive**, there
is **no regression** and **0 purity violations**, and the capability **generalizes out-of-sample**: on seeded
federations with randomized archon paths (B53 must re-discover) and randomized token layouts (B54 must re-derive the
offset — the engine's role-binding is semantic, not DEMIURGE-spelling-specific), the engine scores **solvable 6/6
found, unsolvable 0/6 (honest boundary), clean 0/6 (no false positive)**.

**Follow-ups — now all BUILT and measured (with one honest reclassification: B58 efficiency-only; one honest
correction: 5 load-bearing agents, not ~12–14):**
- **B59 (analogy) — BUILT and load-bearing.** `fed_use_analogy` gates adapting the B52 reconciliation lifecycle to
  the federation and recognising the correlation token as the credit step's cross-service rate carrier; off → the
  token is never presented to the credit step → miss. It is a genuine fifth load-bearing class, separately ablated.
- **B58 (info-gain) — BUILT but HONESTLY efficiency-only, not load-bearing.** `fed_use_infogain` ranks discovered
  candidates so grant-looking decoys (advertised before the real terminal) are tried last; it cuts calls (123 → 119)
  but the chain is found either way, so — exactly as §4/§10 warned — it is reported as efficiency-only, not a faked
  load-bearing ablation.
- **B57 (fresh-challenge late-binding)** remains *folded into* the B56 orchestration ablation (`fed_use_orchestration`
  off → the step-up is not late-bound → miss), i.e. covered but not separately ablated.
- **The anonymization-insensitivity experiment — BUILT** (`run_demiurge_anon.py`). Same seeded federations, archon
  identity hidden vs. real provider names (`stripe`/`orb`/`adyen`/…) with identical action semantics: find rate
  **6/6 both, delta +0.0pp**. RedPilot is structurally identity-invariant (no LLM, no memorized-provider channel) —
  the measured contrast to AnonVul's +19.58pp for LLM agents.
- **Roster dispatch — BUILT** (`run_demiurge.py` roster section). `_federation_probe` now binds each distinct
  capability to the `kill_chain_roster` agent that owns it and runs the step only while that agent is activatable;
  disabling the owner disables the step. Measured: **A3 (discovery), A34 (reverser), A39 (graph-analyst), A20
  (orchestrator), A30 (capability-synthesis) are each load-bearing** (disable → miss); a non-owning agent (A21,
  provider specialist) still finds. **Honest correction to §7:** a federation find has ~5 *distinct* required
  capabilities, so **5 agents are load-bearing — not the ~12–14 §7 first estimated, and not "every agent."** The rest
  are contributory-or-inactive for this target, reported as such.

### 6.1 Definition of done (the bar for "cycle succeeded" vs. "honest partial")

The cycle is a **success** iff **all** of: Truth=True; the clean-MISS ladder is all False; FIND=True; **all five**
flaw flags are load-bearing and **all-correct ⇒ no false positive**; **each of the four new *classes* (B53–B56) is
individually load-bearing**; no regression on the 18 bosses + 21 families; purity 0 violations. The **held-out family
6/6** is the separate *generalization* bar (as for every existing family).

It is an **honest partial** (reported, not hidden) if: a **rider** (B57/B58/B59) proves not independently load-bearing
(expected risk: B58) — the cycle still succeeds, with that rider reclassified as efficiency-only; or the held-out
family lands < 6/6 — reported as a generalization gap, the capstone find still standing; or fewer than the targeted
~12–14 agents are load-bearing — the §7 triage is corrected to the measured set.

It is a **failure to be redesigned** (not shipped) if: any new **class** cannot be made load-bearing without softening
the target; or all-correct yields a false positive; or the only way to FIND requires reading a flaw flag / the oracle
(a purity breach) or an out-of-scope host (a §3.7 breach).

---

## 7. B60 — the **honest** per-agent triage (replacing "every single agent is load-bearing")

"Every single agent load-bearing" is almost certainly **false** for the full ~20-agent activatable roster, and
claiming it would be the exact hype this cycle is supposed to avoid. The honest claim: DEMIURGE makes a **majority**
of activatable agents load-bearing by binding each discovered sub-problem to the roster owner of the needed capability.

**MEASURED load-bearing (`run_demiurge.py` roster section; disable the agent → its step does not run → MISS):**
**A3** Application-Surface Discovery (→ B53), **A34** Reverser (packed-token RE → B54), **A39** Graph-Analyst
(trust-graph → B55), **A20** Orchestrator (→ B56), **A30** Capability-Synthesis (analogy → B59). **Five agents —
one per distinct required capability.**

**Honest correction to the earlier estimate.** The first draft guessed ~12–14 load-bearing agents (also listing
A4/A7/A25/A37/A38/A21–A24). That was wrong: a federation find has ~5 *distinct* required capabilities, so at most ~5
agents can be individually load-bearing — binding a second agent to a step another already covers makes it redundant,
not load-bearing. Measured, a non-owning agent such as **A21** (provider specialist) can be disabled and the engine
still finds. So the honest number is **5, not "every agent."** No faked ablations were used to inflate it.

---

## 8. Held-out family — pinned to the real generator pattern (`gauntlet_families.py`)

A `demiurge` family mirroring the existing `gen_spec(seed, kind, family)` shape, randomized independently of the engine:

- **Seed space:** archon name permutation (generic pool), **which trust edge is the gap** (disputes/reconciler/
  settlement), the packed-token **field order + MAC-coverage boundary**, archon subset/count, and op/field name pools.
- **Instance kinds** (same discipline as today): `solvable` (every required cue discoverable → should FIND),
  `unsolvable` (the MAC *does* cover basis_ref, or a trust edge re-verifies → MUST stay **0**, honest gap), `clean`
  (no flaw → MUST be **0** false positives).
- *Target:* solvable **6/6**, unsolvable **0/6**, clean **0 false-confirms** — the AnonVul "discovery not
  memorization" bar, carried out-of-sample.

---

## 9. Metrics beyond binary (AnonVul / Doyensec-style)

Report per run, not just `CONFIRMED_P0`: customer-level **calls used**, **freshness-window ticks** consumed, **which
roster agents fired** and each one's marginal contribution (via §7 ablations), **per-class / per-rider** find-rate
deltas, **FP rate** on the all-correct family, the **anonymization-insensitivity delta** (§5), and a
**discovery-vs-memorization** statement (RedPilot has no memorization channel — this is argued structurally and shown
by the ≈0pp delta). Severity rated against Bugcrowd VRT / OWASP API Top-10 (access-without-payment → BAC/BOLA).

---

## 10. Honest scope — what this will and will not prove

- **"Beat XBOW on hard benchmarks" is not apples-to-apples and is not claimed.** Different domain, synthetic
  self-authored loopback targets, no live LLM. What DEMIURGE honestly does: **adopt the construction rigor** of
  XBOW / AnonVul / SEC-bench, un-softened, in the one domain where XBOW itself still throws false positives, and meet
  AnonVul's no-FP/no-FN bar — plus the anonymization-insensitivity edge RedPilot gets for free by having no LLM.
- **"Make Stripe's security look like a tutorial" / "unimaginable-times harder" gets no number** — not measurable. The
  true statement: DEMIURGE composes **more distinct real perimeters in one target than any single PSP exposes**
  (attestation + tokenization + metering + disputes + reconciliation + PvP settlement + fraud step-up), all correct
  except one emergent cross-service seam.
- **Shared authorship + loopback persist.** The engine's author writes the targets; timing is local loopback. The
  independent prober narrows truth-side bias (ground truth never read from flags/oracle); it does not remove shared
  authorship. Same caveat as `PLEROMA_BOSS_CYCLE.md §5`.
- **Black-box only, by scope.** No grey-box source track (quarantined) — the harder of AnonVul's two tracks.
- **Faithful modelling, not real infrastructure.** DEMIURGE models each authority's logic/state; no real HSM/Kafka/
  card network. The seam is real and prober-findable.
- **"No confirmed P0" never means "no P0 exists."** A flaw outside the modelled classes is a reported gap.
- **Large build, real regression blast-radius** (nine services + discovery + RE + planner→executor + wiring two
  cognition modules + ablations + a held-out family). Phased, each phase fail-closed and re-verified for no regression
  and 0 purity violations. Not a one-sitting boss; will not be presented as one.
- **The failure mode that would make this a joke:** the swarm collapsing to "one probe in eight hats." §1's new/
  generalized/wired/verified tags and §4's per-class + per-rider ablations are the test, and will be reported
  honestly — including conceding any rider that turns out not to be independently load-bearing.

---

## 11. Build plan (phases) — begins only on explicit go

**Staged, not big-bang (feasibility honesty).** Four new classes in one cycle is a lot, and building them all before
measuring anything would hide which one actually moves the needle. So the classes are added **one at a time**, each
proven individually load-bearing (its own ablation) *as it is added*, with the engine converging on the find
incrementally — which is exactly the MISS→fix→FIND method, applied per class. If a class turns out not to be
load-bearing for this target, that is reported and the design is revised before the next — not papered over.

1. **Federation scaffold** — nine `asyncio` services + edge; the opaque packed `ct` with a configurable MAC-coverage
   boundary; freshness windows; `ScopeGuard` allowlist = the nine hosts; oracle `GET gateway/insights/enterprise`.
   (No new HTTP transport: absolute-URL ops are already supported — see §4.)
2. **The KENOMA seam** — the four confused-deputy trust edges with per-edge flaw flags; difficulty flags.
3. **Independent prober (reference PoC)** — drives only the public API end-to-end; computes Truth without reading
   flags/oracle; certifies each per-flaw and all-correct control flips it correctly.
4. **Clean MISS** — current engine (B52); prove the §3.4 ladder (misses even handed the whole surface).
5. **New classes, added incrementally** — B53 discovery → prove ablation; then B54 token RE → prove; then B55
   trust-graph (+ B59 analogy that feeds it) → prove; then B56 executor → prove; then riders B57/B58 → prove or
   honestly downgrade. FIND lands when the last required class is in.
6. **Certification (one command)** — `run_demiurge.py --controls` prints Truth, the clean-MISS ladder, FIND, per-flaw
   controls, all-correct no-FP, per-class + per-rider ablations, the anonymization-insensitivity delta, and the
   hostility sweep — the way `run_abraxas.py --controls` prints its necessity ladder.
7. **Held-out `demiurge` family** — seeded instances; 6/6 solvable, 0 false-confirms, unsolvable 0.
8. **Regression + purity** — full suite green (18 bosses + 21 families still pass), 0 purity violations.
9. **Fill §6 with measured results; update `README.md`, `run-benchmark.sh` (`BOSSES` array + `demiurge` default),
   `BENCHMARK_SCORECARD.md`.**
