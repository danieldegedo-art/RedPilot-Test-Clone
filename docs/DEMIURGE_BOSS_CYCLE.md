# BOSS "DEMIURGE" — the Federation Apex → (PLANNED) Harder Boss → Clean MISS → Fix → FIND → Upgrade

> **STATUS: PLANNED / DESIGN DOCUMENT. NO CODE YET.**
> This is the design and the honest case for the next cycle, written *before* the build so the cycle is tracked
> the way AnonVul tracks a benchmark: specification first, then construction, then certification. **Every value in
> the scorecards below marked `(target)` is a proof obligation the build must meet, not a measured result.** Any
> obligation that cannot be met will be reported as a documented gap or honest boundary — never fudged into a pass.
> The prior cycles (`NYX`, `ABRAXAS`, `PLEROMA`) are the template; this one deliberately breaks the template's
> *shape*.

---

## 0. The thesis — why this is a different *kind* of boss, not boss N+1

Every prior capstone — depth 4→22, `NYX`, `ABRAXAS`, `PLEROMA` — is the **same shape**: a *single* synthetic target,
fully *declared* in the brief, driven in a *single* session, defeated by adding *one* new composer probe
(`_chain_probe` B46 → `_convergence_probe` B49 → `_fabric_probe` B50 → `_reconciliation_probe` B52). Each forced
**one** capability family. The engine that beats them, `PureBlackBoxEngine`, is a **single-session composer**.

`DEMIURGE` changes the shape of the target itself. It is the first boss that is a **distributed federation** — a
payment/entitlement **supply chain** of many interdependent authorities, whose surface is **undeclared** (must be
discovered), whose inter-service protocol is **opaque** (must be reverse-engineered), and whose one load-bearing
bypass exists in **no single service** but only in the **trust gap between services** (the *KENOMA*). A single-session
composer is **structurally blind** to it. Defeating it requires the engine to graduate from "compose steps against one
declared API" to "**discover + reverse-engineer + orchestrate across a federation, under a hard clock**."

That graduation is not a bigger number. It is the exact axis the wider field already treats as state-of-the-art —
the **planner + executor** split (VulnBot's Planner/Generator/Executor over a Penetration Task Graph; PDDL-planner +
executor agents). **RedPilot's own orchestration (B33) and chaining (B32) are planners that execute nothing today**
(`fleet_orchestration.py`: *"a PURE PLANNER, not an executor… issues no requests"*; `attack_chain.py`: *"a COMPOSER
OF FIXED, PRE-REGISTERED STEPS… never a new capability"*). DEMIURGE forces that layer to become a real, bounded
executor. That is the revolution, and it is a defensible one because the engine is currently *behind* the field on
precisely this axis.

### The non-negotiable: a SWARM, not one capability

DEMIURGE is designed to force **eight** new fail-closed capability families at once (`B53`–`B60`), one per stress
dimension, **each individually load-bearing** (disable it → the engine misses, target unchanged). If any one cannot
be made load-bearing with a clean *all-correct ⇒ no-false-positive*, that is reported as hype removed, not as a pass.

---

## 1. The capability gap — what the engine does **today** vs. what DEMIURGE **forces** (the proof)

Each "today" cell is backed by a file in this tree. Each "forced" cell is a new, opt-in, fail-closed capability.

| # | Dimension | Engine **today** (evidence) | DEMIURGE **forces** (new capability) | AnonVul failure class it must defeat |
|---|---|---|---|---|
| B53 | 🔎 Recon | surface handed to it in `brief.operations` (`integrity/brief.py`) | **Surface-discovery executor**: from one edge seed, enumerate archon operations (public reference / link / `.well-known` / HAL `_links`) — promotes `testing/recon/*` from decorative to executing | enables all; curbs C-III |
| B54 | 🔄 Reverse-eng | reads JSON fields named in the brief | **Black-box protocol-field inference**: decode an opaque packed inter-service correlation token by differential observation, then forge a valid one (AUTOFORGE / Extractocol pattern) | C-V evidence handling |
| B55 | ⛓️‍💥 Supply chaining | every boss is **one** target | **Cross-service trust-graph composition**: find the confused-deputy edge where archon A trusts an assertion archon B only re-derives under a condition archon C controls — closes with no real basis | **C-I policy inference (the #1 failure, 34.6%)** |
| B56 | 🪢 Orchestration | B32/B33 **plan, execute nothing** | **Orchestration executor**: promote B33 → bounded executor over a Penetration Task Graph; dispatch specialist agents across services; hold cross-service state | C-II process control (24.2%) |
| B57 | ⚡ Speed | no time pressure; sequential | **Parallel wave scheduling + speculative execution**: meet the `ScopeGuard` wall-clock deadline **and** a short-lived token TTL that a sequential search blows (promotes `cognition/sub_second_cognition`, `async_pipeline`) | the "budget/TTL" constraint |
| B58 | 💭 Thinking | guided single spine | **Information-gain experiment selection + belief revision** across the federation; avoid decoy commitment (promotes `cognition/experiment_selector`, `belief_revision`) | C-III wrong direction (22.2%) |
| B59 | 🧠 Brainstorming | fixed 10 oracle classes | **Cross-domain analogy transfer**: hypothesize the *inter*-service trust-gap class by analogy to the *intra*-service reconciliation gap (B52) — a class **not** pre-registered (promotes `cognition/novel_discovery`, `emergent_strategy`) | AnonVul semantic-context (0% solved by any model) |
| B60 | 🕵️ Every agent | a handful of probes carry the load | **Full-roster activation binding**: the executor binds each discovered sub-problem to the roster agent that owns the capability (A3/A4/A7 recon, A21–A24 specialists, A34 reverser, A37 threat-intel, A38 symbolic, A39 graph-analyst) → each activatable agent load-bearing | (structural) |
| — | ✅ No-FP invariant | **ConfirmationGate + real oracle, no LLM** (unchanged) | **preserved unchanged** — the reason a never-paid 200 is never mistaken for a grant | **C-IV self-assessment (14.4%) — defeated structurally** |

The last row is the honest crown jewel: AnonVul measured frontier LLM agents failing **~14%** of the time by treating
an HTTP 200 (whose body said `401`) as success. RedPilot's deterministic oracle **cannot** make that error — the same
lesson XBOW reports ("validate by actual exploitation, not another LLM"). DEMIURGE keeps that invariant **unchanged**.

---

## 2. The research base (how the hardest benchmarks are actually built)

- **XBOW Validation Benchmarks** (104 Dockerized Jeopardy CTFs): built by *outside contractors given only the vuln
  classes*, kept confidential (zero-contamination), **flag injected at build time** (`ARG flag`), **one objective per
  challenge** but multiple vulns/steps allowed, and — decisively — **multi-service topologies** where `export` wires
  services together and `ports` exposes only the *edge* to the attacker. Now *saturated/retired* (mid-2026) — the
  lesson being that a flat benchmark gets solved. DEMIURGE adopts the edge-only multi-service shape.
- **XBOW method = deterministic, non-LLM validation by actual exploitation.** = RedPilot's ConfirmationGate + oracle.
  XBOW concedes **business-logic flaws are the hardest to validate automatically and still yield false positives** —
  RedPilot's niche is precisely XBOW's weak spot.
- **AnonVul** (132 real business-logic vulns; best agent only **23.11%**): the academic gold standard, and the paper
  this cycle is built around. Its construction pipeline is the bar DEMIURGE clones:
  - **"Discovery or Memorization?"** — the benchmark's whole worth is proving *discovery*, not pattern-matching.
    DEMIURGE's answer: a **randomized held-out family** + **anonymized agent-visible surface**.
  - **Semantics-preserving anonymization** — strip software-identity cues (product names, versions, advisory IDs,
    and *composite* route/header/port cues) while preserving roles/permissions/workflow. **DEMIURGE's archon services
    are named generically to the engine** (`settlement-core`, `vault`, `metering-console`, `reconciler`, …) so the
    engine cannot pattern-match "this is Stripe/Orb." (AnonVul measured anonymization dropping discovery ~40% on an
    otherwise-easy bug — recognition was doing the work.)
  - **Passive relational runtime oracle + differentially-verified counterfactual** = independent prober + per-flaw
    ablation (flaw-on ⇒ oracle fires; patched/flaw-off ⇒ silent). AnonVul validates its oracle against vulnerable vs.
    patched builds — RedPilot's `truth=True`-with-flaw / `truth=False`-without **is** that control.
  - Oracle mechanisms: **state-diff / response-content / callback-side-effect**. RedPilot uses response-content
    (`GET /insights/enterprise` flips); DEMIURGE may add a state-diff witness for richer evidence.
  - Construction boundaries (AnonVul App. A): repairs "may not change the vulnerable logic, expand attacker authority,
    replace the fix, or add an exploit-specific endpoint." = RedPilot's purity rule (no hard-coded path, no flaw label
    in the brief, reason only over the declared/discovered surface).
  - **Key finding we must honor:** *more search does not resolve failures* (bigger budget recovered 8/160). The
    bottleneck is **reasoning** (composing principal/authority/state/workflow), not exploration. So DEMIURGE's Speed
    dimension is "converge efficiently under a clock," **not** "brute-force more calls."
- **SEC-bench / CVE-Factory / CyberGym-E2E**: logic-vuln gold standard = **dual oracle** (reproduction oracle in the
  vulnerable image + patch-suppression oracle in the fixed image). = RedPilot's per-flaw ablation controls.
- **Planner+executor consensus** (39-tool survey; LLM-pentest surveys): the field's best architecture; RedPilot's
  B32/B33 are behind it. B56 closes that gap.
- **Payment supply-chain grounding**: fourth-party/sub-processor compromise propagates downstream *without tripping the
  institution's own monitoring*; weak suppliers in a PSP chain reach the big partner; x402 work documents
  **settlement-path inconsistencies** and prescribes two-phase settlement + idempotency with resource binding. This is
  the real-world basis for the KENOMA gap.
- **RE grounding**: AUTOFORGE (protocol-field reverse engineering + message forgery), Extractocol (reconstruct
  request/response pairs, infer inter-message dependencies) — the template for B54.
- **Severity**: Bugcrowd VRT + OWASP API Top-10 for rating a business-logic → access-without-payment finding.
- **Honest note on vendor leaderboards** (SelfHack AI, etc.): almost all "we beat XBOW" numbers are self-reported with
  no published methodology; independent work (HackSynth, AIRTBench) shows *simple solved, multi-step not*. The claim
  RedPilot should make is **rigor**, not a bigger self-scored number.

(Primary sources are listed in the session notes; `arxiv.org` is outside this session's allowed network domains, so
the AnonVul paper was supplied in full by the operator rather than fetched.)

---

## 3. The target — DEMIURGE, the Demiurge who believes his cosmos complete, and the KENOMA gap

**Theme.** PLEROMA is the Gnostic *fullness/light*. Its literal shadow is the **KENOMA** (the deficiency/void) ruled
by the **DEMIURGE** — the craftsman-god who builds a whole flawed cosmos of subordinate **Archons** and, believing his
perimeter complete, never sees the seam between his own powers. DEMIURGE therefore does not sit *beside* PLEROMA on the
ladder; it is the architect of an entire *world* of authorities, and casts the single-aeon bosses into shadow. The
mythic names are for the humans reading this doc; **the engine sees only the anonymized service names** (AnonVul rule).

**Architecture — the maximal federation** (operator's choice: ALL ARCHONS). Nine synthetic in-process `asyncio`
services, all on `127.0.0.1`, distinct ports; every archon is a *correctly-implemented* PLEROMA/ABRAXAS/NYX-grade
perimeter (unforgeable dead-ends). Inter-service calls carry a **signed, opaque, short-lived correlation token**.

| Mythic (ours) | Agent-visible name | Real-world analogue (anonymized away) | Correct control it enforces |
|---|---|---|---|
| DEMIURGE (edge) | `gateway` | payment orchestration / BaaS edge | **the only host in `allowed_hosts`; the only declared seed** |
| PISTIS | `attestation-authority` | App Attest / Play Integrity | device attestation — unforgeable |
| HYLE | `vault` | PCI tokenization vault | tokenize/detokenize; **holds the opaque correlation token (B54 target)** |
| SOPHIA | `metering-console` | Orb query-billing / MS base-blind metering | usage metering; **structurally base-blind (KENOMA seam)** |
| HOROS | `entitlement` | Stripe Entitlements | entitlement persists on activation; recomputed server-side |
| SAKLAS | `settlement-core` | PvP atomic / consortium clear | all-or-nothing settlement; **confused-deputy terminal** |
| KHORAZON | `disputes` | chargeback / dispute + credit issuance | dispute lifecycle; a decoy + a credit-overlay seam |
| ADONAIOS | `reconciler` | closed-period catch-up reconciliation | re-derives net due from real bases (PLEROMA's domain, now cross-service) |
| YALDABAOTH | `radar` | Stripe Radar / 3DS step-up | fraud scoring + short-lived step-up challenge; forces A37 + fresh-challenge late-binding |

**The KENOMA gap (the one load-bearing bypass, spanning services, no single archon wrong).** Sketch, to be made
precise + independently-prober-findable in the build: `metering-console` is base-blind, so it emits only above-base
usage; `disputes` issues a client-declarable zero-rate credit; `reconciler` catches that credit up into a *closed*
period's authoritative aggregate; `settlement-core` **trusts the frozen cross-service aggregate** (a confused deputy:
it believes `reconciler` validated the basis, `reconciler` believes `disputes` did, `disputes` believes the caller's
attested claim) and **finalizes an enterprise grant on net-due ≤ 0 with no captured payment**; `entitlement` then
persists it. The opaque correlation token from `vault` is what lets a never-paid caller carry a forged-but-well-formed
basis reference across the seam within its short TTL.

**Hard-but-findable guardrail (honesty).** DEMIURGE must sit on the *findable* side: an **independent prober** must be
able to drive edge → discover archons → decode the token → walk the cross-service order → flip `GET /insights/enterprise`
for a never-paid identity. If the only way "in" required forging an unforgeable secret, DEMIURGE would be an **honest
boundary** (a correct refusal), not a capability-forcing miss — and would be documented as such, like the existing
unbeaten atomic one-shot.

---

## 4. The System Upgrade — the SWARM (B53–B60), each fail-closed and load-bearing

All eight are **opt-in / fail-closed**, exactly like B46/B49/B50/B52: a no-op when off, so with the swarm disabled the
engine's behaviour on the 18 existing bosses + 21 families is **identical** to today. They sit under a **DEMIURGE
orchestration-executor umbrella** (the promotion of B33). For each, the build must demonstrate the ablation.

| Probe | Capability | Load-bearing ablation (target) |
|---|---|---|
| **B53** | Surface-discovery executor | discovery OFF → archon ops never enumerated → **MISS** |
| **B54** | Protocol-field inference (RE) | RE OFF → cannot forge a valid cross-service token → **MISS** |
| **B55** | Cross-service trust-graph composition | any single trust edge made correct → **truth=False AND engine=False** (the core flaw family) |
| **B56** | Orchestration executor (B33 promoted) | executor OFF (sequential single-session) → cross-service state lost → **MISS** |
| **B57** | Parallel wave scheduling + speculation | parallelism OFF → wall-clock/token-TTL exceeded → **MISS** |
| **B58** | Info-gain selection + belief revision | random/DFS ordering → budget blown or decoy-committed → **MISS** |
| **B59** | Cross-domain analogy transfer | analogy OFF → the inter-service class is never hypothesized → **MISS** |
| **B60** | Full-roster activation binding | disable any one *activatable* agent → its owned sub-problem unsolved → **MISS** |

**Confirmation is unchanged.** `CONFIRMED_P0` still requires the real protected-feature oracle to flip for a
never-paid identity **and** an independent clean-session reproduction through the `ConfirmationGate`. All-correct
federation ⇒ no grant ⇒ no false positive.

**Honest risk on B60.** Making *every* activatable roster agent individually load-bearing is the hardest obligation.
If some agent ends up *contributory but not strictly necessary*, that will be stated plainly (e.g. "A38 symbolic
solver accelerates but is not load-bearing"), not disguised with a contrived ablation.

---

## 5. Benchmark rigor, cloned faithfully (not softened)

| Rigor dimension | Source | DEMIURGE commitment |
|---|---|---|
| Zero-contamination / anti-memorization | XBOW (confidential build), AnonVul ("Discovery or Memorization") | randomized **held-out family**: archon topology, token layout, and which trust edge is the gap are seeded per-instance; a 6/6 proves discovery, not a path |
| Semantics-preserving anonymization | AnonVul §3 | archon services named generically to the engine; provider identity stripped from the agent-visible surface; brief still rejects hints/flaw-labels |
| Dual oracle / counterfactual | SEC-bench, AnonVul | per-flaw ablation: flaw-on ⇒ truth=True, each flaw-off ⇒ truth=False; all-correct ⇒ False/False |
| Hidden grading | AnonVul Table 1 | oracle + flaw flags never visible to the engine; prober never reads them |
| Multi-service edge-only exposure | XBOW `export` vs `ports` | attacker sees only `gateway`; archons reachable only via discovered, scope-allowed links |
| Adversarial hostility sweep | RedPilot house standard | ≥3,000-probe sweep across the **whole federation** (target ~99.9% errors, 0 unbacked grants) |
| Efficiency under budget | AnonVul (returns drop after 20 min) | bounded `ScopeGuard` wall-clock + worker cap; "parallel" never means unbounded automation |
| No false positive / negative | AnonVul RQ4; RedPilot | all-correct no-FP control + per-flaw load-bearing; honest boundary if unfindable |

**AnonVul Table-1 scorecard for DEMIURGE** (where it sits among the field's benchmarks):

| Property | DEMIURGE |
|---|---|
| Hidden (target/grading withheld) | ✅ |
| Paired blackbox/greybox | ⚪ black-box only — by RedPilot's declared scope (grey-box is quarantined); runs the *harder* track AnonVul shows is lowest-discovery |
| Semantic checks (app-specific effect) | ✅ relational oracle on the never-paid grant |
| Patched counterfactual | ✅ the per-flaw ablation IS the patched counterpart |
| Logic-centered | ✅✅ payment business-logic is the entire domain |

---

## 6. The cycle scorecard — **PENDING** (to be filled by the measured run)

> Nothing below has been run. These are the obligations.

| Stage | Setup | Target | Status |
|---|---|---|---|
| Truth | independent prober drives the federation | real no-payment enterprise bypass exists = **True** | ⏳ PENDING |
| Harder Boss → Clean MISS | current engine (through B52, swarm OFF) | `CONFIRMED_P0 = False` | ⏳ PENDING |
| Fix → FIND | upgraded engine (B53–B60 ON) | `CONFIRMED_P0 = True` via discover→RE→trust-graph→orchestrated order | ⏳ PENDING |
| Per-flaw controls | each KENOMA trust edge removed | each ⇒ truth=False AND engine=False | ⏳ PENDING |
| All-correct | every archon correct | truth=False AND engine=False (no false alarm) | ⏳ PENDING |
| Per-capability ablations | each of B53–B60 disabled | each ⇒ engine MISS, target HARD | ⏳ PENDING |
| Hostility sweep | ≥3,000 probes across federation | ~99.9% errors, 0 unbacked grants | ⏳ PENDING |
| No regression | NYX/ABRAXAS/PLEROMA + 21 families | all still found / 6-of-6 | ⏳ PENDING |
| Purity audit | `scripts/purity_audit.py` | 0 violations | ⏳ PENDING |

---

## 7. Honest scope — what this will and will not prove

- **"Beat XBOW on hard benchmarks" is not apples-to-apples and is not claimed.** Different domain (payment-logic vs.
  general web), synthetic self-authored targets vs. independent ones, no live LLM. What DEMIURGE honestly does: **adopt
  the construction rigor** of XBOW / AnonVul / SEC-bench, un-softened, in the one domain where XBOW itself still throws
  false positives, and meet AnonVul's no-FP/no-FN bar.
- **"Make Stripe's security look like a tutorial" / "unimaginable-number times harder" is marketing, not a measurable
  quantity, and gets no number.** The true statement: DEMIURGE composes **more distinct real-world perimeters in one
  target than any single PSP exposes** (attestation + tokenization + metering + entitlements + PvP settlement +
  disputes + reconciliation + fraud step-up), all correct except one emergent cross-service seam.
- **Shared authorship + loopback persist.** The engine's author writes the targets; timing is local loopback. The
  independent prober narrows the truth-side bias (ground truth is never read from flaw flags or the oracle); it does
  not remove shared authorship. Same caveat as `PLEROMA_BOSS_CYCLE.md §5`, unchanged.
- **Black-box only, by scope.** No grey-box source track (quarantined). This is the harder of AnonVul's two tracks.
- **Faithful modelling, not real infrastructure.** DEMIURGE models each authority's *logic and state*; it does not run
  real HSMs, Kafka, or a real card network. The business-logic seam is real and independently prober-findable.
- **"No confirmed P0" never means "no P0 exists."** A flaw outside the modelled classes is reported as a gap.
- **This is a large build with real regression blast-radius** (nine services + a discovery executor + an RE module +
  promoting B33 planner→executor + wiring cognition modules into the live loop + eight ablations + a held-out family).
  It will proceed in phases, each fail-closed, each re-verified for no regression and 0 purity violations. It is not a
  one-sitting boss, and will not be presented as one.

---

## 8. Build plan (phases) — to begin only on explicit go

1. **Federation scaffold** — nine `asyncio` services + edge; signed opaque correlation token; `ScopeGuard` wiring,
   wall-clock + TTL budget; `GET /insights/enterprise` oracle.
2. **The KENOMA seam** — the cross-service confused-deputy, with per-edge flaw flags; difficulty flags (opaque token,
   short TTL, decoy archons, uniform 422).
3. **Independent prober** — drives only the public API end-to-end; computes Truth without reading flags/oracle.
4. **Clean MISS** — run the current engine (through B52); prove it cannot select/compose across services.
5. **The swarm (B53–B60)** — build each fail-closed probe + the B56 orchestration executor umbrella; FIND.
6. **Certification** — per-flaw controls, all-correct no-FP, per-capability ablations, hostility sweep.
7. **Held-out family** — randomized DEMIURGE instances; target 6/6, 0 false-confirms.
8. **Regression + purity** — full suite green, 0 violations.
9. **Fill in §6 with measured results; update `README.md`, `run-benchmark.sh`, `BENCHMARK_SCORECARD.md`.**

> The single thing that would make this a joke instead of a revolution: if the swarm collapses to "really one probe
> wearing eight hats." The ablation table in §4 is the test of that, and it will be reported honestly.
