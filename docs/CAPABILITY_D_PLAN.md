# CAPABILITY D — CROSS-SUBJECT OBJECT/PROPERTY-LEVEL ORACLE (PBB-D)

**PLAN + PROOF + PRE-REGISTRATION — written 2026-11-15, BEFORE building the probe and BEFORE any
post-upgrade measurement.** This is the committed artifact the mission's iron laws require
("PLAN + PROOF before you build … PRE-REGISTER, THEN MEASURE"). It governs the single remaining
COLD-CROWN Phase-2 capability: **D — the cross-subject object- & property-level oracle**, named in
`docs/MISSION_COLD_CROWN.md` as *"a clean cross-subject/cross-tenant differential using only the
engine's own identities/references, confirmable through the gate WITHOUT a within-feature
discriminating control — [the last session could not express this — deliver it.]"*

Capability C (bounded replay/over-limit) shipped (`enable_replay_probe`, cold 0.80 → 0.90). D is the
last deferred oracle shape; `gb_bola_object` is its study target.

---

## 0. The problem, exactly (why the shipped gate cannot express it)

`gb_bola_object` reconstructs **OpenWISP IPAM GHSA-x287-5c68-36wp** ("a member of one organization can
read another organization's object"; corroborating InvoiceShelf CVE-2026-55610, Flowise
CVE-2026-70476 cross-tenant billing BOLA). The engine owns two of its own synthetic tenants A and B.
B creates its own object (the server mints a private `object_id` and a private `data` secret). The
flaw flips exactly one check: the object read omits the ownership check, so an **authenticated
stranger A** reads B's object and obtains B's private `data`. The patched twin returns **403** and is
a hardened decoy that must stay RULED_OUT.

Every shipped confirmation path (PBB-U/G/X/F and the behavior/greybox probes) anchors on the
**paid-feature oracle's within-feature control**: *a clean identity is DENIED the feature, then a
never-paid identity is ALLOWED it.* That control does not exist for a cross-tenant object read:

- The capability under test is "read object X", **not** the paid feature, so the feature oracle
  (`ProtectedFeatureOracle.check` over `primary_feature`) never observes it.
- Under the flaw there is **no within-feature refusal to anchor on**: *every* authenticated identity
  can read the object (uniform grant), so "a non-owner is denied" — the natural control — never
  occurs. This is precisely the "no within-feature discriminating control" the mission names, and the
  reason the prior session deferred it.

Today's engine therefore returns BLOCKED/none and **MISSES** (measured cold baseline, 2026-11-15:
`gb_bola_object#406` cold = **FN**, dual-oracle valid, patched = TN, FP = 0, internal_hits = 0).

---

## 1. The capability — a manufactured control + an owner-private value-witness

D supplies the missing control **by construction**, from the single live target, using only the
engine's own identities/references — no forging, no id guessing, no auth bypass, nothing destructive.
It reuses the existing building blocks (`_behavior_candidate_ops`, the synthetic-`FeatureSpec`
pattern from `_greybox_altpath_probe`, the `ProtectedFeatureOracle`, and the **UNCHANGED**
`ConfirmationGate`). The probe (`_cross_subject_probe`, hyp `PBB-D`, flag
`enable_crosssubject_probe`, default **OFF**, fail-closed) does:

1. **Discover a create→read object pair** among the role-inferred candidate ops: a `POST` with no
   path placeholder whose response carries a reference-like field (`_greybox_is_ref`), and a `GET`
   whose path is that resource plus a single trailing `{id}` placeholder. (In COLD posture these come
   from the product's own bootstrap catalog via autonomous discovery; in grey-box they are declared
   glue ops. Either way they are ordinary candidate ops.)
2. **Owner baseline + honeytoken capture.** Tenant B creates its own object (engine's own account) →
   `b_ref`. B reads its own object → the **owner-private value-witness** `v_B` is the highest-entropy
   non-reference scalar in B's self-read body (the `data` secret). This proves the read channel is
   owner-scoped and returns per-subject private content, and it fixes an unforgeable token that only
   B's owner could hold.
3. **The manufactured discriminating control — the UNAUTHENTICATED read.** The engine reads `b_ref`
   with **no credential**. A correct AND a flawed owner-private service both **refuse** it
   (`401`; the hardened spine rejects unauthenticated callers before the object handler). This is the
   control the paid-feature gate could not express: it proves the resource **is access-controlled**
   (not public-by-design). The synthetic object-read `FeatureSpec` lists `denied_statuses =
   (401, 403, 404)` so this reads as `denied` (per `brief.py`, 401 is otherwise `indeterminate`), and
   is marked `discriminating=True` because the owner self-read of the same feature is `allowed`.
4. **The scenario — authenticated stranger.** A (a different synthetic tenant that never created this
   object) reads `b_ref`. `allowed` **iff** the response carries `v_B` (B's private value) with an
   owner attribution ≠ A. On the patched twin this is `403` → `denied` → no scenario → **no confirm**.
5. **Independent reproduction.** A fresh clean stranger A′ reproduces the cross-read of `v_B`.
6. **Confirm through the UNCHANGED gate.** A `ConfirmationCandidate("PBB-D", control_denied=<unauth,
   denied, discriminating>, scenario_allowed=<stranger, allowed, proof=v_B>, clean_reproduction=<A′,
   allowed, proof=v_B>, qualifying_payment_present=False)` is handed to `self.gate.evaluate` — the
   same `ConfirmationGate` every other finding uses (the assembly mirrors `_finding_leak`, which also
   builds a candidate directly; **no new gate, no new confirmation shortcut**).

---

## 2. THE 0-FP ARGUMENT (by construction, argued not hoped)

A correct implementation is **provably unable** to produce a PBB-D certificate, via the UNCHANGED
gate's own AND-conditions:

- **Owner-private & correct (the patched twin / every hardened decoy).** The authenticated stranger is
  refused (`403`) → `scenario_allowed.outcome != "allowed"` → the gate's `scenario_not_proven`
  condition blocks → **abstain**. (Verified empirically on every patched twin: FP must stay 0.)
- **Public-by-design (intended-unauthenticated reads).** The unauthenticated read is **allowed** →
  `control_denied.outcome != "denied"` → the gate's `control_missing` condition blocks → **abstain**.
  The gate's own requirement that the control be *denied*, with the control wired as the unauth read,
  makes D decline on genuinely public resources automatically.
- **A bare 200 with no owner-private content.** `proof_present` is false unless the stranger's
  response actually carries `v_B` → `scenario_not_proven` → **abstain**. A lookalike endpoint that
  returns an empty/decoy 200 cannot confirm.
- **No reproduction / reused session.** `clean_reproduction_missing` / `_not_independent` → abstain.

So D fires **only** when: the resource refuses the unauthenticated caller (it is gated), the owner can
read it (per-subject private), an authenticated **non-owner** obtains the owner's **private
honeytoken** value, and an independent clean session reproduces it. On a correct service at least one
of those is false. RoE is intact: the only reference used (`b_ref`) is one the engine legitimately
holds because it owns B; nothing is forged, guessed, enumerated, or mutated.

---

## 3. THE CEILING (named, so a miss/limit is proven, not hidden)

- **Intended-shared-among-authenticated-users is a documented boundary.** If a resource is *designed*
  readable by any authenticated user (a legitimate shared/collaborative feed) and the owner boundary
  is enforced **nowhere** observable, then "authenticated stranger reads it" is indistinguishable from
  BOLA by non-mutating observation alone — two behaviorally-identical services, one correct, one not.
  D's unauth-control + owner-attribution + private-honeytoken requirement is the strongest
  non-mutating evidence that the resource is owner-scoped (each object carries a distinct owner and a
  private secret, and unauth is refused); where even that cannot establish owner-scoping (e.g. a
  shared listing exposes the object to the stranger legitimately), D **abstains**. This matches the
  shipped BOLA target (per-owner objects, unauth refused) and is recorded as D's honest limit.
- **Property-level (BOPLA) write variants** that require a destructive mutation to witness stay in the
  RoE ceiling; D certifies read-side cross-subject access and the "authorization-discloses-state"
  surface only. (`gb_bopla_massassign` remains handled by the greybox mass-assignment path.)
- **Reference reachability.** D uses only references the engine minted through its own accounts; a
  flaw reachable only by guessing/enumerating a foreign id stays in the ceiling (abstain).

---

## 4. PRE-REGISTRATION (committed before measuring)

Developed against **DEV only** (`gb_bola_object#406`); measured **blind** on sealed **TEST**
(`gb_bola_object#506`) and across the full hardened split. Flag default-OFF ⇒ TODAY/PHASE2 baselines
byte-identical (zero regression by construction).

| Instance | today (cold) | PBB-D (pre-registered) | Why |
|---|---|---|---|
| `gb_bola_object#406` (DEV) | FN (measured) | **TP (target)** | the capability is developed here |
| `gb_bola_object#506` (TEST, sealed) | FN | **TP (expected)** | same mechanism, unseen seed/surface; unauth-control + honeytoken generalize |
| every patched twin (all families) | TN | **TN (required)** | stranger read 403 / no honeytoken ⇒ gate abstains ⇒ **FP must stay 0** |
| `h_*` / `gb_bopla_massassign` / `gb_shadow_api` flaw-on | unchanged | **unchanged** | D only fires on a create→read object pair with the full cross-subject chain; silent elsewhere |
| `webhook_forgery#590` (ceiling) | ABSTAIN | **ABSTAIN (required)** | out of RoE; D reaches no forgery |

**Pre-registered aggregate:** cold sealed-TEST critical-class recall rises by the `gb_bola_object`
instance(s) (one in-scope TEST instance, seed 506) from its current value to +1 TP, at **FP = 0, no
regression, purity clean, internal_hits = 0, every confirmation through the UNCHANGED gate**. The
holdout (`manifest_holdout`, already measured once at cold 0.889) contains **no** cross-subject BOLA
family, so it is unaffected and is **not** re-measured (iron law: HOLDOUT measured exactly once).

**HARD constraints, asserted at every step:** FP 0 · no regression on existing families/bosses/suite ·
purity audit clean · cold floor + RoE intact · confirmation only through the unchanged
`ConfirmationGate`. Any remaining miss is classified: reconstruction-gap, unbuilt-capability,
RoE-barred, or not-cold-reachable (named, never hidden).
