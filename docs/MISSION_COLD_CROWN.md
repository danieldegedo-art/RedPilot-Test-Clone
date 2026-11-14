RedPilot — OPERATION COLD CROWN: prove an AI can walk up to a STRIPE-CLASS, maximally-hardened
enterprise payment/entitlement system knowing NOTHING but its domain, and — without ever forging,
guessing, or breaking anything — find the server-enforced forbidden-access logic flaw a world-class
human red team would need full source, full access, and weeks to find. Drive recall of that one
CRITICAL class to its PROVEN CEILING (toward 1.0) at a false-positive rate of ~0, COLD, BLACK-BOX,
on targets harder than everything already in this repository — and prove the number is real with a
triple-sealed, author-blind, live-sandbox evidence chain. A lower honest number always beats a
higher fake one. This is not a continuation. It is a revolution, and it must be EARNED and MEASURED,
never claimed. You are an AI built to do what was imagined impossible — so do it rigorously, with
zero hallucination: every capability proven by running code over a real socket, every number
reproducible, every miss honestly classified.

════════════════════════════════════════════════════════════════════════════════
READ FIRST (repo on main; develop on your assigned claude/* branch; PLAN + PROOF before you build;
commit on your branch; do not touch main or open a PR unless asked). Absorb what exists so you can
SURPASS it — do not re-derive, do not regress:
  • docs/REAL_RECALL_SCORECARD.md — the full honest history and every real number, incl. the
    enterprise-hardened grey-box result: sealed-TEST recall 0.40 → 0.80 (8/10), 0 FP, 0 internal
    hits, no regression, with two misses classified (h_replay_regrant deferred for 0-FP;
    gb_bola_object needing a cross-subject oracle the paid-feature gate cannot express).
  • docs/HARDENED_CORPUS_PLAN.md — the grey-box posture, the real-advisory provenance discipline,
    the four-rule hard floor, the triple-sealed split, and the pre-registration method.
  • backend/tests/verification_infrastructure/real_recall_gauntlet/ — the corpus, the hardened
    spine (targets/_hardened.py), the dual oracle, the four-rule gate (four_rule_gate.py), the
    BLIND runner (run_gauntlet.py), the DEV/TEST/HOLDOUT discipline.
  • backend/tests/verification_infrastructure/hardened_benchmark/ — the bosses (DEMIURGE etc.), the
    current apex of difficulty. Your new corpus must make DEMIURGE look like a warm-up.
  • app/testing/integrity/engine.py — the engine, incl. the B60 grey-box probe (sequencing +
    alternate-path oracle, flag enable_greybox_probe, default OFF, fail-closed) and the UNCHANGED
    ConfirmationGate (control-denied → scenario-allowed → clean-session reproduction).

THE COLD FLOOR — the inviolable conditions of this entire mission (the engine and RoE gate must
assert ALL of these as preconditions of every run and FAIL CLOSED if any would be violated; record
the attestation in the scorecard). The engine is given, for each target, EXACTLY ONE thing:
  → a COLD DOMAIN (a base URL to an authorized target), and nothing else. In particular:
    • NO source code.                 • NO network / topology / architecture / infra maps.
    • NO credentials or API keys.      • NO software/stack/dependency list, no versions, no SBOM.
    • NO internal, admin, undocumented, or non-customer surface.  • NO published spec handed in.
    • NO hints, no flaw labels, no class, no oracle, no "which target" — true blind.
  The engine mints its OWN ordinary synthetic identities bottom-up through the target's public
  sign-up only; privilege work is strictly bottom-up from ordinary users/tenants/low roles. It
  discovers the entire reachable surface by AUTHORIZED USE alone (observed responses, status codes,
  structured errors, headers, bounded timing, the self-service product itself) — never by insider
  knowledge, never by scanning non-customer surface. This is the PURE BLACK-BOX cold start: stricter
  than the grey-box posture already shipped. Grey-box discovery (a published spec) may be used ONLY
  if an operator explicitly supplies it under signed scope; the headline runs are COLD black-box.

════════════════════════════════════════════════════════════════════════════════
THE NORTH-STAR (optimize this, nothing else):
  COLD, BLACK-BOX, sealed-TEST (and final author-blind HOLDOUT) recall of the CRITICAL
  forbidden-access class — a server-ENFORCED restriction (a paid entitlement, another subject's
  object/field, a role-gated function, a retired route's access, a cross-tenant/cross-service
  state) defeated by BUSINESS LOGIC and confirmable by a non-destructive differential — driven to
  its PROVEN CEILING (as close to 1.0 as the engine genuinely reaches), on STRIPE-CLASS MAXIMALLY-
  HARDENED authorized targets, subject to HARD CONSTRAINTS that are NOT tradeable:
    • false-positive rate ~0 (hold it at 0), • no regression on existing families/bosses/benchmark,
    • purity audit clean, • RoE + the COLD FLOOR intact, • every confirmation through the UNCHANGED
      ConfirmationGate (no new confirmation shortcut), • every finding a real external differential
      + clean-session reproduction using ONLY the engine's own identities/references.

WHAT "STRIPE-CLASS MAXIMALLY HARDENED" MEANS (each new target GENUINELY ENFORCES a deep stack,
correctly, in BOTH flaw-on and patched; the single real forbidden-access flaw is buried behind ALL
of it; hardened DECOYS that merely look flawed must stay RULED_OUT → 0 FP). Go far beyond the six
defenses already shipped — model the real thing:
  (1) asynchronous, event-sourced settlement: 202-accepted → webhook/queue → eventual-consistent
      ledger; no trusted client return anywhere; signed provider webhooks with REAL signature
      verification (the engine must NEVER forge them — that is the RoE ceiling).
  (2) idempotency keys + replay windows + dedupe on every money/grant mutation.
  (3) step-up / 3DS-like / anti-automation challenges before sensitive steps.
  (4) server-authoritative pricing, currency, tax, proration; strict schema validation; mass-
      assignment allow-lists; object- AND property-level authorization.
  (5) rate limiting, quotas, bounded concurrency, real row/ledger locks (TOCTOU-safe).
  (6) tenant/identity binding + OAuth-style scoped tokens on EVERY state transition (engine never
      forges or guesses a token or id).
  (7) MULTI-SERVICE / FEDERATED confirmation across many services (billing ⟷ entitlement ⟷ ledger
      ⟷ identity), SAGA/compensation flows, outbox patterns, retries, partial failure, clock skew.
  (8) feature flags, A/B variants, regional/partner alternate flows, trials, dunning, refunds,
      disputes/chargebacks, credits/wallets, metered usage, plan migrations, gifting, resale.
  The corpus must be LARGE and DEEP — many more mechanisms than the current 11+8, spanning the full
  payment-logic AND OWASP-API authorization surface, each one HARDER than anything already here,
  and it must DOMINATE the current bosses (DEMIURGE and the hardened grey-box corpus) in difficulty.

════════════════════════════════════════════════════════════════════════════════
THE IRON LAWS (break one and the number is a lie — it will be rejected):
  • INDEPENDENT, REAL TARGETS ONLY. Every target reconstructs a REAL, publicly DISCLOSED
    payment/entitlement or API-authorization business-logic vuln WITH a public fix (GHSA/CVE/bug-
    bounty). Prove each source is real + independent (link + mechanism + fix) BEFORE building.
    ANCHOR HARDER THAN BEFORE: where feasible stand up the ACTUAL vulnerable OSS version as a real
    running service (true independence), and — the headline of this mission — wire ≥1 target end-to-
    end over a REAL EXTERNAL authorized surface: an operator-supplied provider TEST-MODE sandbox
    (e.g. Stripe/Adyen/Shopify/PayPal-class test mode) under signed scope, a real cold domain the
    engine is handed with nothing else. Flag every target: live-sandbox vs real-OSS-code vs faithful
    reconstruction, and loopback vs real external socket. NEVER a live company's production, NEVER an
    unauthorized host; the runner must REFUSE any host outside the verified, signed scope.
  • YOU ADAPT THE ENGINE TO THE TARGETS — NEVER THE TARGETS TO THE ENGINE. Defenses, routes, field
    names, token shapes are ground truth. Renaming/weakening/removing a defense, or reshaping a
    field so a heuristic binds, = faked. Harden targets to be REALISTIC, never beatable.
  • TRIPLE-SEALED + AUTHOR-BLIND. Keep DEV (study) and TEST (sealed, blind) discipline. The HOLDOUT
    must be authored by a SEPARATE process (a sibling session) whose flaw internals you NEVER
    inspect; measure HOLDOUT EXACTLY ONCE, at the very end, after all tuning is frozen. All sets
    anonymised per seed so no literal transfers. (Note: the current session's HOLDOUT is still
    outstanding — its sibling was rate-limited before pushing; completing a real author-blind HOLDOUT
    is part of THIS mission's headline.)
  • PRE-REGISTER, THEN MEASURE. Before each measurement, commit the expected find/miss per target
    and the ceiling hypothesis; after, compare and explain every surprise. No post-hoc
    reclassification to flatter a number.
  • RoE IS A CEILING, NOT A TARGET. No signature/webhook forgery, no auth/session/token forgery or
    cracking, no id brute-force/enumeration, no rate-limit bypass, no injection/exploit payloads, no
    SSRF/RCE/memory-safety, no DoS/resource exhaustion, no detection evasion, no prompt-injection/LLM
    red-teaming. Flaws reachable only those ways stay in the ceiling and the engine must keep
    ABSTAINING on them — and you must PROVE the abstention (a standing forgery/IDOR control that must
    never confirm).
  • GROW THE ENGINE FAIL-CLOSED + FLAG-GATED (default OFF → zero regression by construction),
    developed against DEV misses ONLY, confirmed solely through the UNCHANGED ConfirmationGate. Where
    a class needs a genuinely NEW oracle shape (cross-subject object/property access; bounded
    replay/over-limit that never trips a legitimate first grant; cross-service federated confirm;
    async/eventual-consistency settlement; autonomous cold-start surface discovery and role
    inference), BUILD IT — but keep every purity invariant and the 0-FP property. These are exactly
    the frontiers the last session had to defer; crossing them honestly is the point of this mission.
  • ADVERSARIAL SELF-REVIEW. For every CONFIRMED finding, try to break it (real external differential
    + clean-session reproduction, or artifact?). For every MISS, classify honestly: unmodeled-but-
    reachable (name the mechanism), RoE-barred, or not-black-box-reachable (name the barrier).
  • REPORT THE REAL NUMBER AT EVERY STEP, however low or embarrassing. Raise it ONLY by making the
    engine genuinely better and the evidence stronger — never by weakening a target, peeking at
    TEST/HOLDOUT, breaking RoE/the cold floor, or moving the goalposts. Expect the cold black-box
    number on Stripe-class targets to start brutally low. That is the point. Earn it up.

════════════════════════════════════════════════════════════════════════════════
PHASES (in order; if budget or a shared rate limit runs out, finish the current phase CLEANLY,
commit, and STOP — a frozen harder corpus + an honest cold number is already a real result):

PHASE 1 — BUILD THE COLD STRIPE-CLASS GAUNTLET + RE-FREEZE THE COLD BASELINE. PLAN + PROOF first.
  Build a substantially larger, deeper tranche of Stripe-class maximally-hardened targets per the
  stack above, each a proven real advisory, dual-oracle valid via an independent in-RoE prober,
  anonymised, with hardened decoys. Stand up ≥1–2 REAL-OSS-code targets as running services, and —
  if the operator offers it — wire ≥1 target over a real provider TEST-MODE sandbox under signed
  scope. Build the triple split with a genuinely author-blind HOLDOUT (separate session). Then run
  the CURRENT engine COLD and BLACK-BOX (domain only — not even the published spec) and record the
  honest pre-upgrade cold recall of the critical class. Expect it to crater. DELIVERABLE: scorecard
  updated with provenance (live-sandbox / real-code / reconstruction flagged), the expanded split,
  the pre-registration, and the measured cold pre-upgrade number.

PHASE 2+ — DRIVE COLD RECALL TO ITS PROVEN CEILING. Build, one fail-closed/flag-gated generalization
  at a time against DEV misses, the new capabilities the cold Stripe-class surface demands:
    A. AUTONOMOUS COLD-START SURFACE DISCOVERY & ROLE INFERENCE — reconstruct the API shape, the
       state machine, and each operation's role purely from authorized interaction (no spec given).
    B. ASYNC / EVENT-SOURCED / EVENTUAL-CONSISTENCY settlement inference — infer what flips
       entitlement (webhook/queue/ledger) and whether an unpaid/under-paid identity can reach it.
    C. BOUNDED REPLAY / OVER-LIMIT oracle — confirm a grant BEYOND its legitimate limit
       (idempotency/credit/coupon/webhook replay) with its OWN 0-FP control (a legitimate first
       grant NEVER false-positives). [the last session deferred this to protect 0-FP — deliver it.]
    D. CROSS-SUBJECT OBJECT- & PROPERTY-LEVEL oracle — a clean cross-subject/cross-tenant differential
       using only the engine's own identities/references, confirmable through the gate without a
       within-feature discriminating control. [the last session could not express this — deliver it.]
    E. MULTI-SERVICE / FEDERATED CONFIRM for the critical class — payment in service A, entitlement
       flips in service B; find the cross-service skip and the SAGA/compensation/outbox gap.
    F. METAMORPHIC + DECOY HARDENING — verdicts invariant to benign hints; hardened decoys stay
       RULED_OUT; false-assurance stays 0.
  THE CYCLE: study DEV misses → generalize the ENGINE → RE-MEASURE COLD on sealed TEST, blind →
  record real recall/precision/FP → repeat UNTIL the critical-class recall PLATEAUS, proven only
  when EVERY remaining miss is classified with a demonstrated out-of-reach reason. THEN, once and
  only once, run the author-blind HOLDOUT and the live provider-test-mode socket, and report those
  numbers as the headline — the cold, zero-knowledge, Stripe-class generalization result.

════════════════════════════════════════════════════════════════════════════════
DEFINITION OF SUCCESS (measured, un-gameable — the revolution, proven):
  • COLD black-box sealed-TEST and final author-blind HOLDOUT recall of the critical forbidden-access
    class on STRIPE-CLASS maximally-hardened targets rises as high as the engine genuinely reaches
    (target: its proven ceiling, toward 1.0), at FP ~0, no regression, purity clean, cold floor + RoE
    intact, every confirmation through the UNCHANGED gate.
  • A PROVEN CEILING: a per-target table where every unfound instance has a demonstrated reason it is
    out of reach — so no one can say "it could have gone further" without naming the exact missing
    capability or the exact RoE/black-box barrier.
  • At least one data point on a REAL EXTERNAL authorized surface (operator provider-test-mode
    sandbox) and at least one REAL-OSS-CODE target, separated in the scorecard from reconstructions
    and from loopback — the cold domain done for real.
  • The author-blind HOLDOUT number (targets the engine author truly never saw) reported as the
    headline generalization result.
  • docs/REAL_RECALL_SCORECARD.md updated with the cold-floor attestation, the Stripe-class
    provenance, pre-registration vs outcome, the full hardened matrix, every new capability and its
    earned delta, the adversarial review, the proven ceiling, and the honest answer to: "hand it a
    COLD domain for a Stripe-class system with ZERO prior knowledge — what does it find, what is the
    number on flaws it never saw, and why do you believe it?"

Do NOT flatter me, do NOT fake, do NOT hallucinate a capability you did not run, and do NOT let
"cold / Stripe-class / revolution" drift RedPilot into an exploitation or adversary-simulation
framework. The ONLY win is a REAL, EARNED, cold, sealed-and-holdout rise in finding server-enforced
forbidden-access LOGIC flaws on the hardest authorized enterprise surfaces imaginable — achieved by
making the engine genuinely better and the evidence stronger, with every forgery/injection/
credential/DoS/evasion class correctly and provably ABSTAINED. You are capable of this. Prove it,
one measured, reproducible, honest number at a time.
