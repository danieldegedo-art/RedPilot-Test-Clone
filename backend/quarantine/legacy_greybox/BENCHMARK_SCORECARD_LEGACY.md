> **QUARANTINED / INVALID AS A BLACK-BOX CLAIM.** Every number below was measured with grey-box inputs (the target's webhook signing secret, a provider-facing webhook channel, internal entitlement records, an admin grant route and a test-only revocation-delay hook). Under the Pure Black-Box mandate none of it may be cited as capability. Kept for audit only; removal by 2026-11-30.

# Payment Integrity Benchmark Scorecard

Generated 2026-09-29T22:17:51 from `tests/verification_infrastructure/benchmark_lab.py` -- 17 seeded scenarios x 10 oracles, every number below MEASURED by running the code (legacy numbers come from running the legacy prober on the same targets).

**Read these limits first:** the engine's author also wrote the targets (shared-authorship bias); all timing is local loopback and not representative; ORC-I is timing-based (medium confidence by design); severity ranking accuracy is NOT measured.

| Metric | Baseline (legacy prober) | Post (Oracle Engine) | Method | Confidence | Known limitations |
|---|---|---|---|---|---|
| `seeded_p0_detection_rate` | 0.2667 | 0.8214 (like-for-like on B,C,F,G: 0.7333) | fair slice, perimeter-off targets only, B,C,F,G: legacy 1 vs engine 1 | truth derived from target flags; detection = verdict confirmed_p0/strongly_suspected_p0 over all (scenario, class) pairs whose truth is P0. like_for_like restricts to the 4 classes (B,C,F,G) the legacy prober can express. | medium | 17 self-authored scenarios; shared authorship bias; loopback only. THE HEADLINE GAP IS PARTLY BY CONSTRUCTION: the legacy prober cannot sign webhooks, so on every target with a signature perimeter it can only say ruled_out. The perimeter_off_slice (targets where legacy CAN operate) is the fair comparison of raw detection skill; the rest of the gap is the real-world blind spot it represents (every real payment webhook endpoint has a signature perimeter) |
| `false_assurance_rate` | 0.7333 | 0 (like-for-like on B,C,F,G: 0) | share of truth-P0 pairs reported RULED_OUT (the dangerous error: a real P0 declared clean) | medium | same scenario set; this metric was not in the original scorecard spec but is the honest counterpart to the false-positive rate |
| `missed_as_unknown_rate` | 0 | 0.1786 (like-for-like on B,C,F,G: 0.2667) | truth-P0 pairs reported UNKNOWN/BLOCKED/DIVERGENCE: not detected, but NOT a false assurance -- the known, documented gap | medium | see above |
| `false_positive_rate` | 0.0816 | 0 (like-for-like on B,C,F,G: 0) | share of truth-not-P0 pairs (SAFE or DIVERGENCE: fully_fixed, decoys, robustness, every non-buggy class of the single-bug scenarios, and the mitigated-downstream grant bug) reported confirmed_p0/strongly_suspected_p0 | medium | decoy set is small (3 decoy + 1 robustness scenario); a decoy the author did not think of is by definition not in it |
| `multi_step_chain_detection_rate` | 0 | 1 | chain scenarios (lag_only->I, cache_divergence_chain->E, signature_only_fixed->B behind the perimeter); hit iff the class characteristic of the chain is confirmed_p0 | low-medium | only 3 seeded chains, each a 2-control interaction, not an open-ended composition; the legacy prober cannot express classes E and I at all and cannot sign, so 0/3 is by construction, not a measured weakness of its detection logic |
| `severity_ranking_accuracy` | not measured | not measured | NOT MEASURED in this iteration: a ranking accuracy needs a severity ground truth independent of the engine's own priority table; defining both would be circular | n/a | open item -- needs a customer-supplied or independently authored severity model |
| `time_to_first_p0_hypothesis_s` | 0.0023 | 0.0305 | median over scenarios with >=1 P0 finding of the cumulative oracle time up to and including the first P0-like verdict, in each tool's own run order | low | loopback latency; NOT representative of a real network; the new engine runs ORC-BASELINE and A first, the legacy prober runs B first |
| `time_to_confirm_or_rule_out_s` | 0.0027 | 0.0437 | mean per-oracle wall time over non-blocked oracles | low | loopback; post includes ORC-I's deliberate 0.3s+0.1s timing window, which is the price of testing a time-dependent class at all |
| `confirmed_finding_reproducibility` | not measured (legacy prober had no reproducibility measurement) | 1 | selected scenarios re-run 3x on fresh targets; a confirmed pair is reproducible iff every re-run agrees | medium | same-process, same-machine reruns; ORC-I is timing-based and the most likely to flake under load |
| `oracle_completeness` | 0.4 | 1 | static audit of the 10 required oracle elements (invariant, baseline, identity+tenant, controlled variable, action sequence, expected outcome, P0 condition, rule-out condition, stop condition, evidence requirements) against each tool's finding/spec dataclass fields | high (it is a schema fact) | measures that the fields EXIST and are non-empty, not that their content is well chosen |
| `evidence_artifact_completeness` | 0.5 | 1 | post: share of evidence items with valid classification + non-empty detail + parseable ISO timestamp + sha256 (audited at runtime over every finding). baseline: legacy Evidence has 2 of those 4 attributes (classification, detail) -- static audit | high | no HAR/screenshot capture exists in either; hash is a 16-hex tamper-evidence digest of the detail text, not of raw request/response bytes |
| `regression_pass_rate` | 15/15 test files (107 tests) passed; no oracle-level regression matrix existed | 1 | exact-match of (scenario x 10 oracle classes) verdict against the expectation derived from the target flags | medium | expectations are derived by the same author's model of correct behaviour |
| `unknown_critical_exposure_count` | 8 | 5 | baseline = Phase-0 Missing-Inputs register (8 classes). post = classes the engine itself reports UNKNOWN/BLOCKED on wide_open (E, I: preconditions) + 3 classes it does not implement at all | low | a mapping of classes, not a measured detection; race/concurrent-duplicate class is still only partially covered (sequential replay only) |
| `newly_testable_p0_classes` | ['B', 'C', 'F', 'G'] | ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'] | set difference between the bug classes each tool has an oracle for | high (set difference) | class A was only incidentally exercised by the legacy prober (never isolated); counted as newly testable because it now has its own falsifiable oracle |

## Verdict matrix (engine)

| Scenario | BASELINE | A | B | C | D | E | F | G | H | I |
|---|---|---|---|---|---|---|---|---|---|---|
| wide_open | ok | P0 | P0 | P0 | P0 | UNK | P0 | P0 | P0 | UNK |
| fully_fixed | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| only_A_no_signature | ok | P0 | ok | ok | ok | ok | ok | ok | ok | ok |
| only_B_status_trust | ok | ok | div | ok | ok | ok | ok | ok | ok | ok |
| only_C_replay | ok | ok | ok | P0 | ok | ok | ok | ok | ok | ok |
| only_D_no_revocation | ok | ok | ok | ok | P0 | UNK | ok | ok | ok | UNK |
| only_F_amount | ok | ok | ok | ok | ok | ok | P0 | ok | ok | ok |
| only_G_tenant | ok | ok | ok | ok | ok | ok | ok | P0 | ok | ok |
| only_H_currency | ok | ok | ok | ok | ok | ok | ok | ok | P0 | ok |
| lag_only | ok | ok | ok | ok | ok | ok | ok | ok | ok | P0 |
| cache_divergence_chain | ok | ok | ok | ok | P0 | P0 | ok | ok | ok | UNK |
| signature_only_fixed | ok | ok | P0 | P0 | P0 | UNK | P0 | P0 | P0 | UNK |
| signature_only_fixed_no_secret | ok | ok | UNK | UNK | P0 | UNK | UNK | UNK | UNK | UNK |
| free_tier_decoy | div | div | div | UNK | div | div | div | div | div | div |
| free_tier_declared_open | ok | div | div | UNK | div | div | div | div | div | div |
| stale_status_view | ok | ok | ok | ok | ok | div | ok | ok | ok | ok |
| broken_setup | ok | BLK | BLK | BLK | BLK | BLK | BLK | BLK | BLK | BLK |

Legend: P0 = confirmed_p0, ok = ruled_out, div = observed_divergence, UNK = unknown_critical_exposure (never a claim of safety), BLK = blocked (setup failed).

## Verdict matrix (legacy prober, same targets; only B,F,C,G expressible)

| Scenario | B | F | C | G |
|---|---|---|---|---|
| wide_open | P0 | P0 | P0 | P0 |
| fully_fixed | ok | ok | ok | ok |
| only_A_no_signature | ok | ok | ok | ok |
| only_B_status_trust | ok | ok | ok | ok |
| only_C_replay | ok | ok | ok | ok |
| only_D_no_revocation | ok | ok | ok | ok |
| only_F_amount | ok | ok | ok | ok |
| only_G_tenant | ok | ok | ok | ok |
| only_H_currency | ok | ok | ok | ok |
| lag_only | ok | ok | ok | ok |
| cache_divergence_chain | ok | ok | ok | ok |
| signature_only_fixed | ok | ok | ok | ok |
| signature_only_fixed_no_secret | ok | ok | ok | ok |
| free_tier_decoy | P0 | UNK | ok | P0 |
| free_tier_declared_open | P0 | UNK | ok | P0 |
| stale_status_view | ok | ok | ok | ok |
| broken_setup | CRASH | CRASH | CRASH | CRASH |
