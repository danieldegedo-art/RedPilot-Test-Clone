# Black-Box Purity Benchmark Scorecard

Generated 2026-11-06T20:58:30+00:00 by `scripts/run_purity_benchmark.py` -- 21 scenarios x 8 experiments, every number below MEASURED by running the code (86.7s).

**Read these limits first:** the engine's author also wrote the targets (shared-authorship bias); all timing is local loopback; refund polling is a bounded schedule (lags are upper bounds); three P0 classes cannot be tested by a pure black-box tester and are reported BLOCKED rather than scored (provider-event authenticity, concurrent duplicates, lifecycle incl. coupons/trials/renewal); severity ranking is not measured; the legacy column measures the PRE-MIGRATION engine on the SAME targets with no secret -- it is 0 by construction (it cannot operate without grey-box inputs), which demonstrates the dependency, NOT inferior detection logic.

> The previous scorecard (17 scenarios x 10 oracles, detection 0.8214) was measured with grey-box inputs (the target's webhook signing secret, forged provider events, internal entitlement records, an admin grant route, a test-only delay hook). It is archived at `backend/quarantine/legacy_greybox/BENCHMARK_SCORECARD_LEGACY.md` and **must not be cited as black-box capability**.

| Metric | Baseline (pre-migration engine, same targets, no secret) | Post (pure black-box engine) | Detail | Method | Confidence | Known limitations |
|---|---|---|---|---|---|---|
| `seeded_p0_detection_rate` | 0 (legacy engine BLOCKED on every oracle) | 1 | truth-P0 pairs: 19; TP=19 | detection = verdict CONFIRMED_P0 reached through the ConfirmationGate (control denied -> feature USED -> clean-session reproduction); truth is scorer-side only | medium | 21 self-authored scenarios; shared authorship (engine and targets by the same author); loopback only |
| `false_assurance_rate` | 0 (nothing was ruled out; all BLOCKED) | 0 | RULED_OUT on truth-P0: 0; RULED_OUT on externally unprovable: 0 | the dangerous error: declaring clean what is vulnerable or unprovable | medium | same scenario set |
| `false_positive_rate` | 0 | 0 | CONFIRMED_P0 on truth non-P0: 0 | includes UI-only anomalies, hint decoys, within-tolerance lag, open/opaque/broken targets | medium | decoy set is small and author-written |
| `unknown_honesty_rate` | 1 (everything BLOCKED) | 1 | externally unprovable pairs: 33; honest UNKNOWN/BLOCKED/PARTIAL: 33 | opaque async feature, open feature, broken sandbox must end UNKNOWN/BLOCKED/PARTIAL -- never RULED_OUT, never CONFIRMED | medium | 3 externally-unprovable scenarios |
| `safe_ruled_out_rate` | n/a | 1 | TN=116 of 116 safe pairs; inconclusive-on-safe=0 | correct behaviour is ruled out (not merely unconfirmed) | medium | limited to tested channels |
| `blind_spot_honesty` | n/a | 0/1 detected; 1/1 listed as BLOCKED gap | a seeded flaw outside the modelled classes (coupon) | the engine does NOT find it (no experiment models it) and says so: the lifecycle/coupon class is BLOCKED in the gap register and the summary states that 'no confirmed P0' never means 'no P0 exists' | medium | one blind-spot scenario; the true share of unmodelled flaws in real targets is unknown |
| `ui_only_false_positive_resistance` | n/a | 1 | UI-only pairs: 2; reported as divergence, not P0: 2 | pages/badges/redirects claim paid while the server-enforced feature stays denied | medium | one UI-only scenario |
| `internal_route_hits_total` | n/a (legacy engine used internal/admin routes by design) | 0 | hint scenarios: 2; hints present AND dropped in 2 | target-side counter of requests to /internal, /admin, /__benchmark__ routes that exist in the benchmark environment | high (counted at the target) | counts only these route prefixes |
| `metamorphic_hints_on_off` | n/a | identical | failed_payment_grants_access vs hints_real_flaw | verdicts must not change when benchmark-environment hints are present | high | one metamorphic pair |
| `purity_gate_denials_caused_by_engine` | n/a | 0 | ScopeGuard purity gate denials during engine runs | the engine never addresses a non-customer-facing surface | high | none |
| `evidence_integrity` | n/a | 1597 artifacts: bad_hash=0, bad_classification=0, missing_fields=0, unredacted=0 | rejected at admission: 0 | independent scorer recomputes every hash, checks the five external classifications, required provenance fields and redaction of token/payment/tenant id formats | high | hash covers the redacted payload, not raw wire bytes |
| `reproducibility` | not measured | 6/6 scenarios identical over 3 runs | failed_payment_grants_access, cross_tenant_binding, replay_duplicate_value, refund_retention, fully_fixed, ui_only_anomaly | same verdict map on three fresh targets | medium | same machine/process; refund timing is the likeliest flake |
| `regression` | not measured | replay on fixed target passes: True; replay on still-buggy target flags regression: True | PBB-U (regression_for_confirmed_p0): expected RULED_OUT, got CONFIRMED_P0  <-- REGRESSION; PBB-F (false_positive_control): expected RULED_OUT, got RULED_OUT; PBB-H (false_positive_control): expected RULED_OUT, got RULED_OUT; PBB-C (false_positive_control): expected RULED_OUT, got RULED_OUT; PBB-G (false_positive_control): expected RULED_OUT, got RULED_OUT; PBB-X (false_positive_control): expected RULED_OUT, got RULED_OUT; PBB-R (false_positive_control): expected RULED_OUT, got RULED_OUT; PBB-E (false_positive_control): expected RULED_OUT, got RULED_OUT | a confirmed P0 becomes a regression that must turn RULED_OUT after the fix | medium | regression spec covers verdicts, not request payloads |
| `oracle_spec_completeness` | 0.4 (legacy, measured pre-migration) | 1 | 9 pre-registered specs x 10 elements | static schema fact | high | fields exist and are non-empty; content quality not measured |
| `severity_ranking_accuracy` | not measured | not measured | - | needs an independent severity model | n/a | open item |

Legacy baseline: 210 oracle results over 21 scenarios -> {'blocked': 210}; detections=0, false assurance=0. Inputs: {'expected_gated': True, 'webhook_secret': None}. Each legacy run made exactly two setup calls (`POST /api/v1/payments` and `GET /api/v1/access/{user}` -- routes of the grey-box reference vocabulary that a customer-level target does not have; the targets answer 401) and then reported every oracle BLOCKED.


## Verdict matrix (pure black-box engine)

| Scenario | U | F | H | C | G | X | R | E | OPEN | LEAK | truth |
|---|---|---|---|---|---|---|---|---|---|---|---|
| fully_fixed | ok | ok | ok | ok | ok | ok | ok | ok | - | - | all SAFE |
| failed_payment_grants_access | P0 | ok | ok | ok | ok | ok | ok | ok | - | - | U=P0 |
| ui_only_anomaly | ok | ok | ok | ok | ok | ok | ok | PART | - | - | U=DIV E=DIV |
| opaque_async_feature_internal_flaw | UNK | UNK | UNK | UNK | UNK | UNK | UNK | UNK | - | - | U=UNK F=UNK H=UNK C=UNK G=UNK X=UNK R=UNK E=UNK |
| hints_decoy_fixed | ok | ok | ok | ok | ok | ok | ok | ok | - | - | all SAFE |
| hints_real_flaw | P0 | ok | ok | ok | ok | ok | ok | ok | - | - | U=P0 |
| cross_tenant_binding | ok | ok | ok | ok | P0 | ok | ok | ok | - | - | G=P0 |
| cross_identity_binding | ok | ok | ok | ok | ok | P0 | ok | ok | - | - | X=P0 |
| plan_claim_tamper | ok | P0 | ok | ok | ok | ok | ok | ok | - | - | F=P0 |
| amount_tamper | ok | P0 | ok | ok | ok | ok | ok | ok | - | - | F=P0 |
| plan_not_enforced | ok | P0 | ok | ok | ok | ok | ok | ok | - | - | F=P0 |
| currency_confusion | ok | ok | P0 | ok | ok | ok | ok | ok | - | - | H=P0 |
| replay_duplicate_value | ok | ok | ok | P0 | ok | ok | ok | ok | - | - | C=P0 |
| refund_retention | ok | ok | ok | ok | ok | ok | P0 | ok | - | - | R=P0 |
| revocation_lag_beyond_sla | ok | ok | ok | ok | ok | ok | P0 | ok | - | - | R=P0 |
| revocation_lag_within_sla | ok | ok | ok | ok | ok | ok | ok | ok | - | - | all SAFE |
| open_feature | UNK | UNK | UNK | UNK | UNK | UNK | UNK | PART | PART | - | U=UNK F=UNK H=UNK C=UNK G=UNK X=UNK R=UNK E=UNK |
| broken_setup | BLK | BLK | BLK | BLK | BLK | BLK | BLK | BLK | - | - | U=UNK F=UNK H=UNK C=UNK G=UNK X=UNK R=UNK E=UNK |
| global_entitlement_leak | UNK | UNK | UNK | UNK | UNK | UNK | UNK | UNK | - | P0 | U=UNK F=UNK H=UNK C=UNK G=UNK X=UNK R=UNK E=UNK |
| unprobed_coupon_flaw | ok | ok | ok | ok | ok | ok | ok | ok | - | - | all SAFE |
| wide_open | P0 | P0 | P0 | P0 | P0 | P0 | P0 | ok | - | - | U=P0 F=P0 H=P0 C=P0 G=P0 X=P0 R=P0 |

Legend: P0 = CONFIRMED_P0, ok = RULED_OUT, UNK = UNKNOWN, BLK = BLOCKED, PART = PARTIALLY_VALIDATED (never a confirmation). Experiments: U unconfirmed payment, F plan/price binding, H currency binding, C duplicate value by return-flow repetition, G cross-tenant, X cross-identity, R retention after refund, E UI-vs-server divergence; OPEN = paid feature open to unpaid identities; LEAK = one payer's entitlement usable by an unrelated, never-paying identity.

## Purity-benchmark requirements (mandate) -> scenario

- `failed_payment_grants_access`: purity benchmark #1: real externally observable payment-to-entitlement flaw, confirmable only through the protected-feature oracle
- `ui_only_anomaly`: purity benchmark #2: UI/redirect-only anomaly must NOT become CONFIRMED_P0
- `opaque_async_feature_internal_flaw`: purity benchmark #3: internal evidence would reveal the flaw, external evidence is insufficient -> UNKNOWN/BLOCKED
- `hints_decoy_fixed`: purity benchmark #4: lying target-side hints must be ignored
- `hints_real_flaw`: purity benchmark #4b: true hints present, verdicts must still come from the oracle only (metamorphic partner of failed_payment_grants_access)
- `cross_tenant_binding`: purity benchmark #5: cross-tenant binding provable only by authorised two-tenant comparison
- `cross_identity_binding`: purity benchmark #5b: cross-identity binding
