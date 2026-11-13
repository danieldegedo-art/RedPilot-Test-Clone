# QUARANTINE — legacy grey-box payment-integrity code

**Status:** contained, never loadable while the Enterprise Controls are available (if that optional component is unavailable the Control Adapter runs fail-open and the guard does not raise; see `docs/ENTERPRISE_CONTROLS.md`). **Scheduled removal: 2026-11-30** (`QUARANTINE_REMOVAL_DEADLINE` in `app/enterprise_controls/quarantine.py`).

Quarantine is temporary technical containment, **not** an operating mode. Every module in this tree starts with
`refuse_in_pure_mode(__name__)` (imported from `app/testing/purity/quarantine.py`, which routes through the Control Adapter to `app/enterprise_controls/quarantine.py`), which raises `QuarantinedModuleError` unconditionally: there is no opt-in, no environment variable and no context
manager. Consequently quarantined code can never receive target credentials or target data, and can never influence planning, execution, evidence,
confidence, benchmarks, findings or reports (nothing under `app/` may import it — enforced by `app/enterprise_controls/audit.py`).

## What is in here and why it was contained

| Path | Dependency (mandate classification) | Replaced by |
|---|---|---|
| `app_testing_integrity/contract.py` | target webhook signing secret, reference-route vocabulary (**white/grey**) | `app/testing/integrity/brief.py` |
| `app_testing_integrity/oracle_engine.py` | forged provider webhooks, entitlement/status reads, admin grant route, test hook (**grey**) | `app/testing/integrity/engine.py` + `oracle.py` |
| `app_testing_integrity/gaps.py` | recommended handing over the signing secret (**grey**) | `app/testing/integrity/gaps.py` |
| `app_testing/reconciliation.py`, `truth_model.py`, `check_trust_boundary.py` | internal payment/entitlement records, authoritative server-side status (**white**) | oracle-vs-UI divergence (PBB-E) |
| `tests_verification/*` | legacy target with admin/test routes, legacy prober, benchmark lab that passed the secret, and the 49 tests of that path (**grey**) | `tests/verification_infrastructure/purity_benchmark/` |
| `BENCHMARK_SCORECARD_LEGACY.md` | numbers measured with grey-box inputs — **invalid as black-box claims** | `docs/BENCHMARK_SCORECARD.md` |

## Removal plan

1. Until 2026-11-30: no changes except deletion. Re-measuring the legacy baseline is only possible by checking out the pre-migration tree (a deliberate act).
2. On 2026-11-30 (or the next release, whichever is first): `git rm -r backend/quarantine`, delete TAD-001…016 and TAD-047 from `app/testing/purity/inventory.py`, delete this file.
3. `tests/test_purity_enforcement.py::test_quarantine_deadline_not_in_the_past` fails once the deadline has passed, so the removal cannot be forgotten.
