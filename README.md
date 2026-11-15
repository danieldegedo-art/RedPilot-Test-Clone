# RedPilot — Developer Test Clone

**Private developer test clone** of the RedPilot payment/entitlement QA engine. This copy has enterprise
controls removed so the developer can test the system end-to-end against their own decoy targets.

## What's different from the main repo

This is the complete RedPilot codebase with these enterprise controls stripped:

- **Control port** always returns the FailOpen adapter (enterprise controls never loaded)
- **Execution Brief parser** accepts briefs without purity/credential/attestation/environment validation
- **Attack-chain composition** (B32) — `enabled` gate removed, always active
- **Fleet orchestration** (B33) — `enabled` gate removed, always active
- **Capability synthesis** (B34) — `enabled` gate removed, always active
- **Twin self-play** (B31) — `enabled` gate removed, always active
- **Browser surface planner** (B35) — `enabled` gate removed, always active
- **External tool bridge** (B38) — `enabled` gate and denylist removed, always active

The enterprise controls package (`app/enterprise_controls/`) is still present but is dead code —
the control port never loads it.

## Purpose

For the developer to run the full system once against their own test targets (a decoy paywall
deployed to a cold domain) to validate how far the engine has come. Not for distribution.

## Everything else

The engine, oracle, confirmation gate, all 29 capabilities, all bosses, the test suite — everything
is identical to the main repo. Only the enterprise gates are bypassed.

---

## Quick start

```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install "cryptography>=42,<46"
export PYTHONPATH="tests/verification_infrastructure/shims:tests/verification_infrastructure:."

# Run any boss:
python3 tests/verification_infrastructure/hardened_benchmark/run_abraxas.py --controls

# Run the full benchmark:
./run-benchmark.sh all
```
