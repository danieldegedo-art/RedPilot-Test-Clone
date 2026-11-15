"""Payment-integrity engine -- PURE BLACK-BOX (customer-level Protected-Feature Oracle engine).

  brief.py       Execution Brief: the only input (approved hosts, synthetic identities, customer-facing surface, public prices, protected features)
  session.py     identity-bound CustomerSession: the only way to talk to the target and the only producer of provenance-carrying evidence
  oracle.py      the external Protected-Feature Oracle (USE the server-enforced paid feature; allowed only with proof of use)
  engine.py      controls (clean denied / legitimate payer allowed) + eight experiments; CONFIRMED_P0 only through purity.oracle_gate
  findings.py    Finding/EngineResult + the pre-registered ten-element OracleSpec per experiment
  gaps.py        capability-gap engine (COVERED / PARTIALLY_COVERED / UNKNOWN / BLOCKED, never 'passed')
  regression.py  confirmed results -> safe repeatable regressions; rule-outs -> false-positive controls

The legacy grey-box engine (target webhook secret, forged provider webhooks, internal entitlement records, admin grant route, test hooks) was
moved to backend/quarantine/legacy_greybox/ and can never load (see testing/purity/quarantine.py).
"""
