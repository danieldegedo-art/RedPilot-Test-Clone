"""Compatibility shim: the Oracle Engine is product code now (app/testing/integrity/oracle_engine.py).
Kept so benchmark_lab.py and the tests retain their import path. Do not add logic here."""
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)
from app.testing.integrity.oracle_engine import (  # noqa: F401
    GRANT_STATUS, SPEC_A, SPEC_B, SPEC_BASELINE, SPEC_C, SPEC_D, SPEC_E, SPEC_F, SPEC_G, SPEC_H, SPEC_I,
    EngineResult, EvidenceItem, Finding, OracleEngine, OracleSpec, Verdict, make_evidence,
)
