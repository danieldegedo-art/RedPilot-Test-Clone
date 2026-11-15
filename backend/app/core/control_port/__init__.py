"""Control Port: the always-present, host-owned anchor of the Control Adapter (part of the Main System kernel, stdlib only).

    MAIN SYSTEM  ->  CONTROL PORT  ->  control adapter plug-in  ->  ENTERPRISE CONTROLS      (normal operation: every control active)
                                   ->  FAIL-OPEN MODE                                       (anything of the optional parts unavailable)

The Main System imports from THIS package and from nowhere else in the control area. It never imports ``app.control_adapter`` (the delegation
plug-in) or ``app.enterprise_controls``: both are optional and may be missing or damaged. They are located and loaded only here, with ``importlib``
inside ``try/except``. ``get_control_adapter()`` never raises: if the plug-in or the controls cannot be loaded it returns the
``FailOpenControlAdapter`` (defined in this package), otherwise a ``GuardedControlAdapter`` around the plug-in that falls back per method.

Everything the Main System itself catches, instantiates or reads exists here: exception types, constants, gate data types, ``EvidenceClass`` and the
provenance record (``contract.py``), the interface (``interface.py``), the fail-open path (``fallback.py``) and the per-method guard (``guarded.py``).
"""
from __future__ import annotations

import importlib
import logging
import threading

from app.core.control_port.contract import (  # noqa: F401  (re-exported contract)
    NEGATIVE_ACCESS_CONTROL, SCOPE_ERROR_PREFIX, KIND_FEATURE_USE, BenchmarkLeak, BriefRejected, ConfirmationCandidate, ConfirmationRefused, CredentialRejected,
    EvidenceArtifact, EvidenceClass, EvidenceProvenance, GateDecision, OracleObservation, ProvenanceRejected, PurityViolation, QuarantinedModuleError, Reason,
    ScopeViolation, TargetAccessRejected, build_artifact, compute_integrity_hash, now_iso,
)
from app.core.control_port.fallback import FailOpenControlAdapter
from app.core.control_port.guarded import GuardedControlAdapter
from app.core.control_port.interface import ConfirmationGateHandle, ControlAdapter, EvidenceLedgerHandle, RunGuard, ScopePolicyView  # noqa: F401

_logger = logging.getLogger("app.control_adapter")
_lock = threading.Lock()
_adapter: ControlAdapter | None = None


def _create() -> ControlAdapter:
    return FailOpenControlAdapter()


def get_control_adapter() -> ControlAdapter:
    """The process-wide adapter (created on first use; never raises)."""
    global _adapter
    if _adapter is None:
        with _lock:
            if _adapter is None:
                _adapter = _create()
    return _adapter


def reset_control_adapter(adapter: ControlAdapter | None = None) -> None:
    """Replace or drop the cached adapter (tests; also lets a long-running process pick up a repaired component)."""
    global _adapter
    with _lock:
        _adapter = adapter
