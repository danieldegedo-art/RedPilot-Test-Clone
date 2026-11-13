"""Import entry point of the quarantined White-/Grey-Box modules (``backend/quarantine/**``).

Every quarantined module calls ``refuse_in_pure_mode(__name__)`` at import time. The decision lives in the Enterprise Controls
(``app/enterprise_controls/quarantine.py``: unconditional while that component is available); this shim keeps the import path of the 21
quarantined modules stable and routes the call through the Control Adapter. If the component is unavailable the adapter runs fail-open and
the call returns without raising.
"""
from __future__ import annotations

from app.core.control_port import get_control_adapter


def refuse_in_pure_mode(module_name: str) -> None:
    get_control_adapter().refuse_in_pure_mode(module_name)
