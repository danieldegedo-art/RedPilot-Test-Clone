"""Quarantine guard — TEST CLONE: quarantine removed. All modules can load."""
from __future__ import annotations

QUARANTINE_REMOVAL_DEADLINE = "2026-11-30"
QUARANTINE_REASON = "n/a (test clone)"


def refuse_in_pure_mode(module_name: str) -> None:
    pass
