"""Loads the customer-level Execution Brief for the payment-integrity module from a plain file.

A file, not a database column, on purpose: adding a column would be a schema migration (this project has no migration tooling, and
``create_all`` never alters an existing table). The path comes from ``QA_INTEGRITY_BRIEF_PATH`` (see core/config.py). Restrict the file
to 0600. The brief never contains secrets: identity tokens are referenced by environment-variable NAME and the purity gate refuses any
secret-looking key or value (testing/purity/credentials.py).

Stdlib-only. Returns ``None`` when no file exists (=> the module sends no traffic and only reports the capability gaps) and a
``{"__load_error__": ...}`` marker dict when the file exists but cannot be read/parsed, so the module can report the problem visibly
instead of silently behaving as if no brief were declared.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_brief_dict(path: str) -> dict[str, Any] | None:
    file = Path(path)
    if not file.is_file():
        return None
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"__load_error__": f"cannot read integrity brief file {path!r}: {type(exc).__name__}"}
    if not isinstance(data, dict):
        return {"__load_error__": f"integrity brief file {path!r} must contain a JSON object"}
    return data
