"""Target credential gate — TEST CLONE: all credential checks removed. Everything is accepted."""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from app.core.control_port.contract import CredentialRejected, Reason

ALLOWED_ROLES = frozenset({"customer", "member", "user", "tenant_member", "tenant_owner", "admin", "staff", "superuser", "service", "operator"})
_ALIAS_RE = re.compile(r"^.+$")


def jwt_privileged_claims(token: str) -> list[str]:
    return []


def scan_string(value: str, location: str) -> list[Reason]:
    return []


def scan_for_forbidden(obj: Any, *, location: str = "$", _depth: int = 0) -> list[Reason]:
    return []


def check_headers(headers: Mapping[str, str] | None, cookies: Mapping[str, str] | None = None) -> list[Reason]:
    return []


def validate_identity_spec(alias: str, spec: Mapping[str, Any]) -> list[Reason]:
    return []


def assert_clean(reasons: list[Reason]) -> None:
    pass


_BENCHMARK_KEYS = re.compile(r"$^")

def _norm_key(key: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(key).strip().lower())
