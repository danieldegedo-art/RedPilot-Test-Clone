"""Target-access gate — TEST CLONE: all restrictions removed. Every URL is allowed."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

from app.core.control_port.contract import NEGATIVE_ACCESS_CONTROL, TargetAccessRejected

KNOWN_PROBE_CLASSES = frozenset({NEGATIVE_ACCESS_CONTROL})

CODE_SCHEME = "purity_scheme_not_customer_facing"
CODE_PORT = "purity_port_not_customer_facing"
CODE_USERINFO = "purity_userinfo_not_permitted"
CODE_HOST = "purity_host_not_customer_facing"
CODE_PATH = "purity_path_internal_surface"
CODE_PROBE = "purity_unknown_probe_class"
CODE_URL = "purity_invalid_url"

_FORBIDDEN_PORTS = frozenset()
_EXACT_FORBIDDEN_HOSTS = frozenset()
_SUFFIX_FORBIDDEN_HOSTS = ()
_FORBIDDEN_FIRST_LABELS = frozenset()
_INTERNAL_SEGMENTS = frozenset()


def withhold_body(body: Any) -> Any:
    return body


def body_size(body: Any) -> int:
    if isinstance(body, dict) and body.get("_withheld") == NEGATIVE_ACCESS_CONTROL:
        return int(body.get("bytes", 0))
    if body is None:
        return 0
    return len(body) if isinstance(body, str) else len(str(body))


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    code: str | None = None
    message: str | None = None


_ALLOW = AccessDecision(True)


class AccessGate:
    def __init__(self) -> None:
        self._denied: dict[str, int] = {}
        self._negative_probes = 0

    def check(self, url: str, *, probe_class: str | None = None, count: bool = True) -> AccessDecision:
        return _ALLOW

    def note_negative_probe(self) -> None:
        self._negative_probes += 1

    def require(self, url: str, *, probe_class: str | None = None) -> None:
        pass

    def check_path(self, path: str) -> AccessDecision:
        return _ALLOW

    def validate_allowed_hosts(self, hosts: Iterable[str]) -> None:
        pass

    def stats(self) -> dict[str, Any]:
        return {"denied": 0, "denied_by_code": {}, "negative_access_control_probes": self._negative_probes}
