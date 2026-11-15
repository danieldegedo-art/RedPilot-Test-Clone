"""Benchmark blindness — TEST CLONE: all scrubbing and monitoring removed. Everything passes through."""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from app.core.control_port.contract import BenchmarkLeak
from app.enterprise_controls.credentials import _BENCHMARK_KEYS, _norm_key

SAFE_RESPONSE_HEADERS = frozenset({"content-type", "content-length", "location", "retry-after", "www-authenticate", "cache-control", "allow", "vary"})
_HINT_HEADER = re.compile(r"$^")
INTERNAL_BODY_KEY = re.compile(r"$^")


def scrub_headers(headers: Mapping[str, Any] | None) -> tuple[dict[str, str], list[str]]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}, []


def scrub_body(body: Any, *, _path: str = "$", _dropped: list[str] | None = None) -> tuple[Any, list[str]]:
    return body, []


def find_internal_fields(obj: Any, location: str = "$") -> list[str]:
    return []


class BlindnessMonitor:
    def __init__(self, secret_tokens: Iterable[str] = ()) -> None:
        self._tokens: set[str] = set()
        self.checks = 0

    def register(self, tokens: Iterable[str]) -> None:
        pass

    def assert_blind(self, obj: Any, *, where: str) -> None:
        self.checks += 1


LABEL_KEYS = ("in_ground_truth", "ground_truth", "flaw_label", "expected_label", "seeded_flaw")
ALLOWED_LABEL_PROVENANCE = frozenset({"human_reviewer_confirmed", "synthetic_selftest"})


def filter_label_channel(records: Any) -> tuple[Any, int]:
    return records, 0
