"""Benchmark blindness + target-hint scrubbing (mandate: 'Benchmark blindness', 'forbidden fallback').

Two jobs, both structural:

1. SCRUB: whatever a (benchmark or customer) target volunteers in a response beyond the product behaviour a customer sees --
   debug headers, ``_debug``/``_internal`` body fields, ground-truth echoes, entitlement-record dumps -- is removed BEFORE the
   engine's decision logic or the evidence ledger can see it. The number of dropped hints is kept as a counter so a test can prove
   "hints were present AND ignored", not merely "hints were absent".
2. MONITOR: benchmark ground truth (flaw ids, scenario names, expected verdicts) must never reach the system under assessment.
   A ``BlindnessMonitor`` is told the secret tokens by the benchmark harness and refuses (BenchmarkLeak) any engine input or
   outgoing request that contains one.
Stdlib only.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping

from app.core.control_port.contract import BenchmarkLeak
from app.enterprise_controls.credentials import _BENCHMARK_KEYS, _norm_key

SAFE_RESPONSE_HEADERS = frozenset({"content-type", "content-length", "location", "retry-after", "www-authenticate", "cache-control", "allow", "vary"})
_HINT_HEADER = re.compile(r"^x-.*(debug|internal|benchmark|hint|flaw|entitle|ground|trace|state|ledger|fixture|seed|vuln|truth)", re.I)
INTERNAL_BODY_KEY = re.compile(
    r"^(_.*|debug|internal|ground_?truth|flaw\w*|hints?|benchmark\w*|fixture\w*|entitlement_?record\w*|ledger|server_?state|trace\w*|seeded\w*)$", re.I
)


def scrub_headers(headers: Mapping[str, Any] | None) -> tuple[dict[str, str], list[str]]:
    """(safe headers, names of volunteered hints that were dropped). Unknown non-hint headers are dropped silently (minimisation)."""
    clean: dict[str, str] = {}
    hints: list[str] = []
    for name, value in (headers or {}).items():
        lowered = str(name).lower()
        if lowered in SAFE_RESPONSE_HEADERS:
            clean[lowered] = str(value)
        elif _HINT_HEADER.match(lowered):
            hints.append(lowered)
    return clean, hints


def scrub_body(body: Any, *, _path: str = "$", _dropped: list[str] | None = None) -> tuple[Any, list[str]]:
    dropped = _dropped if _dropped is not None else []
    if isinstance(body, dict):
        out: dict[str, Any] = {}
        for key, value in body.items():
            if INTERNAL_BODY_KEY.match(str(key)):
                dropped.append(f"{_path}.{key}")
                continue
            out[key], _ = scrub_body(value, _path=f"{_path}.{key}", _dropped=dropped)
        return out, dropped
    if isinstance(body, list):
        return [scrub_body(v, _path=f"{_path}[{i}]", _dropped=dropped)[0] for i, v in enumerate(body)], dropped
    return body, dropped


def find_internal_fields(obj: Any, location: str = "$") -> list[str]:
    """Paths of internal/hint-looking keys still present in an (already supposedly scrubbed) structure."""
    found: list[str] = []
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            if INTERNAL_BODY_KEY.match(str(key)) or _BENCHMARK_KEYS.search(_norm_key(str(key))):
                found.append(f"{location}.{key}")
            found.extend(find_internal_fields(value, f"{location}.{key}"))
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            found.extend(find_internal_fields(item, f"{location}[{i}]"))
    return found


class BlindnessMonitor:
    """Refuses benchmark ground truth in anything the system under assessment is given or sends."""

    def __init__(self, secret_tokens: Iterable[str] = ()) -> None:
        self._tokens: set[str] = set()
        self.checks = 0
        self.register(secret_tokens)

    def register(self, tokens: Iterable[str]) -> None:
        for token in tokens:
            if isinstance(token, str) and len(token.strip()) >= 4:
                self._tokens.add(token.strip().lower())

    def assert_blind(self, obj: Any, *, where: str) -> None:
        self.checks += 1
        text = json.dumps(obj, sort_keys=True, default=str).lower() if not isinstance(obj, str) else obj.lower()
        for token in self._tokens:
            if token in text:
                raise BenchmarkLeak("benchmark_ground_truth_leak", f"benchmark ground truth reached {where} (a registered secret token occurs in it)")
        if isinstance(obj, Mapping):
            bad = [p for p in find_internal_fields(obj) if _BENCHMARK_KEYS.search(_norm_key(p.rsplit(".", 1)[-1]))]
            if bad:
                raise BenchmarkLeak("benchmark_metadata_key", f"benchmark metadata key(s) {bad[:3]} reached {where}")


# --- label channel (self-optimisation loops) ---------------------------------------------------------------------------------------
# The cognition layer's self-tuning (improvement loop, hyper-parameter optimiser) can consume per-result ground-truth labels. A label that
# originates from a benchmark's seeded-flaw metadata (or from anything target-side) must never steer the system under assessment, so only two
# provenances are accepted; every other label is STRIPPED before the metrics are computed and counted (fail closed).
LABEL_KEYS = ("in_ground_truth", "ground_truth", "flaw_label", "expected_label", "seeded_flaw")
ALLOWED_LABEL_PROVENANCE = frozenset({"human_reviewer_confirmed", "synthetic_selftest"})


def filter_label_channel(records: Any) -> tuple[Any, int]:
    """(records without unapproved ground-truth labels, number of records whose labels were stripped)."""
    if not isinstance(records, list):
        return records, 0
    out: list[Any] = []
    stripped = 0
    for rec in records:
        if isinstance(rec, dict) and any(k in rec for k in LABEL_KEYS) and rec.get("label_provenance") not in ALLOWED_LABEL_PROVENANCE:
            rec = {k: v for k, v in rec.items() if k not in LABEL_KEYS}
            stripped += 1
        out.append(rec)
    return out, stripped
