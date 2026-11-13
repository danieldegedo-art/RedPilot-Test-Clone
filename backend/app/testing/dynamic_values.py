"""Resolves realistic test-payload values from Recon's discoveries, so the
static per-module defaults (prod_standard_plan, 49.99, ...) only apply
when Recon found nothing better for that specific field this run.

This is intentionally SHALLOW and NAME-based, not schema-aware: it walks a
module's payload dict recursively and, at every nesting level, replaces a
value whose KEY matches something Recon observed elsewhere this run (any
nesting depth, exact name match) with that observed value. It never ADDS a
field a module didn't already plan to send, and never changes a payload's
shape -- only which values populate the fields already there.

Why this is the right amount of "automatic": the alternative --
reconstructing a different payload shape from scratch based on guessed
field names -- would routinely send a malformed request to whatever the
target's real endpoint expects and turn every module's result into noise.
Value substitution by name is the boundary that's reliably correct: if the
target expects "productId", this uses *its own* observed productId value
instead of "prod_standard_plan"; if it expects a field name this run never
observed anywhere (e.g. "sku" instead of "productId"), no automatic
mechanism can safely infer that without a schema, and the existing manual
EndpointMap override (README -> "Configuring your API contract") is still
the right tool for that case.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.testing.recon.browser_crawler import DiscoveredCall


@dataclass
class DiscoveredValues:
    by_field_name: dict[str, Any] = field(default_factory=dict)
    # field_name -> (method, path) it was observed on, kept only for the
    # audit-trail summary Recon reports (RECON-005), not used to resolve.
    source_by_field_name: dict[str, tuple[str, str]] = field(default_factory=dict)

    def resolve(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Returns a NEW structure with every matching key's value replaced.
        Never mutates `payload`."""
        return self._resolve_value(payload)

    def _resolve_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (self.by_field_name[key] if key in self.by_field_name else self._resolve_value(val))
                for key, val in value.items()
            }
        if isinstance(value, list):
            return [self._resolve_value(item) for item in value]
        return value


def build_discovered_values(calls: list[DiscoveredCall]) -> DiscoveredValues:
    """Flattens every network-observed call's param_values into one
    field-name-keyed pool. Network observations are processed before
    static-JS ones (which never carry values anyway -- static JS analysis
    has no runtime value to read, see js_endpoint_parser.py); first-seen,
    non-empty value wins per field name."""
    discovered = DiscoveredValues()
    ordered_calls = sorted(calls, key=lambda c: 0 if c.source == "network" else 1)
    for call in ordered_calls:
        for field_name, value in call.param_values.items():
            if field_name not in discovered.by_field_name:
                discovered.by_field_name[field_name] = value
                discovered.source_by_field_name[field_name] = (call.method, call.path)
    return discovered
