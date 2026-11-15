"""B15 (serves A15 Report-Generation, A29 Chain-Trace Renderer): Narrative Generator.

Turns real finding and attack-chain data into deterministic, human-readable prose for
a report. It is the narrative layer, distinct from ZR-034's structured completion
report: this one writes sentences.

Two disciplines keep it trustworthy:
  * NO FABRICATION. Every clause is built from a field that is actually present on the
    finding/chain; a missing field is omitted, never filled with an invented value,
    number, or claim.
  * HONEST VERDICT LANGUAGE. The verdict word comes from the finding's own verdict --
    a RULED_OUT finding is never narrated as "confirmed" or a P0, and a view/UI issue
    is never upgraded. The narrative mirrors the data; it does not editorialise.

Deterministic: same input -> same prose, findings ordered by hypothesis id.
Stdlib only; pure.
"""
from __future__ import annotations

from typing import Any

MODULE_VERSION = "narrative/1.0"

# Neutral phrasing per verdict, taken ONLY from the verdict itself.
_VERDICT_PHRASE = {
    "CONFIRMED_P0": "confirmed (P0)",
    "PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE": "partially validated",
    "RULED_OUT": "ruled out",
    "UNKNOWN": "unknown",
    "BLOCKED": "blocked",
}


def _phrase(verdict: str) -> str:
    return _VERDICT_PHRASE.get(verdict, verdict.lower().replace("_", " "))


def narrate_finding(finding: dict[str, Any]) -> str:
    """One deterministic sentence from a finding's real fields. Missing fields are
    omitted, never invented."""
    hid = finding.get("hypothesis_id", "?")
    title = finding.get("title")
    verdict = finding.get("verdict", "")
    parts = [f"[{hid}]"]
    if title:
        parts.append(str(title) + " —")
    parts.append(_phrase(verdict) if verdict else "(no verdict)")
    conf = finding.get("confidence")
    if conf:
        parts.append(f"({conf} confidence)")
    text = " ".join(parts)
    summary = finding.get("summary")
    if summary:
        text += f": {summary}"
    impact = finding.get("impact")
    if impact and verdict == "CONFIRMED_P0":   # impact is meaningful only for a confirmed P0
        text += f" Impact: {impact}"
    return text


def narrate_chain(chain: dict[str, Any]) -> str:
    """Render a B32 attack chain (steps + establishes) as prose."""
    steps = chain.get("steps", [])
    if not steps:
        return "(empty chain)"
    arrow = " -> ".join(steps)
    establishes = chain.get("establishes", [])
    tail = f" (establishes: {', '.join(establishes)})" if establishes else ""
    return f"Chain reaching {steps[-1]}: {arrow}{tail}"


def report(findings: list[dict[str, Any]], chains: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """A deterministic narrative report. Counts by verdict, per-finding prose
    (ordered by hypothesis id), and optional chain prose."""
    ordered = sorted(findings, key=lambda f: str(f.get("hypothesis_id", "")))
    counts: dict[str, int] = {}
    for f in findings:
        v = f.get("verdict", "")
        counts[v] = counts.get(v, 0) + 1
    chain_lines = [narrate_chain(c) for c in (chains or [])]
    confirmed = [f.get("hypothesis_id") for f in ordered if f.get("verdict") == "CONFIRMED_P0"]
    return {
        "module_version": MODULE_VERSION,
        "headline": (f"{len(confirmed)} confirmed P0 finding(s): {', '.join(confirmed)}" if confirmed
                     else "No confirmed P0 findings"),
        "verdict_counts": dict(sorted(counts.items())),
        "finding_narratives": [narrate_finding(f) for f in ordered],
        "chain_narratives": chain_lines,
        "note": "Deterministic narrative built only from real finding/chain fields; verdict language mirrors the "
                "data (no upgrade), and nothing is fabricated for a missing field.",
    }
