"""Active probing for undocumented system-administration paths.

Everything else in Recon (browser_crawler.py, js_endpoint_parser.py) is
strictly passive -- it only observes traffic/JS the target already serves to
any ordinary visitor. Administrative surfaces are, by nature, rarely linked
from the frontend a normal user sees, so passive observation alone
systematically under-reports them -- which is exactly the gap AICPA SOC2
CC6.1's "Completeness of Service Coverage" requirement (and OWASP
WSTG-INFO-07, "Map Application Architecture") calls out: a review that only
covers the routes a UI happens to link to isn't complete.

This module trades a small amount of that passivity for coverage, with the
trade-off kept deliberately narrow:

  - Only the fixed candidate patterns below (plus, if the target's already-
    discovered routes share a version-style prefix like "/api/v1", that
    prefix applied to each pattern too) -- no wordlist, no fuzzing, no
    parameter brute-forcing, no recursion.
  - Only GET requests -- this step is existence/access-control discovery,
    not action. (RoleBasedAccessModule separately verifies write-method
    access control on whatever this discovers.)
  - Exactly one request per candidate path, using the already-configured
    session (Settings -> Session Cookies) -- the same authenticated view
    every other module already tests with. Nothing here reaches for
    anything that session couldn't otherwise reach on its own.
  - A single baseline request to a random, guaranteed-nonexistent path is
    sent first and used to filter out catch-all SPA fallbacks (a frontend
    that serves its index.html with HTTP 200 for literally any unmatched
    path) so those don't get misread as "every admin path exists".
"""
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass

from app.testing.http_client import QAHttpClient
from app.testing.models import RequestEvidence, ResponseEvidence
from app.core.control_port import NEGATIVE_ACCESS_CONTROL, get_control_adapter

# Exactly the SOC2/OWASP-referenced pattern set from the CC6.1 extension
# spec. Written without a version segment (no "/v1") since not every target
# uses one -- _derive_prefixes() below adds version-prefixed variants when
# the target's own discovered routes suggest one is in use.
SYSTEM_PROBE_PATTERNS: tuple[str, ...] = (
    "/api/admin",
    "/api/role",
    "/api/permissions",
    "/api/system",
    "/api/config",
    "/api/user/manage",
    "/api/account/role",
)

_BASELINE_LENGTH_TOLERANCE = 32  # bytes; see _matches_baseline


@dataclass
class ProbeHit:
    method: str
    path: str
    status_code: int | None
    confidence: str  # "high" | "medium" | "low"
    request: RequestEvidence
    response: ResponseEvidence


def _derive_prefixes(discovered_paths: list[str]) -> list[str]:
    """If the target's already-discovered routes commonly start with a
    version-style segment (e.g. every one of them begins with "/api/v1"),
    also try that prefix on the standard patterns -- e.g. "/api/v1/admin"
    in addition to "/api/admin"."""
    prefixes: set[str] = set()
    for path in discovered_paths:
        segments = [segment for segment in path.split("/") if segment]
        if len(segments) < 2 or segments[0].lower() != "api":
            continue
        candidate = segments[1]
        if len(candidate) >= 2 and candidate[0].lower() == "v" and candidate[1:].isdigit():
            prefixes.add(f"/api/{candidate}")
    return sorted(prefixes)


def _candidate_paths(discovered_paths: list[str]) -> list[str]:
    candidates = list(SYSTEM_PROBE_PATTERNS)
    for prefix in _derive_prefixes(discovered_paths):
        for pattern in SYSTEM_PROBE_PATTERNS:
            suffix = pattern[len("/api") :]  # e.g. "/admin" from "/api/admin"
            candidates.append(f"{prefix}{suffix}")

    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _body_length(body: object) -> int:
    return get_control_adapter().body_size(body)  # understands the withheld stand-in used for negative_access_control probes


def _matches_baseline(resp: ResponseEvidence, baseline: ResponseEvidence) -> bool:
    """True if `resp` looks like the same generic "not found"/SPA-fallback
    response as the baseline -- same status code and near-identical body
    length. A real, distinct route is expected to differ in at least one of
    those, even if both happen to return the same status code family."""
    if baseline.error is not None:
        return False  # baseline call itself failed at the transport level; can't compare, so don't suppress anything on its account
    if resp.status_code != baseline.status_code:
        return False
    return abs(_body_length(resp.body) - _body_length(baseline.body)) <= _BASELINE_LENGTH_TOLERANCE


def _confidence_of(status_code: int | None) -> str:
    if status_code in (401, 403):
        return "high"  # an access-control layer specifically recognized and gated this exact path
    if status_code in (200, 405, 500, 502, 503):
        return "medium"
    return "low"


async def probe_system_paths(http: QAHttpClient, discovered_paths: list[str], concurrency: int = 6) -> list[ProbeHit]:
    """Sends the baseline request, then GETs every candidate system path
    once, returning only the ones that don't match the baseline signature.

    The candidate GETs run concurrently (bounded by `concurrency`) instead
    of one at a time: each targets a different, fixed, read-only path with
    no dependency on any other candidate's result (see this module's
    docstring -- "existence/access-control discovery, not action"), so
    there is nothing for concurrent execution to race against. The baseline
    request stays a lone `await` first, since every candidate's result is
    compared against it."""
    baseline_path = f"/__qa_recon_baseline_{secrets.token_hex(8)}__"
    _, baseline_resp = await http.request("GET", baseline_path, probe_class=NEGATIVE_ACCESS_CONTROL)

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _probe_one(path: str) -> ProbeHit | None:
        async with sem:
            request_evidence, response_evidence = await http.request("GET", path, probe_class=NEGATIVE_ACCESS_CONTROL)
        if response_evidence.error is not None:
            return None  # unreachable/timeout on this one candidate -- not a discovery, not worth failing the whole probe over
        if _matches_baseline(response_evidence, baseline_resp):
            return None
        return ProbeHit(
            method="GET",
            path=path,
            status_code=response_evidence.status_code,
            confidence=_confidence_of(response_evidence.status_code),
            request=request_evidence,
            response=response_evidence,
        )

    results = await asyncio.gather(*(_probe_one(path) for path in _candidate_paths(discovered_paths)))
    return [hit for hit in results if hit is not None]
