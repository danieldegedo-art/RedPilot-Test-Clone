"""Shared plumbing for the Real-Glue-Code Recall Gauntlet.

This harness does NOT contain any flaw logic and NOTHING the engine keys on. It only:
  * serves an in-process target over a real 127.0.0.1 TCP socket (reusing the proven
    reference_target request parser + _TrackedServer teardown), and
  * wires the SAME engine construction every benchmark/boss uses
    (ScopeGuard RoE budget -> QAHttpClient -> PureBlackBoxEngine), with the full set of
    TODAY's shipped probes enabled, so the baseline measures the real current engine.

The engine is run BLIND: its only input is the ExecutionBrief (an authorised-recon view)
and the base URL. It is never told the flaw class, which target it faces, or whether the
flaw is on or patched. "Found" == at least one CONFIRMED_P0 finding.

Faithfulness rule enforced by convention (not code): a target's ``handle`` reproduces the
real advisory's missing/incorrect check and request sequence; the brief declares only what
an authorised happy-path trace + public pricing page would reveal. Attack-only fields and
glue-code-only routes are NOT declared -- the engine must discover them.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from reference_target import _TrackedServer, _read_http_request

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine

# "Today's full engine": every shipped probe ON. Federation included (it is a shipped,
# load-bearing capability). This is the strongest current engine -- the honest thing to
# measure a baseline against. Phase-2 upgrades are NOT in this set.
TODAY_ENGINE_PROBES: dict[str, Any] = {
    "enable_channel_probe": True,
    "enable_chain_probe": True,
    "enable_race_probe": True,
    "enable_convergence_probe": True,
    "enable_fabric_probe": True,
    "enable_reconciliation_probe": True,
    "enable_federation": True,
    "race_burst": 12,
}

HandleFn = Callable[[str, str, Any, dict], Awaitable[tuple]]


async def _serve_connection(handle: HandleFn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        method, path, body, headers = await _read_http_request(reader)
        result = await handle(method, path, body, headers)
        if len(result) == 3:
            status_code, response_body, extra_headers = result
        else:
            status_code, response_body = result
            extra_headers = {}
    except Exception as exc:  # a malformed/corrupted request must get a real response, never hang
        status_code, response_body, extra_headers = 400, {"error": "bad_request", "detail": str(exc)}, {}
    payload = json.dumps(response_body).encode("utf-8")
    extra = "".join(f"{k}: {v}\r\n" for k, v in (extra_headers or {}).items())
    head = (
        f"HTTP/1.1 {status_code} X\r\nContent-Type: application/json\r\n"
        f"{extra}Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    ).encode("utf-8")
    try:
        writer.write(head + payload)
        await writer.drain()
    finally:
        writer.close()


async def start(handle: HandleFn) -> tuple[_TrackedServer, int]:
    """Serve ``handle`` on 127.0.0.1 with an OS-assigned free port over a real socket."""
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader, writer):
        task = asyncio.ensure_future(_serve_connection(handle, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return tracked, server.sockets[0].getsockname()[1]


@dataclass
class RunResult:
    confirmed: list[str]
    verdicts: dict[str, str]
    stats: dict[str, Any]
    reached_paths: set[str] = field(default_factory=set)


# Phase-2 engine = today's probes + the new behavior-based discovery probe (opt-in, fail-closed).
PHASE2_ENGINE_PROBES: dict[str, Any] = {**TODAY_ENGINE_PROBES, "enable_behavior_probe": True}

# Grey-box engine = phase-2 + the B60 grey-box sequencing probe (opt-in, fail-closed). This is the
# capability developed for the ENTERPRISE-HARDENED tranche; default-OFF so legacy runs are identical.
GREYBOX_ENGINE_PROBES: dict[str, Any] = {**PHASE2_ENGINE_PROBES, "enable_greybox_probe": True}


async def run_engine_blind(brief_factory: Callable[[str], dict[str, Any]], handle: HandleFn, *,
                           path_log: set[str] | None = None, probes: dict[str, Any] | None = None) -> RunResult:
    """Start the target, run the engine blind, return the confirmed-P0 set.

    ``probes`` selects the engine capability set (default TODAY_ENGINE_PROBES; pass
    PHASE2_ENGINE_PROBES to include the behavior probe). The engine sees only the brief
    (built by ``brief_factory(base_url)`` once the port is known) + the base URL. ``path_log``
    (optional) is a set the target appends every served path to, for real-socket coverage.
    """
    server, port = await start(handle)
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(brief_factory(base), env={})
        guard = ScopeGuard(
            ScopePolicy.for_environment(
                base,
                max_requests=brief.limits.max_requests,
                max_requests_per_second=brief.limits.max_requests_per_second,
            )
        )
        http = QAHttpClient(
            base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
            max_retries=0, guard=guard, stateless=True,
        )
        engine = PureBlackBoxEngine(http, brief, base_url=base, **(probes if probes is not None else TODAY_ENGINE_PROBES))
        result = await engine.run(None)
        confirmed = sorted({f.hypothesis_id for f in result.findings if f.verdict.value == "CONFIRMED_P0"})
        verdicts = {f.hypothesis_id: f.verdict.value for f in result.findings}
        return RunResult(confirmed=confirmed, verdicts=verdicts, stats=result.stats, reached_paths=set(path_log or ()))
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
