"""Axis 4: "a new provider = implementing one interface, nothing else" --
tested against a SECOND, deliberately differently-conventioned reference
target (provider_b_target.py), not a re-run of the first one. See that
module's docstring for exactly what's different (id-in-path vs
id-in-body, cents vs dollars, different verb names) and what's
deliberately unchanged (the state vocabulary and the two planted bugs,
reused via composition).

What "implementing one interface" means here, concretely: an
EndpointMap(overrides=...) for the four routes, plus a two-method
subclass for the two body-shape assumptions this project's own audit
found (build_refund_body, build_create_payment_body) -- zero changes to
state_exploration.py, invariants.py, or any other line of
state_machine_exploration.py.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

from provider_b_target import start_provider_b_target  # noqa: E402

from app.testing.context import RunSettings, TestContext  # noqa: E402
from app.testing.endpoints import EndpointMap, EndpointSpec  # noqa: E402
from app.testing.enums import TestScope  # noqa: E402
from app.testing.http_client import QAHttpClient  # noqa: E402
from app.testing.modules.state_machine_exploration import StateMachineExplorationModule  # noqa: E402

PROVIDER_B_ENDPOINTS = EndpointMap(
    overrides={
        "create_payment": EndpointSpec("POST", "/v2/transactions"),
        "capture_payment": EndpointSpec("POST", "/v2/transactions/{payment_id}/settle"),
        "cancel_payment": EndpointSpec("POST", "/v2/transactions/{payment_id}/void"),
        "create_refund": EndpointSpec("POST", "/v2/transactions/{payment_id}/refund"),
    }
)


class ProviderBExplorationModule(StateMachineExplorationModule):
    """The ENTIRE Provider-B-specific code: two methods, both just
    reshaping a body. Everything else -- scenario generation, HTTP
    dispatch, invariant checking, TestResult construction -- is inherited
    unchanged from StateMachineExplorationModule."""

    def build_refund_body(self, payment_id: str, amount: float) -> dict[str, Any]:
        return {"cents": round(amount * 100)}

    def build_create_payment_body(self, amount: float) -> dict[str, Any]:
        return {"amountCents": round(amount * 100)}


async def run_against_provider_b() -> tuple[list, dict]:
    target, server, port = await start_provider_b_target()
    base_url = f"http://127.0.0.1:{port}"
    http_client = QAHttpClient(base_url=base_url, timeout_seconds=5.0, proxy_url=None, headers={}, user_agent="ProviderB-Verify/1.0")
    results: list = []

    async def collect(result) -> None:
        results.append(result)

    context = TestContext(
        run_id="provider-b-verify", base_url=base_url, entry_url=base_url, scope=TestScope.FULL_REGRESSION,
        settings=RunSettings(), endpoints=PROVIDER_B_ENDPOINTS, http=http_client,
    )
    module = ProviderBExplorationModule(context, collect)
    await module.run()
    scope_report = module.get_last_run_scope_report()

    await http_client.aclose()
    server.close()
    await server.wait_closed()
    return results, scope_report


def test_zero_scenarios_skipped_against_a_completely_different_provider():
    results, scope_report = asyncio.run(run_against_provider_b())
    assert scope_report["skipped_count"] == 0, f"expected nothing skipped once Provider B's routes are configured, got {scope_report}"
    assert len(results) == 14


def test_finds_the_same_two_bug_classes_as_against_provider_a():
    """The whole point: the underlying bug logic is shared (via
    ProviderBTarget wrapping the same ReferenceTarget) -- if this module's
    exploration/execution/evaluation code were secretly coupled to
    Provider A's wire shape, it would either crash against Provider B or
    silently miss these, not find the identical bug classes through
    entirely different request/response shapes."""
    results, _ = asyncio.run(run_against_provider_b())
    failed_names = {r.name for r in results if r.status == "FAIL"}
    assert "Illegal transition rejected: cancelled -> captured" in failed_names
    assert "Illegal transition rejected: partially_refunded -> captured" in failed_names
    assert "Concurrent race: partially_refunded vs refunded from captured" in failed_names


def test_deterministic_against_provider_b_too():
    patterns = set()
    for _ in range(5):
        results, _ = asyncio.run(run_against_provider_b())
        patterns.add(tuple(sorted((r.test_case_id, r.status) for r in results)))
    assert len(patterns) == 1, f"expected one stable pattern across 5 runs against Provider B, got {len(patterns)}"


def _run(fn) -> None:
    try:
        fn()
        print(f"[PASS] {fn.__name__}")
    except AssertionError as exc:
        print(f"[FAIL] {fn.__name__}: {exc}")
        raise


if __name__ == "__main__":
    for _name, _fn in list(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _run(_fn)
    print("Alle Provider-B-Pluggability-Tests bestanden.")
