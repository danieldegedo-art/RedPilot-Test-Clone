"""payment_integrity module: contract gating, guard integration, and the safety properties that matter most:
no contract => ZERO requests; an interrupted/blocked run reads as 'not tested', never as clean; secrets never leak."""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "verification_infrastructure"))

from app.testing.context import RunSettings  # noqa: E402
from app.testing.endpoints import EndpointMap  # noqa: E402
from app.testing.enums import ResultStatus, TestScope  # noqa: E402
from app.testing.event_bus import EventBus  # noqa: E402
from app.testing.integrity.contract import ContractError, IntegrityContract  # noqa: E402
from app.testing.integrity.gaps import capability_gaps, unknown_exposures  # noqa: E402
from app.testing.runner import TestRunner  # noqa: E402
from app.testing.scope_guard import ScopePolicy  # noqa: E402
from entitlement_target import EntitlementTarget, start_entitlement_target  # noqa: E402

SECRET = "whsec_test_only_do_not_use_in_prod"


def _contract(**over) -> dict:
    base = {
        "vocabulary": "reference", "vocabulary_confirmed": True, "environment": "sandbox", "authorized_by": "qa-lead@example.test",
        "scope_reference": "TICKET-1234", "attested_synthetic_data": True, "allowed_hosts": ["127.0.0.1"],
        "webhook_secret": SECRET, "webhook_secret_is_sandbox": True,
    }
    base.update(over)
    return base


class CountingServer:
    """Answers every request with 200 {} and counts connections: proves 'zero requests' claims."""

    def __init__(self) -> None:
        self.count = 0
        self.port = 0

    async def __aenter__(self) -> "CountingServer":
        self._srv = await asyncio.start_server(self._on, "127.0.0.1", 0)
        self.port = self._srv.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self._srv.close()
        await self._srv.wait_closed()

    async def _on(self, reader, writer) -> None:
        self.count += 1
        try:
            await reader.readline()
            while (h := await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            await writer.drain()
        finally:
            writer.close()


async def _run(base_url: str, contract: dict | None, *, policy: ScopePolicy | None = None, kill: str | None = None):
    runner = TestRunner(
        run_id="pi-test", base_url=base_url, scope=TestScope.COMPREHENSIVE,
        settings=RunSettings(enabled_modules={"payment_integrity"}, integrity_contract=contract),
        endpoints=EndpointMap(), event_bus=EventBus(),
        scope_policy=policy or ScopePolicy.for_environment(base_url, max_requests_per_second=5000.0),
    )
    if kill:
        runner.guard.kill(kill)
    collector = await runner.execute()
    return {r.test_case_id: r for r in collector.results}, runner


def _params(result) -> dict:
    return result.input_parameters


# ------------------------------------------------------------------- contract unit tests
def test_contract_accepts_a_complete_sandbox_contract_and_keeps_the_secret_out_of_public_views() -> None:
    c = IntegrityContract.from_dict(_contract())
    assert c.permits_host("http://127.0.0.1:8080") and not c.permits_host("https://api.stripe.com")
    public = json.dumps(c.to_public_dict())
    assert SECRET not in public and '"webhook_secret_declared": true' in public
    assert c.fingerprint() == IntegrityContract.from_dict(_contract(webhook_secret="whsec_a_completely_different_one")).fingerprint(), "the secret must not influence the identity key"
    assert c.fingerprint() != IntegrityContract.from_dict(_contract(scope_reference="TICKET-9")).fingerprint()


def test_contract_rejects_every_unsafe_variant_and_reports_all_problems_at_once() -> None:
    for bad, needle in (
        (_contract(environment="production"), "production"),
        (_contract(attested_synthetic_data=False), "attested_synthetic_data"),
        (_contract(vocabulary_confirmed=False), "vocabulary_confirmed"),
        (_contract(vocabulary="acme-v2"), "vocabulary must be one of"),
        (_contract(authorized_by="  "), "authorized_by"),
        (_contract(allowed_hosts=[]), "allowed_hosts"),
        (_contract(allowed_hosts=["http://x.com/path"]), "allowed_hosts invalid"),
        (_contract(webhook_secret_is_sandbox=False), "webhook_secret_is_sandbox"),
        (_contract(note="key sk_live_ABCDEFGH12345678"), "live-mode API credential"),
        (_contract(expected_gated="yes"), "expected_gated"),
    ):
        try:
            IntegrityContract.from_dict(bad)
        except ContractError as exc:
            assert needle in "; ".join(exc.errors), (needle, exc.errors)
            assert "sk_live_ABCDEFGH12345678" not in str(exc), "a live credential must never be echoed back"
        else:
            raise AssertionError(f"contract accepted although it should fail on {needle!r}")
    try:
        IntegrityContract.from_dict({"environment": "production", "attested_synthetic_data": False})
    except ContractError as exc:
        assert len(exc.errors) >= 4, exc.errors
    for not_a_dict in (None, [], "x", 3):
        try:
            IntegrityContract.from_dict(not_a_dict)
            raise AssertionError("non-object accepted")
        except ContractError:
            pass


def test_gap_register_uses_the_mandated_statement_and_never_reports_blocked_as_safe() -> None:
    none = capability_gaps(has_contract=False, has_secret=False)
    assert all(r.status != "COVERED" for r in none[:7]), "without a contract NOTHING is covered"
    blocked = next(r for r in none if "ORC-B" in r.p0_class)
    text = blocked.statement()
    assert text.startswith("This P0 class (") and " remains BLOCKED because " in text and "smallest safe improvement" in text and "Its success metric is" in text
    assert blocked.barrier_type == "ASSESSMENT_LIMIT"
    no_secret = next(r for r in capability_gaps(has_contract=True, has_secret=False) if "behind the webhook signature perimeter" in r.p0_class)
    assert no_secret.status == "BLOCKED" and no_secret.barrier_type == "TARGET_LIMIT" and "SANDBOX webhook signing secret" in no_secret.improvement
    with_secret = next(r for r in capability_gaps(has_contract=True, has_secret=True) if "behind the webhook signature perimeter" in r.p0_class)
    assert with_secret.status == "COVERED"
    still_open = {r.p0_class.split(" (")[0] for r in unknown_exposures(capability_gaps(has_contract=True, has_secret=True))}
    assert any("return/redirect" in c for c in still_open) and any("cross-client" in c for c in still_open), "uncovered classes must stay visible even with a perfect contract"


# ------------------------------------------------------------------- module through the real runner
def test_no_contract_sends_zero_requests_and_lists_the_untested_classes() -> None:
    async def scenario() -> None:
        async with CountingServer() as srv:
            results, runner = await _run(f"http://127.0.0.1:{srv.port}", None)
            gap = results["PI-CAPABILITY-GAP"]
            assert gap.status == ResultStatus.WARNING and "NOT covered" in gap.actual
            assert any("remains BLOCKED because" in row["statement"] for row in _params(gap)["capability_gaps"])
            assert srv.count == 0 and runner.guard_stats["requests_used"] == 0, "no contract must mean NO traffic at all"
            assert not any(k.startswith("PI-ORC") for k in results)

    asyncio.run(scenario())


def test_invalid_contract_sends_zero_requests_and_never_echoes_a_live_key() -> None:
    async def scenario() -> None:
        async with CountingServer() as srv:
            bad = {"vocabulary": "reference", "environment": "production", "authorized_by": "", "attested_synthetic_data": False, "allowed_hosts": ["127.0.0.1"], "note": "sk_live_ABCDEFGH12345678"}
            results, _ = await _run(f"http://127.0.0.1:{srv.port}", bad)
            invalid = results["PI-CONTRACT-INVALID"]
            assert invalid.status == ResultStatus.ERROR
            joined = " ".join(_params(invalid)["errors"])
            assert "production" in joined and "attested_synthetic_data" in joined and "live-mode" in joined
            assert "sk_live_ABCDEFGH12345678" not in json.dumps({k: (v.actual, v.input_parameters) for k, v in results.items()})
            assert srv.count == 0

    asyncio.run(scenario())


def test_contract_for_a_different_host_blocks_before_any_request() -> None:
    async def scenario() -> None:
        async with CountingServer() as srv:
            results, _ = await _run(f"http://127.0.0.1:{srv.port}", _contract(allowed_hosts=["only-this-host.example.test"]))
            assert results["PI-CONTRACT-HOST"].status == ResultStatus.ERROR and srv.count == 0

    asyncio.run(scenario())


def test_full_run_through_the_guarded_client_finds_the_seeded_p0s_and_leaks_no_secret() -> None:
    async def scenario() -> None:
        target = EntitlementTarget()  # wide open: every seeded bug present
        _, server, port = await start_entitlement_target(target)
        try:
            results, runner = await _run(f"http://127.0.0.1:{port}", _contract())
        finally:
            server.close()
            await server.wait_closed()
        status = {oid: results[f"PI-ORC-{oid}"].status for oid in ("A", "B", "C", "D", "E", "F", "G", "H", "I")}
        for oid in "ABCDFGH":
            assert status[oid] == ResultStatus.FAIL, (oid, results[f"PI-ORC-{oid}"].actual)
        assert status["E"] == status["I"] == ResultStatus.WARNING, "E and I must stay UNKNOWN on a target where D is still open -- never PASS"
        assert results["PI-ORC-BASELINE"].status == ResultStatus.PASS
        summary = results["PI-SUMMARY"]
        assert summary.status == ResultStatus.FAIL and "'No confirmed P0' never means 'no P0 exists'" in summary.actual
        assert runner.guard_stats["requests_used"] > 30 and runner.guard_stats["denied_by_code"] == {}, "every oracle request went through the run's shared guard"
        blob = json.dumps({k: (v.actual, v.input_parameters, v.recommendation) for k, v in results.items()}, default=str)
        assert SECRET not in blob, "the sandbox signing secret must never appear in any result"
        first = _params(results["PI-ORC-B"])["_integrity"]
        assert first["evidence"] and all(len(e["sha256"]) == 16 and e["timestamp"] for e in first["evidence"])

    asyncio.run(scenario())


def test_budget_exhaustion_and_kill_switch_read_as_blocked_never_as_clean() -> None:
    async def scenario() -> None:
        target = EntitlementTarget(**{k: True for k in ("require_webhook_signature", "dedupe_webhook_events", "verify_authoritative_status", "revoke_entitlement_on_refund", "invalidate_cache_on_revoke", "verify_amount_matches_tier", "enforce_tenant_isolation", "verify_currency_matches_tier", "check_access_verifies_authoritative")})
        _, server, port = await start_entitlement_target(target)
        try:
            base = f"http://127.0.0.1:{port}"
            results, runner = await _run(base, _contract(), policy=ScopePolicy.for_environment(base, max_requests=14, max_requests_per_second=5000.0))
            oracle = [r for k, r in results.items() if k.startswith("PI-ORC")]
            blocked = [r for r in oracle if _params(r)["_integrity"]["blocked_reason"]]
            assert blocked, "a 14-request budget cannot cover ten oracles: some must be BLOCKED"
            assert all(r.status == ResultStatus.WARNING for r in blocked), "BLOCKED must never be PASS"
            reasons = " ".join(_params(r)["_integrity"]["blocked_reason"] for r in blocked)
            assert "budget_exhausted" in reasons or "scope_violation" in reasons, reasons
            assert results["PI-SUMMARY"].status != ResultStatus.PASS
            assert runner.guard_stats["requests_used"] <= 14

            results2, _ = await _run(base, _contract(), kill="operator stop")
            oracle2 = [r for k, r in results2.items() if k.startswith("PI-ORC")]
            assert oracle2 and all(_params(r)["_integrity"]["blocked_reason"] and "killed" in _params(r)["_integrity"]["blocked_reason"] for r in oracle2)
            assert all(r.status == ResultStatus.WARNING for r in oracle2)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


if __name__ == "__main__":
    import inspect
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and inspect.isfunction(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{'ALL PASSED' if not failures else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
