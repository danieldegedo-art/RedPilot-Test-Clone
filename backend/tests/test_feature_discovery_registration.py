"""ZR-002: the concrete link between surface discovery (Section 3.2) and
ZR-025 condition 1. Proves the full chain for real, not just each piece in
isolation:

    DiscoveredCall (what ReconModule's crawler would observe)
      -> map_to_endpoint_overrides        (existing, pre-dates this session)
      -> register_discovered_features     (new, this session)
      -> PESMStore now has the Feature
      -> ConfirmationGate.evaluate() with that store's registered_feature_ids
         actually allows confirmation for it -- and still blocks anything
         that was never discovered.

Stdlib only.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import ConfirmationCandidate, KIND_FEATURE_USE, OracleObservation  # noqa: E402
from app.enterprise_controls.oracle_gate import ConfirmationGate  # noqa: E402
from app.testing.endpoints import EndpointSpec  # noqa: E402
from app.testing.pesm import InMemoryPESMStore  # noqa: E402
from app.testing.recon.browser_crawler import DiscoveredCall  # noqa: E402
from app.testing.recon.mapper import map_to_endpoint_overrides, register_discovered_features  # noqa: E402


class _FakeLedger:
    def __init__(self, admitted):
        self._admitted = set(admitted)

    def is_admitted(self, artifact_id):
        return artifact_id in self._admitted


def _well_evidenced_candidate(feature_id: str) -> ConfirmationCandidate:
    return ConfirmationCandidate(
        hypothesis_id="h-e2e",
        control_denied=OracleObservation("o1", feature_id, "clean-id", None, "denied", KIND_FEATURE_USE, True, "s1", ("a1",), discriminating=True),
        scenario_allowed=OracleObservation("o2", feature_id, "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s2", ("a1",)),
        clean_reproduction=OracleObservation("o3", feature_id, "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s3", ("a1",)),
        qualifying_payment_present=False,
    )


async def _run_discovery_and_registration() -> InMemoryPESMStore:
    calls = [
        DiscoveredCall(method="POST", path="/api/checkout", source="network"),
        DiscoveredCall(method="POST", path="/api/subscriptions/abc123/cancel", source="network"),
        DiscoveredCall(method="GET", path="/api/account/profile", source="static-js"),  # won't match any rule
    ]
    mapped = map_to_endpoint_overrides(calls)
    store = InMemoryPESMStore()
    await register_discovered_features(mapped, store, discovered_at=datetime.now(timezone.utc))
    return store


def test_discovered_checkout_and_cancel_calls_get_registered():
    import asyncio
    store = asyncio.run(_run_discovery_and_registration())
    ids = asyncio.run(store.registered_feature_ids())
    assert ids == frozenset({"create_checkout_session", "cancel_subscription"})


def test_unmatched_call_does_not_get_registered_as_anything():
    import asyncio
    store = asyncio.run(_run_discovery_and_registration())
    ids = asyncio.run(store.registered_feature_ids())
    # the /api/account/profile call matched no rule in map_to_endpoint_overrides,
    # so it must not silently become a "feature" either
    assert "account_profile" not in ids
    assert len(ids) == 2


def test_full_chain_end_to_end_discovered_feature_can_now_be_confirmed():
    """The actual point of today's work: a feature that was never discovered
    cannot be confirmed; the same feature, once discovered, can be."""
    import asyncio
    store = asyncio.run(_run_discovery_and_registration())
    registered_ids = asyncio.run(store.registered_feature_ids())
    gate = ConfirmationGate(ledger=_FakeLedger(admitted=["a1"]), registered_feature_ids=registered_ids)

    confirmed_decision = gate.evaluate(_well_evidenced_candidate("create_checkout_session"))
    assert confirmed_decision.confirmed is True
    assert confirmed_decision.token is not None

    blocked_decision = gate.evaluate(_well_evidenced_candidate("delete_entire_database"))
    assert blocked_decision.confirmed is False
    assert any(r.startswith("feature_not_registered") for r in blocked_decision.reasons)


def test_re_running_discovery_against_the_same_target_does_not_duplicate():
    import asyncio

    async def go():
        store = InMemoryPESMStore()
        calls = [DiscoveredCall(method="POST", path="/api/checkout", source="network")]
        mapped = map_to_endpoint_overrides(calls)
        await register_discovered_features(mapped, store, discovered_at=datetime.now(timezone.utc))
        await register_discovered_features(mapped, store, discovered_at=datetime.now(timezone.utc))  # second "run"
        return await store.registered_feature_ids()

    ids = asyncio.run(go())
    assert ids == frozenset({"create_checkout_session"})


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
