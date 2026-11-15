"""Validates the black-box methodology itself: BlackBoxProber (which only
ever sees HTTP responses, never entitlement_target.py's internals) must
independently reproduce confirmed_p0 for every bug this project already
knows about (white-box, from earlier rounds) when unfixed, and ruled_out
when fixed. A mismatch here would mean either the white-box fix doesn't
actually work externally, or the black-box oracle is unsound -- both
worth knowing immediately, which is why this comparison is a test, not
just a report.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from black_box_prober import BlackBoxProber  # noqa: E402
from entitlement_target import EntitlementTarget, start_entitlement_target  # noqa: E402

FIXED_CONFIG = dict(
    verify_authoritative_status=True,
    dedupe_webhook_events=True,
    verify_amount_matches_tier=True,
    verify_currency_matches_tier=True,
    enforce_tenant_isolation=True,
    require_webhook_signature=True,
)


async def _probe(target_kwargs: dict) -> dict[str, str]:
    target, server, port = await start_entitlement_target(EntitlementTarget(**target_kwargs))
    prober = BlackBoxProber(f"http://127.0.0.1:{port}")
    result = await prober.run_all()
    await prober.aclose()
    server.close()
    await server.wait_closed()
    return {f.finding_id: f.status for f in result["findings"]}


def test_black_box_confirms_all_four_known_bugs_when_unfixed():
    statuses = asyncio.run(_probe({}))
    assert statuses == {"BB-001": "confirmed_p0", "BB-002": "confirmed_p0", "BB-003": "confirmed_p0", "BB-004": "confirmed_p0"}


def test_black_box_rules_out_all_four_once_fixed():
    statuses = asyncio.run(_probe(FIXED_CONFIG))
    assert statuses == {"BB-001": "ruled_out", "BB-002": "ruled_out", "BB-003": "ruled_out", "BB-004": "ruled_out"}


def test_black_box_is_deterministic_across_repeated_probes():
    patterns = set()
    for _ in range(5):
        statuses = asyncio.run(_probe({}))
        patterns.add(tuple(sorted(statuses.items())))
    assert len(patterns) == 1


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
    print("Blackbox-Methodenvalidierung bestanden: unabhaengige Wiederentdeckung UND Fix-Verifikation, rein ueber HTTP.")
