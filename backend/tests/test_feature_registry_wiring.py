"""ZR-002 wiring: tests for build_feature_registry's fail-safe fallback.

The durable SQLAlchemy branch can't execute without sqlalchemy; what IS executable
(and what these tests cover) is that the factory falls back to the in-memory store
and returns a functional PESMStore either way. Stdlib only.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.modules.payment_integrity import build_feature_registry  # noqa: E402
from app.testing.pesm import Feature, InMemoryPESMStore  # noqa: E402


async def test_falls_back_to_in_memory_when_sqlalchemy_is_absent():
    store = await build_feature_registry()           # prefer_durable=True, but no sqlalchemy here
    assert isinstance(store, InMemoryPESMStore)


async def test_prefer_durable_false_uses_in_memory_directly():
    store = await build_feature_registry(prefer_durable=False)
    assert isinstance(store, InMemoryPESMStore)


async def test_returned_store_is_a_functional_pesm_store():
    store = await build_feature_registry()
    feat = Feature(feature_id="premium_export", name="Premium export", discovered_via="recon",
                   registered_at=datetime.now(timezone.utc))
    await store.register_feature(feat)
    assert await store.is_registered("premium_export") is True
    assert "premium_export" in await store.registered_feature_ids()
