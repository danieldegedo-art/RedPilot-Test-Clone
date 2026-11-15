"""B11: tests for app/testing/integrity/dedup.py (local duplicate/novelty fingerprinting). Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.dedup import (  # noqa: E402
    SCOPE_NOTE, NoveltyRegister, fingerprint,
)


class _F:
    def __init__(self, hid, p0_class, affected_flow):
        self.hypothesis_id = hid
        self.p0_class = p0_class
        self.affected_flow = affected_flow


class _Result:
    def __init__(self, findings):
        self.findings = findings


def test_fingerprint_is_deterministic_and_discriminates():
    a = fingerprint("unconfirmed_payment_grants_access", "checkout", "fpA")
    assert a.digest == fingerprint("unconfirmed_payment_grants_access", "checkout", "fpA").digest
    assert a.digest != fingerprint("cross_tenant_binding", "checkout", "fpA").digest   # different class
    assert a.digest != fingerprint("unconfirmed_payment_grants_access", "refund", "fpA").digest  # different flow
    assert a.digest != fingerprint("unconfirmed_payment_grants_access", "checkout", "fpB").digest  # different target


def test_an_unseen_finding_is_novel():
    reg = NoveltyRegister()
    nov = reg.assess(fingerprint("unconfirmed_payment_grants_access", "checkout", "fpA"))
    assert nov.is_novel and nov.times_seen == 0 and nov.novelty_score == 1.0


def test_novelty_diminishes_as_own_history_repeats():
    reg = NoveltyRegister()
    fp = fingerprint("unconfirmed_payment_grants_access", "checkout", "fpA")
    reg.register(fp)
    first = reg.assess(fp)
    assert first.is_novel is False and first.times_seen == 1 and first.novelty_score == 0.5
    reg.register(fp)
    assert reg.assess(fp).times_seen == 2 and reg.assess(fp).novelty_score == 1 / 3


def test_the_same_class_on_a_different_target_is_still_novel():
    reg = NoveltyRegister()
    reg.register(fingerprint("cross_tenant_binding", "entitlement", "fpA"))
    assert reg.assess(fingerprint("cross_tenant_binding", "entitlement", "fpB")).is_novel  # different target


def test_dedup_run_splits_then_registers():
    reg = NoveltyRegister()
    r = _Result([_F("PBB-U", "unconfirmed_payment_grants_access", "checkout"),
                 _F("PBB-G", "cross_tenant_binding", "entitlement")])
    first = reg.dedup_run(r, "fpA")
    assert set(first["novel"]) == {"PBB-U", "PBB-G"} and first["duplicate_of_own_history"] == []
    second = reg.dedup_run(r, "fpA")  # same findings, same target, second run
    assert second["novel"] == [] and set(second["duplicate_of_own_history"]) == {"PBB-U", "PBB-G"}


def test_outputs_carry_the_honest_scope_note_and_are_json_safe():
    reg = NoveltyRegister()
    out = reg.dedup_run(_Result([_F("PBB-U", "unconfirmed_payment_grants_access", "checkout")]), "fpA")
    assert out["scope_note"] == SCOPE_NOTE and "private" in SCOPE_NOTE and "no platform can know" in SCOPE_NOTE
    assert json.loads(json.dumps(out)) == out
