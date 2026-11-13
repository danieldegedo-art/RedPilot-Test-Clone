"""ZR-011: tests for app/testing/integrity/repetition.py (repetition avoidance). Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.repetition import (  # noqa: E402
    RepetitionRegister, profile_from, repetition_adjustment,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402

RO = Verdict.RULED_OUT
P0 = Verdict.CONFIRMED_P0
PARTIAL = Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE
UNK = Verdict.UNKNOWN


def _adj(hid, seq):
    return repetition_adjustment(profile_from(hid, seq))[0]


def test_consecutive_clean_count_is_trailing_only_and_resets_on_a_non_clean_run():
    p = profile_from("PBB-U", [RO, P0, RO, RO])
    assert p.consecutive_ruled_out == 2 and p.stably_clean is True  # the middle CONFIRMED reset the streak


def test_a_single_clean_run_is_not_yet_stably_clean_no_demotion():
    assert _adj("PBB-U", [RO]) == 0.0


def test_repeated_clean_runs_demote_progressively():
    two, three = _adj("PBB-U", [RO, RO]), _adj("PBB-U", [RO, RO, RO])
    assert two == -5.0 and three == -10.0 and three < two < 0.0


def test_demotion_is_capped_so_a_class_is_never_dropped():
    assert _adj("PBB-U", [RO] * 10) == -20.0  # capped at REPEAT_CAP, never deep enough to skip


def test_an_open_lead_is_boosted():
    assert _adj("PBB-H", [UNK]) == 15.0
    assert _adj("PBB-H", [PARTIAL]) == 15.0


def test_a_flapping_but_not_stably_clean_class_is_boosted():
    assert _adj("PBB-F", [RO, P0, RO]) == 10.0  # trailing clean = 1 (not stable), window flaps -> attention


def test_a_stably_clean_streak_does_not_also_get_the_flap_boost():
    # [RO, CONFIRMED, RO, RO]: window flaps, but the trailing streak is stably clean -> demote only, no flap boost
    assert _adj("PBB-U", [RO, P0, RO, RO]) == -5.0


def test_register_reports_deprioritized_classes_with_reasons_and_never_says_skip():
    reg = RepetitionRegister.from_history({"PBB-U": [RO, RO, RO], "PBB-H": [UNK], "PBB-C": [RO]})
    adj = reg.adjustments()
    assert adj["PBB-U"] == -10.0 and adj["PBB-H"] == 15.0 and adj["PBB-C"] == 0.0
    dep = reg.deprioritized()
    assert [d["hypothesis_id"] for d in dep] == ["PBB-U"] and all(d["adjustment"] < 0 for d in dep)
    report = reg.report()
    assert json.loads(json.dumps(report)) == report
    assert "NEVER skipped" in report["note"]


def test_profiles_are_class_level_only():
    p = profile_from("PBB-G", [RO, RO])
    assert set(p.to_dict()) == {"hypothesis_id", "runs_seen", "consecutive_ruled_out", "last_verdict", "flapping", "stably_clean", "open_lead"}
