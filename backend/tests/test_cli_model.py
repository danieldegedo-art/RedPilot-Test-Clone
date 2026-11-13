"""RP-001: tests for app/cli/model.py. Stdlib only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.cli.model import (  # noqa: E402
    AppModel, Command, CommandPalette, LogBuffer, compute_layout, fuzzy_rank,
)

CMDS = [Command("run", "start a run"), Command("plan", "show OPPLAN"),
        Command("agents", "roster"), Command("findings", "results")]


def test_log_buffer_caps_and_tails_newest():
    b = LogBuffer(capacity=3)
    for i in range(5):
        b.append("info", f"line{i}")
    assert len(b) == 3
    assert [e.text for e in b.tail(2)] == ["line3", "line4"]


def test_log_splits_multiline():
    b = LogBuffer()
    b.append("info", "a\nb\nc")
    assert [e.text for e in b.tail(3)] == ["a", "b", "c"]


def test_fuzzy_rank_subsequence_and_prefix():
    assert fuzzy_rank("pl", "plan") is not None
    assert fuzzy_rank("pn", "plan") is not None          # subsequence, not contiguous
    assert fuzzy_rank("xyz", "plan") is None
    assert fuzzy_rank("", "plan")[0] == 0                # empty matches
    # a prefix match ranks before a non-prefix match
    assert fuzzy_rank("pl", "plan") < fuzzy_rank("pl", "replant")


def test_command_palette_filter_and_select():
    p = CommandPalette(CMDS)
    p.type("a");
    names = [c.name for c in p.matches()]
    assert "agents" in names and "plan" in names and "run" not in names
    p.query = ""; p.type("r"); p.type("u"); p.type("n")
    assert p.selected().name == "run"


def test_palette_move_is_clamped():
    p = CommandPalette(CMDS)
    p.move(-5)
    assert p.index == 0
    p.move(100)
    assert p.index == len(p.matches()) - 1


def test_compute_layout_80x24():
    lay = compute_layout(80, 24)
    assert lay["title"].y == 0 and lay["title"].h == 1
    assert lay["status"].y == 23 and lay["status"].h == 1
    assert lay["sidebar"].w + lay["main"].w == 80
    assert lay["main"].h == 22


def test_compute_layout_tiny_terminal_degrades_without_negatives():
    lay = compute_layout(10, 3)
    for r in lay.values():
        assert r.w >= 0 and r.h >= 0
    assert lay["sidebar"].w == 0            # no room for a sidebar


def test_app_model_palette_flow():
    m = AppModel(palette=CommandPalette(CMDS))
    m.open_palette()
    assert m.palette_open
    for ch in "plan":
        m.palette.type(ch)
    cmd = m.accept_palette()
    assert cmd.name == "plan" and not m.palette_open
