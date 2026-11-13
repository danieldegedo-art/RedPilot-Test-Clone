"""RP-001: tests for app/cli/render.py. Stdlib only."""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.cli.model import AppModel, Command, CommandPalette  # noqa: E402
from app.cli.render import frame, render_rows  # noqa: E402
from app.cli.theme import Theme  # noqa: E402

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PLAIN = Theme(enabled=False)
STYLED = Theme(enabled=True)
CMDS = [Command("run", "start a run"), Command("plan", "show OPPLAN"), Command("agents", "roster")]


def _model(w=80, h=24):
    return AppModel(width=w, height=h, palette=CommandPalette(CMDS))


def test_rows_are_width_and_height_correct_plain():
    rows = render_rows(_model(), PLAIN)
    assert len(rows) == 24 and all(len(r) == 80 for r in rows)


def test_title_and_status_rows_present():
    rows = render_rows(_model(), PLAIN)
    assert "RedPilot" in rows[0]
    assert "mode:" in rows[-1] and "Ctrl-K" in rows[-1]


def test_logged_lines_appear_in_the_main_pane():
    m = _model()
    m.log("pass", "CONFIRMED_P0 PBB-U")
    rows = render_rows(m, PLAIN)
    assert any("CONFIRMED_P0 PBB-U" in r for r in rows)


def test_command_palette_overlay_renders_query_and_matches():
    m = _model()
    m.open_palette()
    for ch in "pl":
        m.palette.type(ch)
    rows = render_rows(m, PLAIN)
    assert any("> pl" in r for r in rows)
    assert any("plan" in r for r in rows)


def test_styled_rows_carry_ansi_and_preserve_cell_width():
    rows = render_rows(_model(), STYLED)
    assert any("\x1b[" in r for r in rows)                      # styling present
    assert all(len(_ANSI.sub("", r)) == 80 for r in rows)       # visible width still 80


def test_frame_clears_and_positions_rows():
    rows = render_rows(_model(), PLAIN)
    blob = frame(rows)
    assert blob.startswith("\x1b[2J\x1b[H")
    assert "\x1b[1;1H" in blob and "\x1b[24;1H" in blob


def test_tiny_terminal_does_not_crash():
    rows = render_rows(_model(10, 3), PLAIN)
    assert len(rows) == 3 and all(len(r) == 10 for r in rows)
