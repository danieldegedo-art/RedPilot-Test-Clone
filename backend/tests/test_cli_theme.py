"""RP-001: tests for app/cli/theme.py. Stdlib only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.cli.theme import PALETTE, RESET, Theme, bg, fg, rgb  # noqa: E402


def test_rgb_and_truecolor_escapes():
    assert rgb("#4f7cff") == (79, 124, 255)
    assert fg("#4f7cff") == "\x1b[38;2;79;124;255m"
    assert bg("#0b0f17") == "\x1b[48;2;11;15;23m"


def test_invalid_hex_is_rejected():
    for bad in ("#xyz", "#gggggg", "#12345", "#1234567"):   # '#' is optional, but these are malformed
        try:
            rgb(bad)
            assert False, f"expected ValueError for {bad}"
        except ValueError:
            pass


def test_palette_matches_the_website_exactly():
    # verbatim from dashboard/src/styles/global.css
    assert PALETTE["bg"] == "#0b0f17" and PALETTE["accent"] == "#4f7cff"
    assert PALETTE["pass"] == "#2fb872" and PALETTE["fail"] == "#ef5a5a"
    assert PALETTE["text"] == "#e6ebf5" and PALETTE["warning"] == "#e0a92d"


def test_paint_disabled_is_plain_text():
    assert Theme(enabled=False).paint("x", color="accent", bold=True) == "x"


def test_paint_enabled_wraps_and_resets():
    out = Theme().paint("x", color="accent")
    assert out.startswith("\x1b[38;2;79;124;255m") and out.endswith(RESET) and "x" in out


def test_level_color_maps_known_and_unknown():
    t = Theme()
    assert "\x1b[38;2;47;184;114m" in t.level("pass", "ok")      # pass -> #2fb872
    # an unknown level must not crash and must fall back to the text colour
    assert t.level("banana", "hm").endswith(RESET)
