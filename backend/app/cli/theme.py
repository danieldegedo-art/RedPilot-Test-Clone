"""RP-001 theme: the exact RedPilot website palette as 24-bit ANSI.

The colours are copied verbatim from the dashboard's `--qa-*` CSS variables
(`dashboard/src/styles/global.css`) so the terminal matches the website exactly.
Rendering uses truecolor (24-bit) escapes, which every modern terminal emulator the
tool targets supports; `NO_COLOR` or a non-tty caller can disable styling.

Pure, stdlib only -- no colour library (none is available here, and none is needed).
"""
from __future__ import annotations

from dataclasses import dataclass

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
REVERSE = "\x1b[7m"

# Verbatim from dashboard/src/styles/global.css :root
PALETTE: dict[str, str] = {
    "bg": "#0b0f17",
    "surface": "#121826",
    "surface_raised": "#171f30",
    "border": "#232c40",
    "text": "#e6ebf5",
    "muted": "#8a94a8",
    "accent": "#4f7cff",
    "accent_hover": "#6c92ff",
    "pass": "#2fb872",
    "fail": "#ef5a5a",
    "warning": "#e0a92d",
    "info": "#4f9cff",
    "error": "#b56cf0",
}

# Log/verdict level -> palette role (mirrors the dashboard's semantic colours).
LEVEL_COLOR: dict[str, str] = {
    "pass": "pass", "ok": "pass", "confirmed": "pass",
    "fail": "fail", "p0": "fail", "critical": "fail",
    "warn": "warning", "warning": "warning", "partial": "warning",
    "info": "info", "debug": "muted",
    "error": "error",
}


def rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    if len(h) != 6 or any(c not in "0123456789abcdefABCDEF" for c in h):
        raise ValueError(f"not a 6-digit hex colour: {hex_color!r}")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def fg(hex_color: str) -> str:
    r, g, b = rgb(hex_color)
    return f"\x1b[38;2;{r};{g};{b}m"


def bg(hex_color: str) -> str:
    r, g, b = rgb(hex_color)
    return f"\x1b[48;2;{r};{g};{b}m"


@dataclass(frozen=True)
class Theme:
    enabled: bool = True   # False -> no escapes (NO_COLOR / non-tty)

    def role(self, name: str) -> str:
        return PALETTE[name]

    def paint(self, text: str, *, color: str | None = None, back: str | None = None,
              bold: bool = False, dim: bool = False) -> str:
        if not self.enabled:
            return text
        pre = ""
        if color:
            pre += fg(PALETTE[color] if color in PALETTE else color)
        if back:
            pre += bg(PALETTE[back] if back in PALETTE else back)
        if bold:
            pre += BOLD
        if dim:
            pre += DIM
        return f"{pre}{text}{RESET}" if pre else text

    def level(self, level: str, text: str, *, bold: bool = False) -> str:
        role = LEVEL_COLOR.get(level.lower(), "text")
        return self.paint(text, color=role, bold=bold)
