"""RP-001 render: compose the model into width-correct terminal rows.

`render_rows` returns exactly `height` rows, each occupying exactly `width` visible
cells. With `theme.enabled=False` the rows are plain text (what the tests assert on);
with styling enabled each row carries ANSI escapes but still occupies `width` cells
(escapes are zero-width), so the layout is identical either way. `frame` turns the
rows into one escape-sequence blob (clear + cursor-home + positioned lines) for the
event loop to write.

This is terminal-native output: a title bar, an optional sidebar, a scrolling log /
command-palette main pane, and a status bar -- not a web layout. Stdlib only; pure.
"""
from __future__ import annotations

from app.cli.model import AppModel, Rect
from app.cli.theme import Theme

_ELLIPSIS = "…"
_VBAR = "│"


def fit(s: str, w: int) -> str:
    """Truncate or pad a PLAIN string to exactly `w` cells."""
    if w <= 0:
        return ""
    if len(s) > w:
        return s[: w - 1] + _ELLIPSIS if w >= 1 else ""
    return s.ljust(w)


def _title_row(model: AppModel, theme: Theme, w: int) -> str:
    plain = fit(f" RedPilot  {_VBAR}  payment-integrity console  {_VBAR}  {model.status.mode}", w)
    return theme.paint(plain, color="bg", back="accent", bold=True)


def _status_row(model: AppModel, theme: Theme, w: int) -> str:
    s = model.status
    deg = "  DEGRADED" if s.degraded else ""
    plain = fit(f" mode:{s.mode}  target:{s.target}  scope:{s.scope}{deg}  {_VBAR}  Ctrl-K palette  Ctrl-C quit", w)
    return theme.paint(plain, color="muted" if not s.degraded else "warning", back="surface_raised")


def _sidebar_rows(model: AppModel, theme: Theme, rect: Rect) -> list[str]:
    if rect.is_empty:
        return []
    lines = ["REDPILOT", "", "run        start a run", "plan       show OPPLAN",
             "agents     roster", "orchestrate  waves", "findings   results",
             "chains     attack chains", "coverage   matrix", "", "Ctrl-K  command palette"]
    rows: list[str] = []
    for i in range(rect.h):
        raw = lines[i] if i < len(lines) else ""
        body = fit(raw, rect.w - 1)
        header = i == 0
        cell = theme.paint(body, color="accent" if header else "muted", bold=header) + theme.paint(_VBAR, color="border")
        rows.append(cell)
    return rows


def _palette_rows(model: AppModel, theme: Theme, rect: Rect) -> list[str]:
    rows: list[str] = []
    prompt = fit(f" > {model.palette.query}", rect.w)
    rows.append(theme.paint(prompt, color="text", back="surface_raised", bold=True))
    matches = model.palette.matches()
    sel = model.palette.selected()
    for i in range(1, rect.h):
        mi = i - 1
        if mi < len(matches):
            c = matches[mi]
            line = fit(f"  {c.name:<14}{c.description}", rect.w)
            rows.append(theme.paint(line, color="text", back="surface" if c is sel else None,
                                    bold=c is sel))
        else:
            rows.append(theme.paint(fit("", rect.w), color="text"))
    return rows


def _log_rows(model: AppModel, theme: Theme, rect: Rect) -> list[str]:
    tail = model.logs.tail(rect.h)
    pad = [None] * (rect.h - len(tail)) + tail
    rows: list[str] = []
    for e in pad:
        if e is None:
            rows.append(theme.paint(fit("", rect.w), color="text"))
        else:
            plain = fit(f" {e.text}", rect.w)
            rows.append(theme.level(e.level, plain))
    return rows


def render_rows(model: AppModel, theme: Theme) -> list[str]:
    lay = model.layout()
    w, h = model.width, model.height
    main = lay["main"]
    main_rows = _palette_rows(model, theme, main) if model.palette_open else _log_rows(model, theme, main)
    side_rows = _sidebar_rows(model, theme, lay["sidebar"])

    body: list[str] = []
    for i in range(main.h):
        left = side_rows[i] if i < len(side_rows) else ""
        body.append(left + (main_rows[i] if i < len(main_rows) else theme.paint(fit("", main.w), color="text")))

    rows: list[str] = []
    if h >= 1:
        rows.append(_title_row(model, theme, w))
    rows.extend(body)
    if h >= 2:
        rows.append(_status_row(model, theme, w))
    # clamp to exactly h rows
    rows = rows[:h]
    while len(rows) < h:
        rows.append(theme.paint(fit("", w), color="text"))
    return rows


def frame(rows: list[str]) -> str:
    """Clear, home the cursor, and lay the rows down -- one blob to write to the tty."""
    out = ["\x1b[2J\x1b[H"]
    for i, r in enumerate(rows):
        out.append(f"\x1b[{i + 1};1H{r}")
    return "".join(out)
