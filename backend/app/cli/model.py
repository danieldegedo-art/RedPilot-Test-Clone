"""RP-001 model: the pure, testable state of the terminal app.

Everything here is UI logic with no terminal I/O: a capped log ring-buffer, the
command palette (fuzzy match + selection), pane-rectangle layout from the terminal
size, the status-bar state, and the top-level app model that ties them together. The
raw-terminal event loop (`app.py`) drives this; the render layer (`render.py`) turns
it into ANSI. Keeping the logic here means it is unit-testable without a TTY.

Stdlib only; pure.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque

# ---- logs -----------------------------------------------------------------------

@dataclass(frozen=True)
class LogEntry:
    level: str   # pass|fail|warn|info|error|debug
    text: str
    seq: int


class LogBuffer:
    """A capped ring buffer of log lines (newest kept)."""

    def __init__(self, capacity: int = 2000) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._entries: Deque[LogEntry] = deque(maxlen=capacity)
        self._seq = 0

    def append(self, level: str, text: str) -> LogEntry:
        for line in str(text).splitlines() or [""]:
            e = LogEntry(level, line, self._seq)
            self._seq += 1
            self._entries.append(e)
        return self._entries[-1]

    def tail(self, n: int) -> list[LogEntry]:
        if n <= 0:
            return []
        return list(self._entries)[-n:]

    def __len__(self) -> int:
        return len(self._entries)


# ---- command palette ------------------------------------------------------------

@dataclass(frozen=True)
class Command:
    name: str
    description: str
    category: str = "general"


def fuzzy_rank(query: str, name: str) -> tuple | None:
    """Subsequence fuzzy match (case-insensitive). Returns a sort key (lower = better)
    when `query` is a subsequence of `name`, else None. An empty query matches all."""
    q, n = query.lower(), name.lower()
    if not q:
        return (0, 0, len(name), name)
    i = 0
    first = -1
    for ci, ch in enumerate(n):
        if i < len(q) and ch == q[i]:
            if first < 0:
                first = ci
            i += 1
    if i < len(q):
        return None
    prefix = 0 if n.startswith(q) else 1
    return (prefix, first, len(name), name)


class CommandPalette:
    def __init__(self, commands: list[Command]) -> None:
        self.commands = list(commands)
        self.query = ""
        self.index = 0

    def matches(self) -> list[Command]:
        ranked = []
        for c in self.commands:
            key = fuzzy_rank(self.query, c.name)
            if key is not None:
                ranked.append((key, c))
        ranked.sort(key=lambda t: t[0])
        return [c for _, c in ranked]

    def type(self, ch: str) -> None:
        self.query += ch
        self.index = 0

    def backspace(self) -> None:
        self.query = self.query[:-1]
        self.index = 0

    def move(self, delta: int) -> None:
        m = self.matches()
        if not m:
            self.index = 0
            return
        self.index = max(0, min(len(m) - 1, self.index + delta))

    def selected(self) -> Command | None:
        m = self.matches()
        if not m:
            return None
        return m[min(self.index, len(m) - 1)]

    def reset(self) -> None:
        self.query = ""
        self.index = 0


# ---- layout ---------------------------------------------------------------------

@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    w: int
    h: int

    @property
    def is_empty(self) -> bool:
        return self.w <= 0 or self.h <= 0


def compute_layout(width: int, height: int, *, sidebar: bool = True, sidebar_w: int = 28) -> dict[str, Rect]:
    """Terminal-native layout: a 1-row title bar on top, a 1-row status bar on the
    bottom, a main pane in between, and an optional left sidebar. Degrades gracefully
    on a tiny terminal (panes clamp to empty rather than going negative)."""
    width = max(0, width)
    height = max(0, height)
    title = Rect(0, 0, width, 1 if height >= 1 else 0)
    status = Rect(0, max(0, height - 1), width, 1 if height >= 2 else 0)
    body_y = 1
    body_h = max(0, height - 2)
    use_side = sidebar and width >= sidebar_w + 20
    side_w = sidebar_w if use_side else 0
    sidebar_rect = Rect(0, body_y, side_w, body_h)
    main = Rect(side_w, body_y, max(0, width - side_w), body_h)
    return {"title": title, "status": status, "sidebar": sidebar_rect, "main": main}


# ---- app model ------------------------------------------------------------------

@dataclass
class StatusBar:
    mode: str = "idle"          # idle|planning|running|report
    target: str = "(none)"
    scope: str = "authorized-only"
    degraded: bool = False      # control layer fail-open marker (R10)


@dataclass
class AppModel:
    width: int = 80
    height: int = 24
    logs: LogBuffer = field(default_factory=LogBuffer)
    palette: CommandPalette = field(default_factory=lambda: CommandPalette([]))
    palette_open: bool = False
    status: StatusBar = field(default_factory=StatusBar)
    running: bool = True

    def resize(self, width: int, height: int) -> None:
        self.width = max(1, width)
        self.height = max(1, height)

    def layout(self) -> dict[str, Rect]:
        return compute_layout(self.width, self.height)

    def log(self, level: str, text: str) -> None:
        self.logs.append(level, text)

    def open_palette(self) -> None:
        self.palette_open = True
        self.palette.reset()

    def close_palette(self) -> None:
        self.palette_open = False
        self.palette.reset()

    def accept_palette(self) -> Command | None:
        cmd = self.palette.selected()
        self.close_palette()
        return cmd
