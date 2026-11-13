"""RP-001 app: the terminal driver.

`interactive()` is the raw-terminal event loop (termios raw mode, key reading,
SIGWINCH resize, ANSI frame writes). It needs a real TTY, so it is the thin,
not-unit-tested shell over the tested model/render/commands. `demo()` runs a scripted
sequence and returns the rendered plain frame -- it needs no TTY, so it is both the
non-interactive fallback (when stdin is piped) and runnable proof that the whole
pipeline composes. Stdlib only.
"""
from __future__ import annotations

import os
import sys

from app.cli.commands import COMMANDS, handle_key, run_command
from app.cli.model import AppModel, CommandPalette
from app.cli.render import frame, render_rows
from app.cli.theme import Theme


def new_model(width: int = 100, height: int = 30) -> AppModel:
    m = AppModel(width=width, height=height, palette=CommandPalette(COMMANDS))
    m.log("accent", "RedPilot payment-integrity console")
    m.log("muted", "authorized-only · scope-bound · Ctrl-K for the command palette")
    return m


def _term_size(default=(100, 30)) -> tuple[int, int]:
    try:
        sz = os.get_terminal_size()
        return sz.columns, sz.lines
    except OSError:
        return default


def _read_key(read1) -> str | None:
    """Normalise one key from a single-byte reader `read1()` to a token."""
    b = read1()
    if not b:
        return None
    o = b[0] if isinstance(b, (bytes, bytearray)) else ord(b)
    if o == 0x0B:
        return "ctrl-k"
    if o == 0x03:
        return "ctrl-c"
    if o == 0x11:
        return "ctrl-q"
    if o in (0x0D, 0x0A):
        return "enter"
    if o == 0x7F:
        return "backspace"
    if o == 0x1B:  # escape or an arrow sequence \x1b[A/B/C/D
        seq = read1() or b""
        if seq in (b"[", "["):
            arrow = read1() or b""
            a = arrow if isinstance(arrow, str) else arrow.decode("latin-1", "ignore")
            return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(a, "esc")
        return "esc"
    ch = chr(o)
    return ch if ch.isprintable() else None


def demo(model: AppModel, theme: Theme, commands: list[str]) -> str:
    """Run `commands` in order, then return the rendered plain frame (no TTY needed)."""
    for name in commands:
        run_command(model, name)
    return frame(render_rows(model, theme))


def interactive(model: AppModel) -> int:  # pragma: no cover - needs a real TTY
    import termios
    import tty
    theme = Theme(enabled=os.environ.get("NO_COLOR") is None)
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        sys.stdout.write("\x1b[?25l")  # hide cursor
        while model.running:
            model.resize(*_term_size())
            sys.stdout.write(frame(render_rows(model, theme)))
            sys.stdout.flush()
            key = _read_key(lambda: os.read(fd, 1))
            if key is None:
                continue
            name = handle_key(model, key)
            if name:
                run_command(model, name)
    finally:
        sys.stdout.write("\x1b[?25h\x1b[0m\n")  # show cursor, reset
        sys.stdout.flush()
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    width, height = _term_size()
    model = new_model(width, height)
    theme = Theme(enabled=os.environ.get("NO_COLOR") is None)

    if "--demo" in argv or not sys.stdin.isatty():
        # non-interactive: run a representative sequence and print the frame once.
        seq = [a for a in argv if not a.startswith("-")] or ["help", "agents", "orchestrate", "chains"]
        sys.stdout.write(demo(model, theme, seq))
        sys.stdout.write("\x1b[0m\n")
        return 0
    return interactive(model)
