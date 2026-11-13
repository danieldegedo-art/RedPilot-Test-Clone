"""RP-001 entrypoint: `python -m app.cli` launches the terminal console.

With a real TTY it runs the interactive raw-terminal loop; piped or with `--demo` it
renders a representative frame once and exits. Positional args in demo mode are run as
commands, e.g. `python -m app.cli --demo agents chains`.
"""
from __future__ import annotations

import sys

from app.cli.app import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
