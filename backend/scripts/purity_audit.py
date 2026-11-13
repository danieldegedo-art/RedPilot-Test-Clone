#!/usr/bin/env python3
"""CLI: static Pure Black-Box audit (inventory completeness, forbidden literals/imports, benchmark-blindness import boundary). Exit 1 on any finding."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app.enterprise_controls.audit import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
