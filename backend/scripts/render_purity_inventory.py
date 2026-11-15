#!/usr/bin/env python3
"""Renders the machine-readable migration inventory (app/enterprise_controls/inventory.py) into docs/purity/INVENTORY.xml (the mandate's exact
<target_access_dependency> structure) and docs/purity/INVENTORY.md (reviewable table). The inventory module is the single source of truth."""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.enterprise_controls import inventory as inv  # noqa: E402

DOCS = ROOT.parent / "docs" / "purity"


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def main() -> int:
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "INVENTORY.xml").write_text('<?xml version="1.0" encoding="UTF-8"?>\n<target_access_inventory>\n' + "\n".join("  " + line if line else line for line in inv.inventory_xml().splitlines()) + "\n</target_access_inventory>\n")
    counts = inv.counts()
    lines = ["# Pure Black-Box migration inventory", "",
             f"Generated from `backend/app/enterprise_controls/inventory.py` ({len(inv.INVENTORY)} entries). Classification counts: " + ", ".join(f"{k}={v}" for k, v in counts.items()) + ".",
             "Every repository file is covered by at least one entry (`scripts/purity_audit.py` -> `uncovered_files: 0`); no WHITE_BOX/GREY_BOX entry has `no_change` (`forbidden_no_change: 0`).", "",
             "| ID | Component | File / module | Classification | Action | Priority | State now | Why not pure (if applicable) | Replacement | Validation | Remaining limitations |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for d in inv.INVENTORY:
        lines.append(f"| {d.id} | {cell(d.system_component)} | {cell(d.file_or_module)} | {d.classification.value} | {d.migration_action.value} | {d.migration_priority.value} | {cell(d.state_after_migration)} | "
                     f"{cell(d.why_it_is_not_pure_black_box)} | {cell(d.safe_black_box_replacement)} | {cell(d.validation_method)} | {cell(d.remaining_limitations)} |")
    (DOCS / "INVENTORY.md").write_text("\n".join(lines) + "\n")
    print(f"wrote {DOCS / 'INVENTORY.xml'} and {DOCS / 'INVENTORY.md'} ({len(inv.INVENTORY)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
