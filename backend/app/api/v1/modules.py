"""Powers the Settings screen's test-module toggles: reports every module
in the intended design (SCOPE_MODULES) alongside whether it's actually
implemented yet (MODULE_REGISTRY)."""
from __future__ import annotations

from fastapi import APIRouter

from app.testing.registry import MODULE_REGISTRY, SCOPE_MODULES

router = APIRouter(prefix="/modules", tags=["modules"])


@router.get("")
async def list_modules() -> list[dict]:
    all_ids: set[str] = set()
    for ids in SCOPE_MODULES.values():
        all_ids |= ids

    return [
        {
            "module_id": module_id,
            "display_name": (
                MODULE_REGISTRY[module_id].display_name
                if module_id in MODULE_REGISTRY
                else module_id.replace("_", " ").title()
            ),
            "implemented": module_id in MODULE_REGISTRY,
            "scopes": sorted(scope.value for scope, ids in SCOPE_MODULES.items() if module_id in ids),
        }
        for module_id in sorted(all_ids)
    ]
