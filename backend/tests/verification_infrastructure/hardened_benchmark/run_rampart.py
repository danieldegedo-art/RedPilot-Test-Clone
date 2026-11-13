#!/usr/bin/env python3
"""Run the engine against 'Rampart' (vulnerable signed webhook: leaked secret). Also runs the HONEST CONTROL
(secret NOT leaked) which must stay unbeaten. See boss_rampart.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_rampart as R


async def main() -> int:
    print("== 'Rampart' -- signed webhook, VULNERABLE (secret leaked via recon) ==")
    truth = await R.probe_rampart_truth(leak_secret=True)
    found, _ = await R.run_engine(leak_secret=True)
    print(f"  truth: forging a valid event is possible (secret leaked) = {truth}")
    print(f"  engine CONFIRMED_P0 (forged the signed webhook)          = {found}")
    print()
    print("== HONEST CONTROL -- same webhook, secret NOT leaked (implemented correctly) ==")
    ctrl_truth = await R.probe_rampart_truth(leak_secret=False)   # prober uses its in-process secret
    ctrl_found, _ = await R.run_engine(leak_secret=False)
    print(f"  an insider with the secret could forge it = {ctrl_truth} (not observable black-box)")
    print(f"  engine CONFIRMED_P0 = {ctrl_found}   (MUST be False -- a correct webhook stays unforgeable)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
