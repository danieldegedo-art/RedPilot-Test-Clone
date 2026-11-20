#!/usr/bin/env python3
"""Cold-domain scanner CLI.

Usage:
    python scan.py https://example.com
    python scan.py https://example.com/pricing

Starts the full engine against the given URL: all 20 modules, cognitive
analysis, discovery layer, payment integrity with all 13 probes. No brief
file, no settings, no configuration. Just a domain and go.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from urllib.parse import urlparse

import httpx


async def scan(url: str, twin_url: str | None = None, cookies: str | None = None) -> None:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"

    api_base = "http://127.0.0.1:8420/api/v1"

    async with httpx.AsyncClient(timeout=30.0) as client:
        mode = "DUAL-TARGET (cold domain + digital twin)" if twin_url else "FULL_REGRESSION (all 20 modules + cognitive + discovery + payment integrity)"
        print(f"Scanning: {url}")
        if twin_url:
            print(f"Twin:     {twin_url}")
        print(f"Mode: {mode}")
        print()

        body: dict = {"url": url}
        if twin_url:
            body["twin_url"] = twin_url
        if cookies:
            body["session_cookies"] = cookies
        resp = await client.post(f"{api_base}/runs/scan", json=body)
        if resp.status_code != 202:
            print(f"ERROR: {resp.status_code} {resp.text}")
            sys.exit(1)

        data = resp.json()
        run_id = data["run_id"]
        print(f"Run started: {run_id}")
        print(f"Status: {data['status']}")
        print()

        while True:
            resp = await client.get(f"{api_base}/runs/{run_id}")
            run = resp.json()
            status = run["status"]

            if status in ("completed", "failed", "cancelled"):
                results = run.get("results", [])
                summary = run.get("summary", {})

                fails = [r for r in results if r["status"] == "FAIL"]
                warnings = [r for r in results if r["status"] == "WARNING"]
                passes = [r for r in results if r["status"] == "PASS"]

                print(f"Status: {status.upper()}")
                print(f"Results: {len(results)} total | {len(fails)} FAIL | {len(warnings)} WARNING | {len(passes)} PASS")
                print()

                if fails:
                    print("=== CRITICAL FINDINGS ===")
                    for f in fails:
                        print(f"  [{f['category']}] {f['name']}")
                        print(f"    {f['actual'][:200]}")
                        if f.get("recommendation"):
                            print(f"    -> {f['recommendation'][:200]}")
                        print()

                if run.get("error_message"):
                    print(f"Error: {run['error_message']}")

                break

            print(f"  [{status}] ...", end="\r")
            await asyncio.sleep(2)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scan.py <url> [--twin <twin_url>]")
        print("Example: python scan.py https://example.com")
        print("         python scan.py https://example.com --twin https://staging.example.com")
        sys.exit(1)

    twin_url = None
    cookies = None
    if "--twin" in sys.argv:
        idx = sys.argv.index("--twin")
        if idx + 1 < len(sys.argv):
            twin_url = sys.argv[idx + 1]
    if "--cookies" in sys.argv:
        idx = sys.argv.index("--cookies")
        if idx + 1 < len(sys.argv):
            cookies = sys.argv[idx + 1]

    asyncio.run(scan(sys.argv[1], twin_url=twin_url, cookies=cookies))


if __name__ == "__main__":
    main()
