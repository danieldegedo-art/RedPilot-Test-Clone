"""Process-level registry of currently-active TestRunner instances.

Lets the API's DELETE /runs/{run_id} endpoint reach into a running job and
request cancellation. Entries are removed once a run finishes persisting.
"""
from __future__ import annotations

from app.testing.runner import TestRunner

active_runners: dict[str, TestRunner] = {}
