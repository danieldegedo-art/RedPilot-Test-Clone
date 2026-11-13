"""Offline benchmark/analysis components used by the cognitive
architecture (app.testing.cognition). Everything here is read-only with
respect to the system under test: nothing in this package sends network
requests -- it only reasons over observations the test modules already
collected.

Historically referenced from cognition/engine.py and cognition/*.py
(`from benchmark.llm_replacement_layer import LLMReplacementLayer`,
`from benchmark.real_test_executor import RealTestExecutor`) but never
actually shipped, which is why those imports were wrapped in
try/except ImportError and silently degraded. llm_replacement_layer is
now real; see its module docstring.
"""
from __future__ import annotations

from benchmark.llm_replacement_layer import LLMReplacementLayer, LLMReplacementResult

__all__ = ["LLMReplacementLayer", "LLMReplacementResult"]
