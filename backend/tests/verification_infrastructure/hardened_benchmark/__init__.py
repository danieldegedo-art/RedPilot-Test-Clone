"""Hardened Black-Box Purity Benchmark.

An independent, at-scale hardening of purity_benchmark/. Its defining property:
the ground truth for every target is computed by INDEPENDENTLY PROBING the
target's public API (ground_truth.py), never by reading seeded-flaw flags and
never by consulting the engine's oracle code. This is what lets the hardened
benchmark break the shared-authorship bias the base scorecard honestly flags.
"""
