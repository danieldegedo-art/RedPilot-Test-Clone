"""Black-Box Purity Benchmark (controlled benchmark targets + independent post-run scorer).

Layout / blindness boundary:
  customer_target.py  the TARGET (fixture). It knows its own seeded flaws; the system under assessment never does.
  scenarios.py        ground truth + target flags -- SCORER SIDE ONLY. Nothing in here is ever passed to the engine.
  lab.py              runs the engine blind: it receives a base URL and a customer-level Execution Brief, nothing else.
  scorer.py           independent post-run scorer: compares the engine's submitted external verdicts with ground truth AFTER the run.
"""
