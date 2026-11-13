"""Pure Black-Box vocabulary and quarantine entry point (permanent operating identity of the Payment QA System).

Pure Black-Box = every capability, decision, evidence artifact, benchmark and report remains valid when ALL target source code,
databases, logs, dashboards, internal APIs and privileged information are unavailable.

The technical enforcement of that rule is the Enterprise Controls component (``app/enterprise_controls``: access gate, credentials,
provenance + fail-closed EvidenceLedger, oracle gate, blindness, quarantine guard, inventory, audit). The Main System reaches it only
through the Control Port (``app/core/control_port``), which keeps the system running (fail-open availability mode) when the component is unavailable.

What stays in this package:
  taxonomy     core vocabulary (TruthLabel, Verdict, Coverage)
  quarantine   import entry point of the quarantined White-/Grey-Box modules; routes the call through the Control Adapter
"""
from __future__ import annotations

PURE_BLACK_BOX = True  # a constant, not a setting: the product identity is not switchable at runtime (availability of the enforcement: see app/core/control_port)
