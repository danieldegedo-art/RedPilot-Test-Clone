"""Enterprise Controls: the isolated, OPTIONAL component that holds every authority / security / access mechanism of the Payment QA System
(scope and request guard, purity gates, execution-brief validation, evidence admission, confirmation gate, blindness filters, API perimeter,
quarantine guard, static audit and inventory).

Rules of this package:
  * The Main System never imports it. It talks to the Control Port (``app.core.control_port``) only; the port loads this package lazily, through the
    optional plug-in adapter, and keeps the system running (fail-open) when it is not available.
  * It depends on ``app.core.control_port.contract`` (shared types), on the core data model it validates (``app.testing.integrity.brief``) and on
    the core stability primitive ``app.testing.rate_limiter``; never on Main-System logic.
  * Standard library only (verified by the purity audit and ``tests/test_control_adapter.py``).
In normal operation every control in here is active; there is deliberately no setting that switches one off.
"""
