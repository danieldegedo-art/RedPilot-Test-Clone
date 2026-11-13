"""Optional plug-in of the Control Adapter: the delegation to ``app.enterprise_controls`` (``adapter.py``).

The always-present part of the Control Adapter (contract, interface, fail-open path, loader, per-method guard) is the Control Port in
``app/core/control_port/``; the Main System imports only that. This package may be missing or damaged: the loader then returns the fail-open adapter.
Nothing is imported here on purpose.
"""
