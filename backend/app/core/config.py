"""Backend configuration. Every field can be overridden by a QA_-prefixed
environment variable (e.g. QA_DATABASE_URL) or backend/.env -- see
.env.example. Sensible defaults mean the backend runs with zero
configuration out of the box."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="QA_", extra="ignore")

    app_name: str = "Payment QA Framework"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite+aiosqlite:///./redpilot.db"
    default_timeout_seconds: float = 30.0
    default_user_agent: str = "PaymentQA-Suite/1.0"
    host: str = "127.0.0.1"
    port: int = 8420
    log_level: str = "INFO"

    # --- Concurrent-run backpressure (fault-isolation/robustness pass) ---
    # A run launches a headless Chromium instance (Recon) plus real
    # embedding/ML work per failed result (the cognition layer's
    # AutonomousImprovementLoop) on top of the HTTP traffic against the
    # target. Nothing previously bounded how many POST /runs could execute
    # at once -- see api/v1/runs.py's _run_semaphore. A run over this limit
    # is still accepted immediately and stays visible as "queued" (the
    # dashboard already renders that status) until a slot frees; this does
    # not reject or drop anything, only serializes execution start.
    max_concurrent_runs: int = 100

    enable_experimental_cognition_modules: bool = True

    # --- Ambiguous-case resolution (backend/benchmark/ambiguous_case_resolution.py) ---
    # Formerly an optional real-LLM escalation path (benchmark/llm_escalation.py,
    # removed). Fully local now -- see that module's docstring for the full
    # kept-vs-dropped rationale. Defaults to enabled: there is no
    # network/privacy trade-off left to gate behind an opt-in, unlike the
    # module this replaced.
    enable_ambiguous_case_resolution: bool = True
    ambiguous_resolution_memory_context_items: int = 3

    # --- Retention for the cognition knowledge store ---
    # None (default) = accumulate forever, exactly as before this
    # upgrade. Cross-session accumulation is the whole point of
    # PersistentMemoryStore/CoverageMapper (see
    # CHANGELOG_COGNITIVE_UPGRADE.md section 1) -- this is only a bound
    # on it for anyone running continuously against the same target for
    # months and wanting the DB size to stop growing. Applied once per
    # completed run (CognitiveEngine.end_session), not on a timer.
    episodic_retention_seconds: float | None = None

    max_requests_per_run: int = 10_000_000
    max_requests_per_second: float = 10_000.0
    run_deadline_seconds: float | None = None

    # --- Local-only API guard (core/security.py) ---
    # api_token unset => no token required (Host + Origin checks still apply).
    api_token: str | None = None
    allowed_hostnames: str = "*"
    extra_allowed_origins: str = "*"
    strict_local_origins: bool = False

    # --- Payment-integrity Execution Brief (testing/integrity/brief.py) ---
    # A plain file (0600), NOT a database column: no schema migration involved. The brief holds only customer-level information
    # (approved hosts, synthetic identity aliases + the NAME of the env var holding each identity's token, the customer-facing surface,
    # public prices, protected features). It can never hold target secrets: the purity gate rejects them.
    integrity_brief_path: str = "qa_integrity/brief.json"


settings = Settings()
