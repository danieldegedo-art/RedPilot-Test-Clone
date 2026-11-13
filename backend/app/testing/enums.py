"""Core enumerations shared across the test framework, API layer and database."""
from __future__ import annotations

from enum import Enum


class TestCategory(str, Enum):
    """The test module categories the QA suite is organized around."""

    FUNCTIONAL = "functional"
    NEGATIVE = "negative"
    EDGE_CASE = "edge_case"
    ERROR_HANDLING = "error_handling"
    INTEGRATION = "integration"
    RECON = "recon"
    STRIPE_FLOW = "stripe_flow"
    ROLE_BASED_ACCESS = "role_based_access"
    PROCESSING_INTEGRITY = "processing_integrity"
    LIFECYCLE_CONSISTENCY = "lifecycle_consistency"
    INPUT_FORMAT_CONSISTENCY = "input_format_consistency"
    INTELLIGENT_DISCOVERY = "intelligent_discovery"
    WEBHOOK_DELIVERY_CONSISTENCY = "webhook_delivery_consistency"
    STATE_TRANSITION_CONSISTENCY = "state_transition_consistency"
    CROSS_VERSION_CONSISTENCY = "cross_version_consistency"
    ADVANCED_INPUT_FORMAT = "advanced_input_format"
    SESSION_CONSISTENCY = "session_consistency"
    BUSINESS_RULE_CONSISTENCY = "business_rule_consistency"
    PAYMENT_INTEGRITY = "payment_integrity"
    RUN_META = "run_meta"


class ResultStatus(str, Enum):
    """Outcome of a single test case.

    PASS / FAIL / WARNING map directly to the dashboard's result filters.
    INFO is used for system notices (e.g. "module not yet implemented").
    ERROR is used for transport-level failures (timeout, connection refused)
    that are distinct from a definitive functional FAIL.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"
    ERROR = "ERROR"


class TestScope(str, Enum):
    """Test scope selectable from the dashboard's Start Screen dropdown."""

    SMOKE = "smoke"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    FULL_REGRESSION = "full_regression"


class RunStatus(str, Enum):
    """Lifecycle status of a QA run."""

    QUEUED = "queued"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
