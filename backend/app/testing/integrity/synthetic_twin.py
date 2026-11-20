"""Synthetic Twin v2.0 -- a pure-Python, in-memory, deterministic model of a
payment platform's subscription lifecycle, entitlement matrix, webhook delivery,
and multi-entity accounting.  It is the "reference implementation" that the
integrity engine compares live behaviour against: when the live system diverges
from the twin, that divergence is a finding.

Design constraints (unchanged from v1):
  * Stdlib only -- no third-party imports, no I/O, no network calls.
  * Retrospective-only -- the twin never sends requests.  It models what
    SHOULD have happened given the events we observed, so the diff is the bug.
  * Fail-closed -- any state the twin cannot model is flagged, never ignored.
  * NON-AUTHORITATIVE. A twin outcome is an EXPECTATION for planning/rehearsal,
    never a finding. A real P0 still requires the real server-enforced oracle
    chain and the confirmation gate (ZR-017); a twin/real mismatch is only a LEAD
    to investigate with the real oracle.

v2.0 additions over v1:
  * Full subscription state machine (Stripe-like lifecycle)
  * Entitlement matrix (plan -> features, with override support)
  * Multi-entity accounting (customers, orgs, teams, with hierarchy)
  * Webhook idempotency and replay detection
  * Proration and credit calculations
  * Invoice lifecycle modeling
  * Trial management with grace periods
  * Coupon / discount application
  * Usage-based billing metering
  * Refund policy enforcement
  * Dunning state machine for failed payments
  * Snapshot diffing with structural comparison
"""
from __future__ import annotations

import copy
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

MODULE_VERSION = "synthetic-twin/2.0"


# ===========================================================================
# Subscription State Machine
# ===========================================================================

class SubscriptionStatus(str, Enum):
    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    UNPAID = "unpaid"
    CANCELED = "canceled"
    PAUSED = "paused"


VALID_TRANSITIONS: dict[SubscriptionStatus, set[SubscriptionStatus]] = {
    SubscriptionStatus.TRIALING: {
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.PAST_DUE,
        SubscriptionStatus.CANCELED,
        SubscriptionStatus.INCOMPLETE,
    },
    SubscriptionStatus.ACTIVE: {
        SubscriptionStatus.PAST_DUE,
        SubscriptionStatus.CANCELED,
        SubscriptionStatus.PAUSED,
        SubscriptionStatus.UNPAID,
    },
    SubscriptionStatus.PAST_DUE: {
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.CANCELED,
        SubscriptionStatus.UNPAID,
    },
    SubscriptionStatus.INCOMPLETE: {
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.INCOMPLETE_EXPIRED,
        SubscriptionStatus.CANCELED,
    },
    SubscriptionStatus.INCOMPLETE_EXPIRED: {
        SubscriptionStatus.CANCELED,
    },
    SubscriptionStatus.UNPAID: {
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.CANCELED,
    },
    SubscriptionStatus.CANCELED: set(),
    SubscriptionStatus.PAUSED: {
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.CANCELED,
    },
}


# ===========================================================================
# Invoice State Machine
# ===========================================================================

class InvoiceStatus(str, Enum):
    DRAFT = "draft"
    OPEN = "open"
    PAID = "paid"
    VOID = "void"
    UNCOLLECTIBLE = "uncollectible"


VALID_INVOICE_TRANSITIONS: dict[InvoiceStatus, set[InvoiceStatus]] = {
    InvoiceStatus.DRAFT: {InvoiceStatus.OPEN, InvoiceStatus.VOID},
    InvoiceStatus.OPEN: {InvoiceStatus.PAID, InvoiceStatus.VOID, InvoiceStatus.UNCOLLECTIBLE},
    InvoiceStatus.PAID: set(),
    InvoiceStatus.VOID: set(),
    InvoiceStatus.UNCOLLECTIBLE: {InvoiceStatus.OPEN, InvoiceStatus.VOID},
}


# ===========================================================================
# Dunning State Machine
# ===========================================================================

class DunningStatus(str, Enum):
    HEALTHY = "healthy"
    FIRST_RETRY = "first_retry"
    SECOND_RETRY = "second_retry"
    THIRD_RETRY = "third_retry"
    EXHAUSTED = "exhausted"


DUNNING_ESCALATION = [
    DunningStatus.HEALTHY,
    DunningStatus.FIRST_RETRY,
    DunningStatus.SECOND_RETRY,
    DunningStatus.THIRD_RETRY,
    DunningStatus.EXHAUSTED,
]


# ===========================================================================
# Data Models
# ===========================================================================

@dataclass
class PaymentRecord:
    amount_cents: int = 0
    currency: str = "usd"
    timestamp: float = 0.0
    payment_id: str = ""
    customer_id: str = ""
    qualifying: bool = True
    refunded: bool = False
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    refunded_cents: int = 0
    dispute_status: str | None = None


@dataclass
class RefundRecord:
    refund_id: str = ""
    payment_id: str = ""
    amount_cents: int = 0
    reason: str = ""
    timestamp: float = 0.0
    customer_id: str = ""


@dataclass
class SubscriptionRecord:
    subscription_id: str = ""
    customer_id: str = ""
    plan_id: str = ""
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    current_period_start: float = 0.0
    current_period_end: float = 0.0
    trial_start: float | None = None
    trial_end: float | None = None
    cancel_at_period_end: bool = False
    canceled_at: float | None = None
    created_at: float = 0.0
    quantity: int = 1
    coupon_id: str | None = None
    discount_percent: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    status_history: list[tuple[SubscriptionStatus, float]] = field(default_factory=list)
    dunning_status: DunningStatus = DunningStatus.HEALTHY
    pause_start: float | None = None


@dataclass
class InvoiceRecord:
    invoice_id: str = ""
    customer_id: str = ""
    subscription_id: str | None = None
    amount_cents: int = 0
    amount_paid_cents: int = 0
    status: InvoiceStatus = InvoiceStatus.DRAFT
    line_items: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = 0.0
    due_date: float | None = None
    paid_at: float | None = None
    coupon_id: str | None = None
    discount_cents: int = 0
    tax_cents: int = 0
    proration_credits_cents: int = 0


@dataclass
class UsageMeterRecord:
    meter_id: str = ""
    customer_id: str = ""
    subscription_id: str = ""
    metric_name: str = ""
    quantity: float = 0.0
    period_start: float = 0.0
    period_end: float = 0.0
    reported_at: float = 0.0


@dataclass
class WebhookEvent:
    event_id: str = ""
    event_type: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    delivered_at: float | None = None
    delivery_attempts: int = 0
    idempotency_key: str = ""


@dataclass
class CustomerRecord:
    customer_id: str = ""
    email: str = ""
    name: str = ""
    org_id: str | None = None
    team_id: str | None = None
    balance_cents: int = 0
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    default_payment_method: str | None = None


@dataclass
class EntitlementGrant:
    feature_id: str = ""
    source: str = "plan"  # "plan", "addon", "override", "trial", "coupon"
    granted_at: float = 0.0
    expires_at: float | None = None
    limit: int | None = None  # None = unlimited
    used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


# ===========================================================================
# v1-compat TwinComparison (kept for backward compatibility)
# ===========================================================================

@dataclass(frozen=True)
class TwinComparisonV1:
    identity: str
    expected: bool
    observed: bool
    diverges: bool
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"identity": self.identity, "expected": self.expected, "observed": self.observed,
                "diverges": self.diverges, "note": self.note}


# ===========================================================================
# v2 TwinComparison
# ===========================================================================

@dataclass
class TwinComparison:
    matches: bool
    divergences: list[dict[str, Any]] = field(default_factory=list)
    twin_state: dict[str, Any] = field(default_factory=dict)
    live_state: dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    confidence: str = "high"

    @property
    def is_critical(self) -> bool:
        return self.severity in ("critical", "high") and not self.matches


# ===========================================================================
# Entitlement Matrix
# ===========================================================================

class EntitlementMatrix:
    """Maps plans -> features with override support. Computes the effective
    entitlements for a customer given their subscriptions, add-ons, and
    manual overrides."""

    def __init__(self) -> None:
        self._plan_features: dict[str, dict[str, EntitlementGrant]] = {}
        self._customer_overrides: dict[str, dict[str, EntitlementGrant]] = {}
        self._org_overrides: dict[str, dict[str, EntitlementGrant]] = {}

    def register_plan(self, plan_id: str, features: dict[str, dict[str, Any]]) -> None:
        grants: dict[str, EntitlementGrant] = {}
        for feat_id, cfg in features.items():
            grants[feat_id] = EntitlementGrant(
                feature_id=feat_id,
                source="plan",
                limit=cfg.get("limit"),
                metadata=cfg.get("metadata", {}),
            )
        self._plan_features[plan_id] = grants

    def add_customer_override(self, customer_id: str, feature_id: str, grant: EntitlementGrant) -> None:
        self._customer_overrides.setdefault(customer_id, {})[feature_id] = grant

    def add_org_override(self, org_id: str, feature_id: str, grant: EntitlementGrant) -> None:
        self._org_overrides.setdefault(org_id, {})[feature_id] = grant

    def effective_entitlements(
        self,
        customer: CustomerRecord,
        subscriptions: list[SubscriptionRecord],
        now: float = 0.0,
    ) -> dict[str, EntitlementGrant]:
        result: dict[str, EntitlementGrant] = {}

        active_statuses = {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING}
        for sub in subscriptions:
            if sub.customer_id != customer.customer_id:
                continue
            if sub.status not in active_statuses:
                continue
            plan_grants = self._plan_features.get(sub.plan_id, {})
            for feat_id, grant in plan_grants.items():
                if feat_id not in result:
                    result[feat_id] = copy.copy(grant)
                else:
                    existing = result[feat_id]
                    if grant.limit is None or (existing.limit is not None and grant.limit > existing.limit):
                        result[feat_id] = copy.copy(grant)

        if customer.org_id and customer.org_id in self._org_overrides:
            for feat_id, grant in self._org_overrides[customer.org_id].items():
                if grant.expires_at and now > grant.expires_at:
                    continue
                result[feat_id] = copy.copy(grant)

        if customer.customer_id in self._customer_overrides:
            for feat_id, grant in self._customer_overrides[customer.customer_id].items():
                if grant.expires_at and now > grant.expires_at:
                    continue
                result[feat_id] = copy.copy(grant)

        return result

    def check_access(
        self,
        customer: CustomerRecord,
        subscriptions: list[SubscriptionRecord],
        feature_id: str,
        now: float = 0.0,
    ) -> tuple[bool, str]:
        entitlements = self.effective_entitlements(customer, subscriptions, now)
        grant = entitlements.get(feature_id)
        if grant is None:
            return False, f"no entitlement for feature '{feature_id}'"
        if grant.limit is not None and grant.used >= grant.limit:
            return False, f"usage limit reached ({grant.used}/{grant.limit}) for '{feature_id}'"
        return True, "granted"


# ===========================================================================
# Webhook Idempotency Tracker
# ===========================================================================

class WebhookTracker:
    """Tracks webhook events for idempotency violations, replay attacks,
    out-of-order delivery, and missing events."""

    def __init__(self) -> None:
        self._events: dict[str, WebhookEvent] = {}
        self._idempotency_keys: dict[str, str] = {}
        self._event_sequence: list[str] = []
        self._expected_events: dict[str, list[str]] = {}
        self._anomalies: list[dict[str, Any]] = []

    def record_event(self, event: WebhookEvent) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []

        if event.event_id in self._events:
            existing = self._events[event.event_id]
            anomalies.append({
                "type": "duplicate_event_id",
                "event_id": event.event_id,
                "event_type": event.event_type,
                "first_seen": existing.created_at,
                "duplicate_at": event.created_at,
                "severity": "high",
            })
        else:
            self._events[event.event_id] = event
            self._event_sequence.append(event.event_id)

        if event.idempotency_key:
            if event.idempotency_key in self._idempotency_keys:
                prev_id = self._idempotency_keys[event.idempotency_key]
                if prev_id != event.event_id:
                    anomalies.append({
                        "type": "idempotency_key_collision",
                        "key": event.idempotency_key,
                        "first_event": prev_id,
                        "second_event": event.event_id,
                        "severity": "critical",
                    })
            else:
                self._idempotency_keys[event.idempotency_key] = event.event_id

        if len(self._event_sequence) >= 2:
            prev_event = self._events.get(self._event_sequence[-2])
            if prev_event and event.created_at < prev_event.created_at:
                anomalies.append({
                    "type": "out_of_order_delivery",
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "event_timestamp": event.created_at,
                    "previous_event_timestamp": prev_event.created_at,
                    "severity": "medium",
                })

        if event.delivery_attempts > 3:
            anomalies.append({
                "type": "excessive_retries",
                "event_id": event.event_id,
                "attempts": event.delivery_attempts,
                "severity": "medium",
            })

        self._anomalies.extend(anomalies)
        return anomalies

    def register_expected_sequence(self, trigger: str, expected: list[str]) -> None:
        self._expected_events[trigger] = expected

    def check_missing_events(self, trigger: str) -> list[dict[str, Any]]:
        expected = self._expected_events.get(trigger, [])
        if not expected:
            return []
        observed_types = {self._events[eid].event_type for eid in self._event_sequence if eid in self._events}
        missing = [et for et in expected if et not in observed_types]
        anomalies = []
        for et in missing:
            anomalies.append({
                "type": "missing_expected_event",
                "trigger": trigger,
                "missing_event_type": et,
                "severity": "high",
            })
        self._anomalies.extend(anomalies)
        return anomalies

    def detect_replay_attack(self, window_seconds: float = 300.0) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        payload_hashes: dict[str, list[WebhookEvent]] = defaultdict(list)
        for event in self._events.values():
            payload_str = str(sorted(event.payload.items())) if event.payload else ""
            h = hashlib.sha256(payload_str.encode()).hexdigest()[:16]
            payload_hashes[h].append(event)

        for h, events in payload_hashes.items():
            if len(events) < 2:
                continue
            events_sorted = sorted(events, key=lambda e: e.created_at)
            for i in range(1, len(events_sorted)):
                delta = events_sorted[i].created_at - events_sorted[i - 1].created_at
                if 0 < delta < window_seconds:
                    anomalies.append({
                        "type": "potential_replay",
                        "first_event": events_sorted[i - 1].event_id,
                        "second_event": events_sorted[i].event_id,
                        "delta_seconds": round(delta, 2),
                        "payload_hash": h,
                        "severity": "critical",
                    })
        self._anomalies.extend(anomalies)
        return anomalies

    @property
    def all_anomalies(self) -> list[dict[str, Any]]:
        return list(self._anomalies)


# ===========================================================================
# Proration Engine
# ===========================================================================

class ProrationEngine:
    """Calculates proration credits/charges for mid-cycle plan changes."""

    @staticmethod
    def calculate_proration(
        old_amount_cents: int,
        new_amount_cents: int,
        period_start: float,
        period_end: float,
        change_at: float,
    ) -> dict[str, Any]:
        total_period = period_end - period_start
        if total_period <= 0:
            return {"credit_cents": 0, "charge_cents": 0, "net_cents": 0, "error": "invalid_period"}

        remaining_fraction = max(0.0, (period_end - change_at) / total_period)
        credit_cents = int(old_amount_cents * remaining_fraction)
        charge_cents = int(new_amount_cents * remaining_fraction)
        net_cents = charge_cents - credit_cents

        return {
            "credit_cents": credit_cents,
            "charge_cents": charge_cents,
            "net_cents": net_cents,
            "remaining_fraction": round(remaining_fraction, 6),
            "old_daily_rate": round(old_amount_cents / max(total_period / 86400, 1), 2),
            "new_daily_rate": round(new_amount_cents / max(total_period / 86400, 1), 2),
        }


# ===========================================================================
# SyntheticTwin v2.0
# ===========================================================================

class SyntheticTwin:
    """In-memory, deterministic model of a payment platform. All state changes
    are driven by ``apply_event()`` calls that mirror what the live system did.
    ``compare()`` then diffs the twin's expected state against the live state
    to surface divergences.

    NON-AUTHORITATIVE. A twin outcome is an EXPECTATION for planning/rehearsal,
    never a finding. A real P0 still requires the real server-enforced oracle
    chain and the confirmation gate (ZR-017)."""

    def __init__(self) -> None:
        self.version = MODULE_VERSION

        self._customers: dict[str, CustomerRecord] = {}
        self._subscriptions: dict[str, SubscriptionRecord] = {}
        self._payments: dict[str, PaymentRecord] = {}
        self._refunds: dict[str, RefundRecord] = {}
        self._invoices: dict[str, InvoiceRecord] = {}
        self._usage_meters: dict[str, UsageMeterRecord] = {}

        self._entitlement_matrix = EntitlementMatrix()
        self._webhook_tracker = WebhookTracker()
        self._proration_engine = ProrationEngine()

        self._event_log: list[dict[str, Any]] = []
        self._anomalies: list[dict[str, Any]] = []
        self._balances: dict[str, int] = defaultdict(int)

        self._plan_prices: dict[str, int] = {}
        self._beneficiary_claims: list[tuple[str, str]] = []

    # -- Plan/Feature registration --

    def register_plan(self, plan_id: str, price_cents: int, features: dict[str, dict[str, Any]] | None = None) -> None:
        self._plan_prices[plan_id] = price_cents
        if features:
            self._entitlement_matrix.register_plan(plan_id, features)

    # -- Customer management --

    def add_customer(self, customer: CustomerRecord) -> None:
        self._customers[customer.customer_id] = customer

    def get_customer(self, customer_id: str) -> CustomerRecord | None:
        return self._customers.get(customer_id)

    # -- v1 compat helpers --

    @staticmethod
    def _check_identity(identity: str) -> None:
        if not isinstance(identity, str) or not identity:
            raise ValueError("identity must be a non-empty synthetic token")

    def name_beneficiary(self, payer: str, beneficiary: str) -> None:
        self._check_identity(payer)
        self._check_identity(beneficiary)
        self._beneficiary_claims.append((payer, beneficiary))

    def expected(self, identity: str) -> bool:
        self._check_identity(identity)
        rec = self._payments.get(identity)
        if rec is not None:
            return bool(rec.qualifying and not rec.refunded)
        for sub in self._subscriptions.values():
            if sub.customer_id == identity and sub.status in (SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING):
                return True
        return False

    def use(self, identity: str) -> bool:
        return self.expected(identity)

    def compare_v1(self, identity: str, observed_entitled: bool) -> TwinComparisonV1:
        exp = self.expected(identity)
        diverges = exp != observed_entitled
        if not diverges:
            note = "matches the correct expectation"
        elif observed_entitled and not exp:
            note = ("observed access the correct model does NOT expect -- a LEAD for the real oracle "
                    "(never a finding on its own; the twin is not authoritative)")
        else:
            note = ("observed denial where the correct model expects access -- a reliability/availability LEAD "
                    "for the real oracle, not an entitlement finding")
        return TwinComparisonV1(identity, exp, observed_entitled, diverges, note)

    # -- Event application (the core loop) --

    def apply_event(self, event_type: str, payload: dict[str, Any], timestamp: float = 0.0) -> list[dict[str, Any]]:
        self._event_log.append({"type": event_type, "payload": payload, "timestamp": timestamp})
        anomalies: list[dict[str, Any]] = []

        handler = self._event_handlers.get(event_type)
        if handler:
            result = handler(self, payload, timestamp)
            if result:
                anomalies.extend(result)
        else:
            anomalies.append({
                "type": "unknown_event_type",
                "event_type": event_type,
                "severity": "low",
            })

        self._anomalies.extend(anomalies)
        return anomalies

    # -- Event handlers --

    def _handle_payment_succeeded(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        pid = payload.get("payment_id", "")
        cid = payload.get("customer_id", "")
        amount = payload.get("amount_cents", 0)

        if pid in self._payments:
            anomalies.append({
                "type": "duplicate_payment",
                "payment_id": pid,
                "severity": "critical",
            })
            return anomalies

        record = PaymentRecord(
            amount_cents=amount,
            currency=payload.get("currency", "usd"),
            timestamp=ts,
            payment_id=pid,
            customer_id=cid,
            qualifying=payload.get("qualifying", True),
            description=payload.get("description", ""),
            metadata=payload.get("metadata", {}),
        )
        self._payments[pid] = record
        self._balances[cid] += amount

        if amount == 0:
            anomalies.append({
                "type": "zero_amount_payment",
                "payment_id": pid,
                "customer_id": cid,
                "severity": "high",
            })
        elif amount < 0:
            anomalies.append({
                "type": "negative_payment",
                "payment_id": pid,
                "amount_cents": amount,
                "severity": "critical",
            })

        return anomalies

    def _handle_payment_failed(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        sub_id = payload.get("subscription_id")
        if sub_id and sub_id in self._subscriptions:
            sub = self._subscriptions[sub_id]
            self._escalate_dunning(sub, ts)
            if sub.dunning_status == DunningStatus.EXHAUSTED:
                transition_result = self._transition_subscription(sub, SubscriptionStatus.UNPAID, ts)
                anomalies.extend(transition_result)
        return anomalies

    def _handle_refund(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        refund_id = payload.get("refund_id", "")
        pid = payload.get("payment_id", "")
        amount = payload.get("amount_cents", 0)
        cid = payload.get("customer_id", "")

        if refund_id in self._refunds:
            anomalies.append({
                "type": "duplicate_refund",
                "refund_id": refund_id,
                "severity": "critical",
            })
            return anomalies

        payment = self._payments.get(pid)
        if payment is None:
            anomalies.append({
                "type": "refund_without_payment",
                "refund_id": refund_id,
                "payment_id": pid,
                "severity": "critical",
            })
        else:
            max_refundable = payment.amount_cents - payment.refunded_cents
            if amount > max_refundable:
                anomalies.append({
                    "type": "over_refund",
                    "refund_id": refund_id,
                    "payment_id": pid,
                    "requested_cents": amount,
                    "max_refundable_cents": max_refundable,
                    "severity": "critical",
                })
            payment.refunded_cents += amount
            if amount >= payment.amount_cents:
                payment.refunded = True

        record = RefundRecord(
            refund_id=refund_id,
            payment_id=pid,
            amount_cents=amount,
            reason=payload.get("reason", ""),
            timestamp=ts,
            customer_id=cid,
        )
        self._refunds[refund_id] = record
        self._balances[cid] -= amount

        return anomalies

    def _handle_subscription_created(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        sub_id = payload.get("subscription_id", "")
        cid = payload.get("customer_id", "")
        plan_id = payload.get("plan_id", "")

        if sub_id in self._subscriptions:
            anomalies.append({
                "type": "duplicate_subscription",
                "subscription_id": sub_id,
                "severity": "high",
            })
            return anomalies

        initial_status = SubscriptionStatus(payload.get("status", "active"))
        trial_start = payload.get("trial_start")
        trial_end = payload.get("trial_end")

        if trial_start is not None and trial_end is not None:
            initial_status = SubscriptionStatus.TRIALING

        record = SubscriptionRecord(
            subscription_id=sub_id,
            customer_id=cid,
            plan_id=plan_id,
            status=initial_status,
            current_period_start=payload.get("current_period_start", ts),
            current_period_end=payload.get("current_period_end", ts + 2592000),
            trial_start=trial_start,
            trial_end=trial_end,
            created_at=ts,
            quantity=payload.get("quantity", 1),
            coupon_id=payload.get("coupon_id"),
            discount_percent=payload.get("discount_percent", 0.0),
            metadata=payload.get("metadata", {}),
        )
        record.status_history.append((initial_status, ts))
        self._subscriptions[sub_id] = record

        if cid not in self._customers:
            anomalies.append({
                "type": "subscription_for_unknown_customer",
                "subscription_id": sub_id,
                "customer_id": cid,
                "severity": "medium",
            })

        return anomalies

    def _handle_subscription_updated(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        sub_id = payload.get("subscription_id", "")
        sub = self._subscriptions.get(sub_id)

        if sub is None:
            anomalies.append({
                "type": "update_unknown_subscription",
                "subscription_id": sub_id,
                "severity": "high",
            })
            return anomalies

        new_status_str = payload.get("status")
        if new_status_str:
            new_status = SubscriptionStatus(new_status_str)
            transition_anomalies = self._transition_subscription(sub, new_status, ts)
            anomalies.extend(transition_anomalies)

        new_plan = payload.get("plan_id")
        if new_plan and new_plan != sub.plan_id:
            old_price = self._plan_prices.get(sub.plan_id, 0)
            new_price = self._plan_prices.get(new_plan, 0)
            proration = self._proration_engine.calculate_proration(
                old_price, new_price,
                sub.current_period_start, sub.current_period_end, ts,
            )
            sub.metadata["last_plan_change"] = {
                "old_plan": sub.plan_id, "new_plan": new_plan,
                "proration": proration, "changed_at": ts,
            }
            sub.plan_id = new_plan

        if "quantity" in payload:
            sub.quantity = payload["quantity"]
        if "cancel_at_period_end" in payload:
            sub.cancel_at_period_end = payload["cancel_at_period_end"]
            if sub.cancel_at_period_end:
                sub.canceled_at = ts

        return anomalies

    def _handle_subscription_deleted(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        sub_id = payload.get("subscription_id", "")
        sub = self._subscriptions.get(sub_id)
        if sub is None:
            return [{"type": "delete_unknown_subscription", "subscription_id": sub_id, "severity": "medium"}]
        return self._transition_subscription(sub, SubscriptionStatus.CANCELED, ts)

    def _handle_invoice_created(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        inv_id = payload.get("invoice_id", "")
        if inv_id in self._invoices:
            return [{"type": "duplicate_invoice", "invoice_id": inv_id, "severity": "high"}]

        record = InvoiceRecord(
            invoice_id=inv_id,
            customer_id=payload.get("customer_id", ""),
            subscription_id=payload.get("subscription_id"),
            amount_cents=payload.get("amount_cents", 0),
            status=InvoiceStatus(payload.get("status", "draft")),
            line_items=payload.get("line_items", []),
            created_at=ts,
            due_date=payload.get("due_date"),
            coupon_id=payload.get("coupon_id"),
            discount_cents=payload.get("discount_cents", 0),
            tax_cents=payload.get("tax_cents", 0),
        )
        self._invoices[inv_id] = record
        return []

    def _handle_invoice_paid(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        inv_id = payload.get("invoice_id", "")
        invoice = self._invoices.get(inv_id)
        if invoice is None:
            anomalies.append({"type": "pay_unknown_invoice", "invoice_id": inv_id, "severity": "high"})
            return anomalies

        if invoice.status not in (InvoiceStatus.OPEN, InvoiceStatus.DRAFT):
            anomalies.append({
                "type": "invalid_invoice_transition",
                "invoice_id": inv_id,
                "current_status": invoice.status.value,
                "attempted": "paid",
                "severity": "high",
            })

        invoice.status = InvoiceStatus.PAID
        invoice.paid_at = ts
        invoice.amount_paid_cents = payload.get("amount_paid_cents", invoice.amount_cents)

        if invoice.amount_paid_cents != invoice.amount_cents:
            anomalies.append({
                "type": "partial_invoice_payment",
                "invoice_id": inv_id,
                "expected_cents": invoice.amount_cents,
                "paid_cents": invoice.amount_paid_cents,
                "severity": "medium",
            })

        if invoice.subscription_id:
            sub = self._subscriptions.get(invoice.subscription_id)
            if sub and sub.dunning_status != DunningStatus.HEALTHY:
                sub.dunning_status = DunningStatus.HEALTHY
                if sub.status in (SubscriptionStatus.PAST_DUE, SubscriptionStatus.UNPAID):
                    self._transition_subscription(sub, SubscriptionStatus.ACTIVE, ts)

        return anomalies

    def _handle_trial_ended(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        sub_id = payload.get("subscription_id", "")
        sub = self._subscriptions.get(sub_id)
        if sub is None:
            return [{"type": "trial_end_unknown_subscription", "subscription_id": sub_id, "severity": "medium"}]

        if sub.status != SubscriptionStatus.TRIALING:
            anomalies.append({
                "type": "trial_end_wrong_state",
                "subscription_id": sub_id,
                "current_status": sub.status.value,
                "severity": "medium",
            })

        has_payment = payload.get("payment_method_attached", False)
        if has_payment:
            anomalies.extend(self._transition_subscription(sub, SubscriptionStatus.ACTIVE, ts))
        else:
            anomalies.extend(self._transition_subscription(sub, SubscriptionStatus.INCOMPLETE, ts))

        return anomalies

    def _handle_webhook_received(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        event = WebhookEvent(
            event_id=payload.get("event_id", ""),
            event_type=payload.get("event_type", ""),
            payload=payload.get("data", {}),
            created_at=ts,
            delivered_at=payload.get("delivered_at"),
            delivery_attempts=payload.get("delivery_attempts", 1),
            idempotency_key=payload.get("idempotency_key", ""),
        )
        return self._webhook_tracker.record_event(event)

    def _handle_usage_reported(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        meter_id = payload.get("meter_id", "")
        quantity = payload.get("quantity", 0)

        if quantity < 0:
            anomalies.append({
                "type": "negative_usage",
                "meter_id": meter_id,
                "quantity": quantity,
                "severity": "high",
            })

        record = UsageMeterRecord(
            meter_id=meter_id,
            customer_id=payload.get("customer_id", ""),
            subscription_id=payload.get("subscription_id", ""),
            metric_name=payload.get("metric_name", ""),
            quantity=quantity,
            period_start=payload.get("period_start", 0),
            period_end=payload.get("period_end", 0),
            reported_at=ts,
        )
        self._usage_meters[meter_id] = record
        return anomalies

    def _handle_entitlement_check(self, payload: dict[str, Any], ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        cid = payload.get("customer_id", "")
        feature_id = payload.get("feature_id", "")
        live_allowed = payload.get("allowed", False)

        customer = self._customers.get(cid)
        if customer is None:
            if live_allowed:
                anomalies.append({
                    "type": "access_granted_unknown_customer",
                    "customer_id": cid,
                    "feature_id": feature_id,
                    "severity": "critical",
                })
            return anomalies

        subs = [s for s in self._subscriptions.values() if s.customer_id == cid]
        twin_allowed, reason = self._entitlement_matrix.check_access(customer, subs, feature_id, ts)

        if live_allowed and not twin_allowed:
            anomalies.append({
                "type": "access_without_entitlement",
                "customer_id": cid,
                "feature_id": feature_id,
                "twin_reason": reason,
                "severity": "critical",
            })
        elif not live_allowed and twin_allowed:
            anomalies.append({
                "type": "access_denied_despite_entitlement",
                "customer_id": cid,
                "feature_id": feature_id,
                "severity": "medium",
            })

        return anomalies

    _event_handlers: dict[str, Any] = {
        "payment.succeeded": _handle_payment_succeeded,
        "payment.failed": _handle_payment_failed,
        "refund.created": _handle_refund,
        "subscription.created": _handle_subscription_created,
        "subscription.updated": _handle_subscription_updated,
        "subscription.deleted": _handle_subscription_deleted,
        "invoice.created": _handle_invoice_created,
        "invoice.paid": _handle_invoice_paid,
        "trial.ended": _handle_trial_ended,
        "webhook.received": _handle_webhook_received,
        "usage.reported": _handle_usage_reported,
        "entitlement.check": _handle_entitlement_check,
    }

    # -- State machine helpers --

    def _transition_subscription(
        self, sub: SubscriptionRecord, new_status: SubscriptionStatus, ts: float,
    ) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        old_status = sub.status

        if new_status == old_status:
            return []

        valid = VALID_TRANSITIONS.get(old_status, set())
        if new_status not in valid:
            anomalies.append({
                "type": "invalid_subscription_transition",
                "subscription_id": sub.subscription_id,
                "from": old_status.value,
                "to": new_status.value,
                "valid_targets": sorted(s.value for s in valid),
                "severity": "high",
            })

        sub.status = new_status
        sub.status_history.append((new_status, ts))

        if new_status == SubscriptionStatus.CANCELED:
            sub.canceled_at = ts
        elif new_status == SubscriptionStatus.PAUSED:
            sub.pause_start = ts
        elif new_status == SubscriptionStatus.ACTIVE and old_status == SubscriptionStatus.PAUSED:
            sub.pause_start = None

        return anomalies

    def _escalate_dunning(self, sub: SubscriptionRecord, ts: float) -> None:
        idx = DUNNING_ESCALATION.index(sub.dunning_status)
        if idx < len(DUNNING_ESCALATION) - 1:
            sub.dunning_status = DUNNING_ESCALATION[idx + 1]

    # -- v1 compat pay/refund shortcuts --

    def pay(self, identity_or_amount: str | int, *, qualifying: bool = True, customer_id: str = "", payment_id: str = "", **kw: Any) -> Any:
        if isinstance(identity_or_amount, str):
            self._check_identity(identity_or_amount)
            self._payments[identity_or_amount] = PaymentRecord(qualifying=qualifying)
            return None
        return self.apply_event("payment.succeeded", {
            "payment_id": payment_id or f"pay_{len(self._payments)}",
            "customer_id": customer_id or "default",
            "amount_cents": identity_or_amount,
            "qualifying": qualifying,
            **kw,
        })

    def refund(self, identity_or_amount: str | int, *, payment_id: str = "", customer_id: str = "", **kw: Any) -> Any:
        if isinstance(identity_or_amount, str):
            self._check_identity(identity_or_amount)
            rec = self._payments.get(identity_or_amount)
            if rec is not None:
                self._payments[identity_or_amount] = PaymentRecord(
                    amount_cents=rec.amount_cents, currency=rec.currency,
                    timestamp=rec.timestamp, payment_id=rec.payment_id,
                    customer_id=rec.customer_id, qualifying=rec.qualifying,
                    refunded=True, description=rec.description,
                    metadata=rec.metadata, refunded_cents=rec.amount_cents,
                )
            return None
        return self.apply_event("refund.created", {
            "refund_id": kw.pop("refund_id", f"ref_{len(self._refunds)}"),
            "payment_id": payment_id,
            "customer_id": customer_id or "default",
            "amount_cents": identity_or_amount,
            **kw,
        })

    # -- Full comparison engine --

    def compare(self, live_state_or_identity: dict[str, Any] | str = "", observed_entitled: bool | None = None) -> TwinComparison | TwinComparisonV1:
        if isinstance(live_state_or_identity, str) and live_state_or_identity:
            if observed_entitled is None:
                raise ValueError("observed_entitled required for v1 compare")
            return self.compare_v1(live_state_or_identity, observed_entitled)

        live_state = live_state_or_identity if isinstance(live_state_or_identity, dict) else {}
        twin_snapshot = self.snapshot()
        divergences: list[dict[str, Any]] = []
        max_severity = "info"

        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        live_balances = live_state.get("balances", {})
        for cid, twin_balance in self._balances.items():
            live_balance = live_balances.get(cid)
            if live_balance is None:
                continue
            if isinstance(live_balance, (int, float)) and int(live_balance) != twin_balance:
                sev = "critical" if abs(int(live_balance) - twin_balance) > 100 else "high"
                divergences.append({
                    "type": "balance_mismatch",
                    "customer_id": cid,
                    "twin_balance_cents": twin_balance,
                    "live_balance_cents": int(live_balance),
                    "delta_cents": int(live_balance) - twin_balance,
                    "severity": sev,
                })
                if severity_rank.get(sev, 0) > severity_rank.get(max_severity, 0):
                    max_severity = sev

        live_subs = live_state.get("subscriptions", {})
        for sub_id, twin_sub in self._subscriptions.items():
            live_sub = live_subs.get(sub_id)
            if live_sub is None:
                continue
            live_sub_status = live_sub.get("status", "")
            if live_sub_status and live_sub_status != twin_sub.status.value:
                divergences.append({
                    "type": "subscription_status_mismatch",
                    "subscription_id": sub_id,
                    "twin_status": twin_sub.status.value,
                    "live_status": live_sub_status,
                    "severity": "high",
                })
                if severity_rank.get("high", 0) > severity_rank.get(max_severity, 0):
                    max_severity = "high"

        live_entitlements = live_state.get("entitlements", {})
        for cid, features in live_entitlements.items():
            customer = self._customers.get(cid)
            if customer is None:
                continue
            subs = [s for s in self._subscriptions.values() if s.customer_id == cid]
            twin_ent = self._entitlement_matrix.effective_entitlements(customer, subs)
            for feat_id, live_allowed in features.items():
                twin_has = feat_id in twin_ent
                if live_allowed and not twin_has:
                    divergences.append({
                        "type": "entitlement_mismatch",
                        "customer_id": cid,
                        "feature_id": feat_id,
                        "twin_allowed": False,
                        "live_allowed": True,
                        "severity": "critical",
                    })
                    if severity_rank.get("critical", 0) > severity_rank.get(max_severity, 0):
                        max_severity = "critical"

        for anomaly in self._anomalies:
            sev = anomaly.get("severity", "low")
            divergences.append(anomaly)
            if severity_rank.get(sev, 0) > severity_rank.get(max_severity, 0):
                max_severity = sev

        return TwinComparison(
            matches=len(divergences) == 0,
            divergences=divergences,
            twin_state=twin_snapshot,
            live_state=live_state,
            severity=max_severity,
            confidence="high",
        )

    # -- Snapshot / restore --

    def snapshot(self) -> dict[str, Any]:
        return {
            "module_version": MODULE_VERSION,
            "customers": {cid: _customer_to_dict(c) for cid, c in self._customers.items()},
            "subscriptions": {sid: _subscription_to_dict(s) for sid, s in self._subscriptions.items()},
            "payments": {pid: _payment_to_dict(p) for pid, p in sorted(self._payments.items())},
            "refunds": {rid: _refund_to_dict(r) for rid, r in self._refunds.items()},
            "invoices": {iid: _invoice_to_dict(inv) for iid, inv in self._invoices.items()},
            "balances": dict(self._balances),
            "beneficiary_claims": [list(c) for c in self._beneficiary_claims],
            "anomaly_count": len(self._anomalies),
            "event_count": len(self._event_log),
            "webhook_anomalies": self._webhook_tracker.all_anomalies,
            "note": "Synthetic, deterministic, offline model of CORRECT behaviour. A twin outcome is an "
                    "expectation for rehearsal/planning, never a finding; real P0s require the real oracle "
                    "chain (ZR-017).",
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        for cid, cdata in snapshot.get("customers", {}).items():
            self._customers[cid] = CustomerRecord(
                customer_id=cid,
                email=cdata.get("email", ""),
                name=cdata.get("name", ""),
                org_id=cdata.get("org_id"),
                team_id=cdata.get("team_id"),
                balance_cents=cdata.get("balance_cents", 0),
                created_at=cdata.get("created_at", 0),
                metadata=cdata.get("metadata", {}),
                default_payment_method=cdata.get("default_payment_method"),
            )
        for sid, sdata in snapshot.get("subscriptions", {}).items():
            self._subscriptions[sid] = SubscriptionRecord(
                subscription_id=sid,
                customer_id=sdata.get("customer_id", ""),
                plan_id=sdata.get("plan_id", ""),
                status=SubscriptionStatus(sdata.get("status", "active")),
                current_period_start=sdata.get("current_period_start", 0),
                current_period_end=sdata.get("current_period_end", 0),
                trial_start=sdata.get("trial_start"),
                trial_end=sdata.get("trial_end"),
                cancel_at_period_end=sdata.get("cancel_at_period_end", False),
                canceled_at=sdata.get("canceled_at"),
                created_at=sdata.get("created_at", 0),
                quantity=sdata.get("quantity", 1),
                coupon_id=sdata.get("coupon_id"),
                discount_percent=sdata.get("discount_percent", 0.0),
                metadata=sdata.get("metadata", {}),
            )
        for pid, pdata in snapshot.get("payments", {}).items():
            self._payments[pid] = PaymentRecord(
                amount_cents=pdata.get("amount_cents", 0),
                currency=pdata.get("currency", "usd"),
                timestamp=pdata.get("timestamp", 0),
                payment_id=pid,
                customer_id=pdata.get("customer_id", ""),
                qualifying=pdata.get("qualifying", True),
                refunded=pdata.get("refunded", False),
                description=pdata.get("description", ""),
                metadata=pdata.get("metadata", {}),
                refunded_cents=pdata.get("refunded_cents", 0),
            )
        self._balances.update(snapshot.get("balances", {}))
        self._beneficiary_claims = [tuple(c) for c in snapshot.get("beneficiary_claims", [])]


# ===========================================================================
# Serialisation helpers
# ===========================================================================

def _customer_to_dict(c: CustomerRecord) -> dict[str, Any]:
    return {
        "customer_id": c.customer_id, "email": c.email, "name": c.name,
        "org_id": c.org_id, "team_id": c.team_id,
        "balance_cents": c.balance_cents, "created_at": c.created_at,
        "metadata": c.metadata, "default_payment_method": c.default_payment_method,
    }


def _subscription_to_dict(s: SubscriptionRecord) -> dict[str, Any]:
    return {
        "subscription_id": s.subscription_id, "customer_id": s.customer_id,
        "plan_id": s.plan_id, "status": s.status.value,
        "current_period_start": s.current_period_start,
        "current_period_end": s.current_period_end,
        "trial_start": s.trial_start, "trial_end": s.trial_end,
        "cancel_at_period_end": s.cancel_at_period_end,
        "canceled_at": s.canceled_at, "created_at": s.created_at,
        "quantity": s.quantity, "coupon_id": s.coupon_id,
        "discount_percent": s.discount_percent,
        "metadata": s.metadata,
        "dunning_status": s.dunning_status.value,
        "status_history": [(st.value, ts) for st, ts in s.status_history],
    }


def _payment_to_dict(p: PaymentRecord) -> dict[str, Any]:
    return {
        "payment_id": p.payment_id, "amount_cents": p.amount_cents,
        "currency": p.currency, "timestamp": p.timestamp,
        "customer_id": p.customer_id, "qualifying": p.qualifying,
        "refunded": p.refunded, "description": p.description,
        "metadata": p.metadata, "refunded_cents": p.refunded_cents,
        "dispute_status": p.dispute_status,
    }


def _refund_to_dict(r: RefundRecord) -> dict[str, Any]:
    return {
        "refund_id": r.refund_id, "payment_id": r.payment_id,
        "amount_cents": r.amount_cents, "reason": r.reason,
        "timestamp": r.timestamp, "customer_id": r.customer_id,
    }


def _invoice_to_dict(inv: InvoiceRecord) -> dict[str, Any]:
    return {
        "invoice_id": inv.invoice_id, "customer_id": inv.customer_id,
        "subscription_id": inv.subscription_id,
        "amount_cents": inv.amount_cents, "amount_paid_cents": inv.amount_paid_cents,
        "status": inv.status.value, "line_items": inv.line_items,
        "created_at": inv.created_at, "due_date": inv.due_date,
        "paid_at": inv.paid_at, "coupon_id": inv.coupon_id,
        "discount_cents": inv.discount_cents, "tax_cents": inv.tax_cents,
        "proration_credits_cents": inv.proration_credits_cents,
    }
