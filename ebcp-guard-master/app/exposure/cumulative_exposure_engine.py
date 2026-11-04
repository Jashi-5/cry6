"""
EBCP-Guard Cumulative Exposure Intelligence Engine
====================================================
Tracks disclosure events across API requests and computes cumulative
privacy risk using the formula:

  R(t) = α·S(t) + β·C(t) + γ·L(t) + δ·D(t)

Where:
  S(t) = Current sensitivity score (from sensitivity classifier)
  C(t) = Cumulative exposure score (from historical disclosure events)
  L(t) = Cross-request linkability risk (from entity co-occurrence)
  D(t) = Destination trust risk (inverse of destination trust level)

All components are normalized to [0, 1].
Weights α, β, γ, δ are configurable via environment variables.

Research motivation:
  Conventional DLP inspects each request independently.
  This engine demonstrates that sequentially low-risk disclosures
  can collectively exceed acceptable exposure thresholds.

SECURITY CONTRACT:
  Exposure events NEVER store original sensitive values.
  Only entity TYPE labels and safe hashes are used for correlation.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


# ------------------------------------------------------------------ #
# Configuration
# ------------------------------------------------------------------ #

# Destination trust levels (lower = less trusted = higher D(t))
_DESTINATION_TRUST = {
    "internal_payment": 0.95,
    "fraud_service": 0.90,
    "authentication": 0.88,
    "internal_analytics": 0.70,
    "third_party_analytics": 0.40,
    "marketing": 0.25,
    "external_unknown": 0.10,
    "unknown": 0.15,
}

# Sensitivity class → numeric score for S(t) computation
_SENSITIVITY_SCORES = {
    "S0": 0.0,
    "S1": 0.2,
    "S2": 0.45,
    "S3": 0.72,
    "S4": 1.0,
}

# Entity linkability weight — entities that enable identity linking
_LINKABILITY_WEIGHTS = {
    "PAN": 0.95,
    "AADHAAR": 0.95,
    "ACCOUNT_NUMBER": 0.80,
    "CARD_NUMBER": 0.85,
    "EMAIL": 0.75,
    "PHONE": 0.70,
    "UPI_ID": 0.65,
    "PERSON": 0.60,
    "DATE_OF_BIRTH": 0.70,
    "ADDRESS": 0.55,
    "IFSC": 0.30,
    "TRANSACTION_AMOUNT": 0.20,
    "IP_ADDRESS": 0.50,
    "GST_NUMBER": 0.60,
}


@dataclass
class ExposureEventRecord:
    """In-memory representation of a single disclosure event."""
    synthetic_customer_id: str
    tenant_id: str
    entity_types: list[str]
    endpoint: str
    purpose: str
    destination: str
    protection_action: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    session_id: str | None = None
    disclosure_sequence_id: str | None = None


@dataclass
class RiskDecomposition:
    """Decomposed risk score components for explainability."""
    sensitivity_score: float      # S(t)
    cumulative_score: float       # C(t)
    linkability_score: float      # L(t)
    destination_trust_score: float  # D(t)
    total_risk_score: float       # R(t)
    risk_level: str
    contributing_factors: dict[str, Any]
    recommended_action: str


class CumulativeExposureEngine:
    """
    Tracks and scores cumulative disclosure risk across API requests.

    In production, this class coordinates with the PostgreSQL ExposureEvent
    and ExposureScore tables. For the in-memory prototype, it maintains
    an internal event log per synthetic customer.

    The engine demonstrates the research contribution:
    Individual request analysis vs. cumulative exposure analysis.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._alpha = settings.risk_weight_sensitivity
        self._beta = settings.risk_weight_cumulative
        self._gamma = settings.risk_weight_linkability
        self._delta = settings.risk_weight_destination
        self._threshold_low = settings.risk_threshold_low
        self._threshold_medium = settings.risk_threshold_medium
        self._threshold_high = settings.risk_threshold_high

        # In-memory event store: {synthetic_customer_id → [events]}
        # In production, replaced by PostgreSQL queries.
        self._event_store: dict[str, list[ExposureEventRecord]] = defaultdict(list)

    # ------------------------------------------------------------------ #
    # Event Recording
    # ------------------------------------------------------------------ #

    def record_event(self, event: ExposureEventRecord) -> None:
        """
        Record a disclosure event for a synthetic customer.
        Original values are never stored — only entity TYPE labels.
        """
        self._event_store[event.synthetic_customer_id].append(event)
        logger.info(
            "exposure_event_recorded",
            synthetic_customer_id=event.synthetic_customer_id,
            entity_types=event.entity_types,
            protection_action=event.protection_action,
        )

    # ------------------------------------------------------------------ #
    # Risk Scoring
    # ------------------------------------------------------------------ #

    def compute_risk(
        self,
        synthetic_customer_id: str,
        current_entity_types: list[str],
        current_sensitivity_class: str,
        destination: str,
        purpose: str,
        tenant_id: str,
        window_hours: int = 24,
    ) -> RiskDecomposition:
        """
        Compute the cumulative exposure risk for a synthetic customer.

        R(t) = α·S(t) + β·C(t) + γ·L(t) + δ·D(t)

        Args:
            synthetic_customer_id: Customer identifier (synthetic, non-PII).
            current_entity_types:  List of entity type labels in current request.
            current_sensitivity_class: S0–S4 from sensitivity classifier.
            destination:           Target service/destination.
            purpose:               Processing purpose label.
            tenant_id:             Tenant identifier.
            window_hours:          Time window for historical event inclusion.

        Returns:
            RiskDecomposition with all components and recommended action.
        """
        # --- S(t): Current sensitivity ---
        s = _SENSITIVITY_SCORES.get(current_sensitivity_class, 0.5)

        # --- C(t): Cumulative historical exposure ---
        c = self._compute_cumulative_score(
            synthetic_customer_id, window_hours
        )

        # --- L(t): Cross-request linkability ---
        l = self._compute_linkability_score(
            synthetic_customer_id, current_entity_types, window_hours
        )

        # --- D(t): Destination trust risk ---
        d = self._compute_destination_risk(destination)

        # --- R(t): Weighted sum ---
        r = (
            self._alpha * s
            + self._beta * c
            + self._gamma * l
            + self._delta * d
        )
        r = min(1.0, max(0.0, r))  # Clamp to [0, 1]

        risk_level = self._classify_risk_level(r)
        action = self._recommend_action(risk_level)

        history = self._event_store.get(synthetic_customer_id, [])
        entity_type_history = [et for ev in history for et in ev.entity_types]
        entity_distribution = dict(Counter(entity_type_history))

        return RiskDecomposition(
            sensitivity_score=round(s, 4),
            cumulative_score=round(c, 4),
            linkability_score=round(l, 4),
            destination_trust_score=round(d, 4),
            total_risk_score=round(r, 4),
            risk_level=risk_level,
            contributing_factors={
                "current_sensitivity_class": current_sensitivity_class,
                "historical_event_count": len(history),
                "unique_entity_types_historical": len(entity_distribution),
                "entity_distribution": entity_distribution,
                "destination": destination,
                "destination_trust_raw": 1.0 - d,
                "current_entity_types": current_entity_types,
                "weights": {
                    "alpha_sensitivity": self._alpha,
                    "beta_cumulative": self._beta,
                    "gamma_linkability": self._gamma,
                    "delta_destination": self._delta,
                },
            },
            recommended_action=action,
        )

    def _compute_cumulative_score(
        self, customer_id: str, window_hours: int
    ) -> float:
        """
        C(t): Score based on the quantity and sensitivity of historical disclosures
        within the time window.

        Accumulation model:
          - Each prior disclosure contributes a decaying weight.
          - More recent disclosures contribute more than older ones.
          - Saturates at 1.0 to prevent unbounded growth.
        """
        events = self._get_recent_events(customer_id, window_hours)
        if not events:
            return 0.0

        now = datetime.now(tz=timezone.utc)
        total_contribution = 0.0

        for event in events:
            age_hours = (now - event.occurred_at).total_seconds() / 3600
            time_weight = max(0.0, 1.0 - age_hours / window_hours)

            entity_sensitivity = max(
                _LINKABILITY_WEIGHTS.get(et, 0.3)
                for et in event.entity_types
            ) if event.entity_types else 0.3

            # Already-protected events contribute less to cumulative risk
            protection_factor = 0.3 if event.protection_action in ("TOKENIZE", "ENCRYPT", "MASK") else 0.8

            total_contribution += time_weight * entity_sensitivity * protection_factor

        # Normalize using a logistic-like saturation
        saturation = 1.0 - 1.0 / (1.0 + total_contribution * 0.5)
        return min(1.0, saturation)

    def _compute_linkability_score(
        self,
        customer_id: str,
        current_entity_types: list[str],
        window_hours: int,
    ) -> float:
        """
        L(t): Risk that current disclosure, combined with prior disclosures,
        enables identity linking or correlation.

        Logic:
          - Collect the union of entity types from the time window.
          - Add current entity types.
          - Score based on the maximum linkability weight in the combined set.
          - Apply a multiplier for combinations of high-linkability entities.
        """
        events = self._get_recent_events(customer_id, window_hours)
        historical_types: set[str] = set()
        for event in events:
            historical_types.update(event.entity_types)

        all_types = historical_types | set(current_entity_types)

        if not all_types:
            return 0.0

        # Score individual entity linkability
        type_scores = [_LINKABILITY_WEIGHTS.get(et, 0.3) for et in all_types]
        max_score = max(type_scores)

        # Combination bonus: combining multiple high-linkability entities
        high_link_count = sum(1 for s in type_scores if s >= 0.7)
        combination_bonus = min(0.3, high_link_count * 0.08)

        # New disclosure bonus: entities not seen before
        new_types = set(current_entity_types) - historical_types
        novelty_factor = 0.1 * len(new_types) if new_types else 0.0

        return min(1.0, max_score + combination_bonus + novelty_factor)

    @staticmethod
    def _compute_destination_risk(destination: str | None) -> float:
        """
        D(t): Inverse of destination trust score.
        Higher D = less trusted destination = higher risk.
        """
        if not destination:
            return _DESTINATION_TRUST["unknown"]

        normalized = destination.lower().replace(" ", "_").replace("-", "_")
        trust = _DESTINATION_TRUST.get(normalized)
        if trust is None:
            # Partial match
            for key, val in _DESTINATION_TRUST.items():
                if key in normalized or normalized in key:
                    trust = val
                    break
        if trust is None:
            trust = _DESTINATION_TRUST["external_unknown"]

        return round(1.0 - trust, 4)

    def _get_recent_events(
        self, customer_id: str, window_hours: int
    ) -> list[ExposureEventRecord]:
        """Return events within the time window for a customer."""
        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=window_hours)
        return [
            e for e in self._event_store.get(customer_id, [])
            if e.occurred_at >= cutoff
        ]

    def _classify_risk_level(self, score: float) -> str:
        if score < self._threshold_low:
            return "LOW"
        elif score < self._threshold_medium:
            return "MEDIUM"
        elif score < self._threshold_high:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _recommend_action(risk_level: str) -> str:
        return {
            "LOW": "ALLOW",
            "MEDIUM": "MASK",
            "HIGH": "TOKENIZE",
            "CRITICAL": "BLOCK",
        }.get(risk_level, "BLOCK")

    # ------------------------------------------------------------------ #
    # Research: per-request vs cumulative comparison
    # ------------------------------------------------------------------ #

    def compare_with_perrequest_baseline(
        self,
        events: list[ExposureEventRecord],
        sensitivity_class: str,
        destination: str,
    ) -> dict[str, Any]:
        """
        Demonstrate the difference between per-request and cumulative analysis.

        Per-request baseline: Each event is analyzed independently.
        Cumulative: All events are analyzed together.

        Returns a comparison dict for the security demonstration report.
        """
        customer_id = events[0].synthetic_customer_id if events else "unknown"

        per_request_decisions = []
        for event in events:
            # Fresh engine with no history — simulates per-request baseline
            baseline_engine = CumulativeExposureEngine()
            baseline_score = baseline_engine.compute_risk(
                synthetic_customer_id=customer_id,
                current_entity_types=event.entity_types,
                current_sensitivity_class=sensitivity_class,
                destination=event.destination,
                purpose=event.purpose,
                tenant_id=event.tenant_id,
            )
            per_request_decisions.append({
                "event_index": len(per_request_decisions) + 1,
                "entity_types": event.entity_types,
                "risk_level": baseline_score.risk_level,
                "risk_score": baseline_score.total_risk_score,
                "recommended_action": baseline_score.recommended_action,
            })

        # Now record all events and compute cumulative risk
        for event in events:
            self.record_event(event)

        cumulative_score = self.compute_risk(
            synthetic_customer_id=customer_id,
            current_entity_types=events[-1].entity_types if events else [],
            current_sensitivity_class=sensitivity_class,
            destination=destination,
            purpose=events[-1].purpose if events else "OTHER",
            tenant_id=events[0].tenant_id if events else "default",
        )

        return {
            "per_request_analysis": per_request_decisions,
            "cumulative_analysis": {
                "risk_level": cumulative_score.risk_level,
                "risk_score": cumulative_score.total_risk_score,
                "recommended_action": cumulative_score.recommended_action,
                "contributing_factors": cumulative_score.contributing_factors,
            },
            "escalation_detected": (
                cumulative_score.risk_level != per_request_decisions[-1]["risk_level"]
                if per_request_decisions else False
            ),
        }

    def get_exposure_history(
        self, customer_id: str, limit: int = 50, tenant_filter: Any = None
    ) -> list[dict[str, Any]]:
        """
        Return a safe summary of the exposure history for a synthetic customer.
        No original values — only entity types, actions, and timestamps.
        tenant_filter: optional predicate limiting which tenants' events are returned.
        """
        events = self._event_store.get(customer_id, [])
        if tenant_filter:
            events = [e for e in events if tenant_filter(e.tenant_id)]
        recent = sorted(events, key=lambda e: e.occurred_at, reverse=True)[:limit]
        return [
            {
                "entity_types": e.entity_types,
                "endpoint": e.endpoint,
                "purpose": e.purpose,
                "destination": e.destination,
                "protection_action": e.protection_action,
                "occurred_at": e.occurred_at.isoformat(),
            }
            for e in recent
        ]


# ------------------------------------------------------------------ #
# Module-level singleton
# ------------------------------------------------------------------ #

_exposure_engine: CumulativeExposureEngine | None = None


def get_exposure_engine() -> CumulativeExposureEngine:
    """Return the module-level CumulativeExposureEngine singleton."""
    global _exposure_engine
    if _exposure_engine is None:
        _exposure_engine = CumulativeExposureEngine()
    return _exposure_engine
