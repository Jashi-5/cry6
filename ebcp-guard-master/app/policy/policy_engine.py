"""
EBCP-Guard Adaptive Privacy Policy Engine
==========================================
Deterministic rule-based policy engine that integrates:
  - NLP model predictions (sensitivity, purpose).
  - Cumulative exposure risk score.
  - Destination authorization.
  - Tenant-specific policy configuration.

CRITICAL DESIGN PRINCIPLE:
  Model predictions inform but NEVER authorize.
  All final decisions are deterministic, rule-based, and configurable.
  Low-confidence predictions always trigger conservative handling.
  Unknown or unavailable components → fail closed (BLOCK or QUARANTINE).

Decision outputs:
  ALLOW      → Pass through without modification.
  MASK       → Apply format-preserving masking per entity type.
  TOKENIZE   → Replace with HMAC-scoped pseudonymization token.
  ENCRYPT    → Apply AES-256-GCM reversible encryption.
  BLOCK      → Reject the request entirely.
  QUARANTINE → Hold for manual review.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.api.schemas.schemas import (
    ProtectionAction,
    ProcessingPurpose,
    SensitivityClass,
    RiskLevel,
)
from app.config import get_settings
from app.core.exceptions import PolicyError
from app.core.logging import get_logger

logger = get_logger(__name__)

# ------------------------------------------------------------------ #
# Per-entity type policy rules
# ------------------------------------------------------------------ #

# Maps (sensitivity_class, risk_level) → action
# This is the base policy table. Tenant overrides are applied on top.
_ENTITY_TYPE_BASE_POLICY: dict[str, dict[str, str]] = {
    # Critical identifying information — always tokenize or encrypt
    "PAN":            {"S4": "ENCRYPT", "S3": "TOKENIZE", "S2": "MASK", "S1": "MASK",   "S0": "ALLOW"},
    "AADHAAR":        {"S4": "ENCRYPT", "S3": "TOKENIZE", "S2": "MASK", "S1": "MASK",   "S0": "ALLOW"},
    "CARD_NUMBER":    {"S4": "ENCRYPT", "S3": "TOKENIZE", "S2": "MASK", "S1": "MASK",   "S0": "ALLOW"},
    "ACCOUNT_NUMBER": {"S4": "ENCRYPT", "S3": "TOKENIZE", "S2": "MASK", "S1": "MASK",   "S0": "ALLOW"},
    "EMAIL":          {"S4": "TOKENIZE","S3": "TOKENIZE", "S2": "MASK", "S1": "ALLOW",  "S0": "ALLOW"},
    "PHONE":          {"S4": "TOKENIZE","S3": "TOKENIZE", "S2": "MASK", "S1": "ALLOW",  "S0": "ALLOW"},
    "UPI_ID":         {"S4": "TOKENIZE","S3": "TOKENIZE", "S2": "MASK", "S1": "ALLOW",  "S0": "ALLOW"},
    "PERSON":         {"S4": "MASK",    "S3": "MASK",     "S2": "MASK", "S1": "ALLOW",  "S0": "ALLOW"},
    "ADDRESS":        {"S4": "MASK",    "S3": "MASK",     "S2": "MASK", "S1": "ALLOW",  "S0": "ALLOW"},
    "DATE_OF_BIRTH":  {"S4": "TOKENIZE","S3": "MASK",     "S2": "MASK", "S1": "ALLOW",  "S0": "ALLOW"},
    "IFSC":           {"S4": "MASK",    "S3": "MASK",     "S2": "ALLOW","S1": "ALLOW",  "S0": "ALLOW"},
    "GST_NUMBER":     {"S4": "TOKENIZE","S3": "MASK",     "S2": "ALLOW","S1": "ALLOW",  "S0": "ALLOW"},
    "TRANSACTION_AMOUNT":{"S4":"MASK",  "S3": "ALLOW",    "S2": "ALLOW","S1": "ALLOW",  "S0": "ALLOW"},
    "IP_ADDRESS":     {"S4": "MASK",    "S3": "MASK",     "S2": "ALLOW","S1": "ALLOW",  "S0": "ALLOW"},
}

# Purpose → maximum permitted action (most permissive allowed per purpose)
_PURPOSE_MAX_ALLOWED_ACTION: dict[str, str] = {
    "PAYMENT_PROCESSING": "ENCRYPT",     # May need full value for processing
    "FRAUD_DETECTION":    "ENCRYPT",     # May need full value for scoring
    "AUTHENTICATION":     "TOKENIZE",    # Stable pseudonym sufficient
    "CUSTOMER_SUPPORT":   "MASK",        # Show partial info only
    "ANALYTICS":          "TOKENIZE",    # No original values needed
    "MARKETING":          "MASK",        # Strict — no full PII
    "REPORTING":          "TOKENIZE",
    "OTHER":              "MASK",
}

# Known destinations. Anything else, or no destination at all, fails closed to BLOCK.
_ALLOWED_DESTINATIONS = {
    "internal_payment",
    "payment_gateway",
    "fraud_service",
    "authentication",
    "internal_analytics",
    "third_party_analytics",
    "marketing",
    "marketing_crm",
    "marketing_platform",
    "application_logs",
    "support_portal",
}

# Action severity ordering (for upgrade/downgrade comparisons)
_ACTION_SEVERITY = {
    "ALLOW": 0,
    "MASK": 1,
    "TOKENIZE": 2,
    "ENCRYPT": 3,
    "QUARANTINE": 4,
    "BLOCK": 5,
}


def _most_restrictive(action_a: str, action_b: str) -> str:
    """Return the more restrictive of two protection actions."""
    return action_a if _ACTION_SEVERITY.get(action_a, 0) >= _ACTION_SEVERITY.get(action_b, 0) else action_b


@dataclass
class EntityDecision:
    """Policy decision for a single detected entity."""
    entity_type: str
    confidence: float
    sensitivity_class: str
    action: ProtectionAction
    policy_rule: str
    requires_validation: bool = False


@dataclass
class PolicyDecision:
    """Overall policy decision for a request."""
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    overall_action: ProtectionAction = ProtectionAction.BLOCK
    entity_decisions: list[EntityDecision] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    policy_rule_triggered: str = "default_block"
    is_blocked: bool = False
    block_reason: str | None = None
    requires_review: bool = False
    decided_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


class PolicyEngine:
    """
    Deterministic adaptive privacy policy engine.

    Inputs:
      - Detected entities (types + confidence scores).
      - Sensitivity prediction (S0–S4 + confidence).
      - Purpose prediction (purpose label + confidence).
      - Cumulative exposure risk score (RiskDecomposition).
      - Destination service identifier.
      - Tenant policy configuration.

    Output:
      PolicyDecision — deterministic, auditable, non-bypassable by models.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._confidence_threshold = settings.model_confidence_threshold
        self._low_confidence_action = settings.low_confidence_action
        self._fail_closed = settings.fail_closed

    def evaluate(
        self,
        entities: list[dict[str, Any]],
        sensitivity_class: str,
        sensitivity_confidence: float,
        purpose: str,
        purpose_confidence: float,
        exposure_risk_level: str,
        exposure_risk_score: float,
        destination: str | None,
        tenant_id: str,
        tenant_policy: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Evaluate the complete privacy policy for a request.

        Args:
            entities:               List of detected entity dicts with type/confidence.
            sensitivity_class:      S0–S4 from classifier.
            sensitivity_confidence: Confidence score for sensitivity prediction.
            purpose:                Processing purpose label.
            purpose_confidence:     Confidence score for purpose prediction.
            exposure_risk_level:    LOW/MEDIUM/HIGH/CRITICAL from exposure engine.
            exposure_risk_score:    Numeric score [0, 1].
            destination:            Target service/destination identifier.
            tenant_id:              Tenant identifier.
            tenant_policy:          Optional tenant-specific policy overrides.

        Returns:
            PolicyDecision with overall action and per-entity decisions.
        """

        decision = PolicyDecision()
        decision.risk_score = exposure_risk_score
        decision.risk_level = RiskLevel(exposure_risk_level)

        # --- Step 1: Fail closed on any destination not explicitly known ---
        dest_normalized = (destination or "unknown").strip().lower().replace(" ", "_").replace("-", "_")
        if dest_normalized not in _ALLOWED_DESTINATIONS:
            logger.warning(
                "policy_blocked_destination",
                destination=destination,
                tenant_id=tenant_id,
            )
            decision.overall_action = ProtectionAction.BLOCK
            decision.is_blocked = True
            decision.block_reason = f"Destination '{destination}' is not authorized."
            decision.policy_rule_triggered = "blocked_destination"
            return decision

        # --- Step 2: Handle low-confidence model predictions ---
        if sensitivity_confidence < self._confidence_threshold:
            logger.warning(
                "policy_low_confidence_sensitivity",
                confidence=sensitivity_confidence,
                threshold=self._confidence_threshold,
                fallback_action=self._low_confidence_action,
            )
            if self._fail_closed:
                # Upgrade sensitivity class to S3 conservatively
                effective_class = "S3"
                decision.requires_review = True
            else:
                effective_class = sensitivity_class
        else:
            effective_class = sensitivity_class

        if purpose_confidence < self._confidence_threshold:
            logger.warning(
                "policy_low_confidence_purpose",
                confidence=purpose_confidence,
                fallback_purpose="OTHER",
            )
            effective_purpose = "OTHER"
            decision.requires_review = True
        else:
            effective_purpose = purpose

        # --- Step 3: Determine risk-level-driven base action ---
        risk_based_action = self._action_from_risk_level(exposure_risk_level)

        # --- Step 4: Per-entity decisions ---
        entity_decisions: list[EntityDecision] = []
        max_action = risk_based_action

        for entity in entities:
            entity_type = entity.get("entity_type", "UNKNOWN")
            confidence = entity.get("confidence", 0.0)

            # Low-confidence entity detection → be conservative
            if confidence < 0.50:
                entity_action_str = "TOKENIZE"
                rule = "low_confidence_entity_conservative"
            else:
                # Look up base policy for this entity type + sensitivity class
                entity_policy = _ENTITY_TYPE_BASE_POLICY.get(entity_type, {})
                entity_action_str = entity_policy.get(effective_class, "TOKENIZE")
                rule = f"base_policy_{entity_type}_{effective_class}"

            # Apply purpose-based constraint
            purpose_max = _PURPOSE_MAX_ALLOWED_ACTION.get(effective_purpose, "MASK")
            # Can't be more permissive than what the purpose allows
            entity_action_str = _most_restrictive(entity_action_str, purpose_max)

            # Apply risk-level escalation
            entity_action_str = _most_restrictive(entity_action_str, risk_based_action)

            # Apply tenant policy overrides if provided
            if tenant_policy:
                override = self._apply_tenant_override(
                    entity_type, entity_action_str, tenant_policy
                )
                if override != entity_action_str:
                    entity_action_str = override
                    rule += "_tenant_override"

            entity_action = ProtectionAction(entity_action_str)
            max_action = _most_restrictive(max_action, entity_action_str)

            entity_decisions.append(EntityDecision(
                entity_type=entity_type,
                confidence=confidence,
                sensitivity_class=effective_class,
                action=entity_action,
                policy_rule=rule,
            ))

        decision.entity_decisions = entity_decisions
        decision.overall_action = ProtectionAction(max_action)
        decision.policy_rule_triggered = f"risk_{exposure_risk_level}_purpose_{effective_purpose}"
        decision.is_blocked = max_action == "BLOCK"
        if decision.is_blocked:
            decision.block_reason = f"Risk level {exposure_risk_level} with entities requiring maximum protection."

        logger.info(
            "policy_decision",
            overall_action=decision.overall_action,
            risk_level=exposure_risk_level,
            entity_count=len(entity_decisions),
            requires_review=decision.requires_review,
        )

        return decision

    @staticmethod
    def _action_from_risk_level(risk_level: str) -> str:
        """Map exposure risk level to minimum required protection action."""
        return {
            "LOW": "ALLOW",
            "MEDIUM": "MASK",
            "HIGH": "TOKENIZE",
            "CRITICAL": "BLOCK",
        }.get(risk_level, "BLOCK")

    @staticmethod
    def _apply_tenant_override(
        entity_type: str,
        current_action: str,
        tenant_policy: dict[str, Any],
    ) -> str:
        """
        Apply tenant-specific entity permission overrides.
        Tenant overrides can only be MORE restrictive than the base policy —
        they cannot be used to loosen protections below the base policy level.
        """
        entity_overrides = tenant_policy.get("entity_permissions", {})
        override_action = entity_overrides.get(entity_type)
        if override_action:
            return _most_restrictive(current_action, override_action)
        return current_action


# Module-level singleton
_policy_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    """Return cached PolicyEngine singleton."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine
