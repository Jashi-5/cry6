"""
EBCP-Guard Adaptive Privacy Policy Engine Tests
=================================================
Tests:
  - Deterministic policy rule execution
  - Blocked destination enforcement
  - Low-confidence model handling (conservative fallback)
  - Tenant policy overrides
"""

import pytest

from app.policy.policy_engine import PolicyEngine
from app.api.schemas.schemas import ProtectionAction

def test_unauthorized_destination_blocked():
    engine = PolicyEngine()
    decision = engine.evaluate(
        entities=[{"entity_type": "PAN", "confidence": 0.95}],
        sensitivity_class="S4",
        sensitivity_confidence=0.95,
        purpose="PAYMENT_PROCESSING",
        purpose_confidence=0.95,
        exposure_risk_level="HIGH",
        exposure_risk_score=0.70,
        destination="external_unknown",
        tenant_id="bank_a",
    )
    assert decision.is_blocked is True
    assert decision.overall_action == ProtectionAction.BLOCK

def test_low_confidence_triggers_conservative_handling():
    engine = PolicyEngine()
    # Confidence 0.20 is below threshold (0.75)
    decision = engine.evaluate(
        entities=[{"entity_type": "EMAIL", "confidence": 0.90}],
        sensitivity_class="S1",
        sensitivity_confidence=0.20,
        purpose="PAYMENT_PROCESSING",
        purpose_confidence=0.90,
        exposure_risk_level="LOW",
        exposure_risk_score=0.20,
        destination="internal_payment",
        tenant_id="bank_a",
    )
    # Must flag for review and upgrade protection
    assert decision.requires_review is True
    assert decision.overall_action in (
        ProtectionAction.MASK, ProtectionAction.TOKENIZE,
        ProtectionAction.ENCRYPT, ProtectionAction.BLOCK
    )

def test_legitimate_payment_encrypted():
    engine = PolicyEngine()
    decision = engine.evaluate(
        entities=[{"entity_type": "ACCOUNT_NUMBER", "confidence": 0.95}],
        sensitivity_class="S4",
        sensitivity_confidence=0.95,
        purpose="PAYMENT_PROCESSING",
        purpose_confidence=0.95,
        exposure_risk_level="MEDIUM",
        exposure_risk_score=0.40,
        destination="internal_payment",
        tenant_id="bank_a",
    )
    assert decision.overall_action == ProtectionAction.ENCRYPT


def _evaluate_destination(destination):
    return PolicyEngine().evaluate(
        entities=[{"entity_type": "PAN", "confidence": 0.95}],
        sensitivity_class="S4",
        sensitivity_confidence=0.95,
        purpose="PAYMENT_PROCESSING",
        purpose_confidence=0.95,
        exposure_risk_level="MEDIUM",
        exposure_risk_score=0.40,
        destination=destination,
        tenant_id="bank_a",
    )

@pytest.mark.parametrize("destination", [
    "untrusted_external",
    "untrusted_third_party",
    "untrusted-third-party",
    "Untrusted Third Party",
    "external_unknown",
    "marketing_external",
    "evil_corp_exfil",
    "unknown",
    "",
    None,
])
def test_unlisted_destination_fails_closed(destination):
    decision = _evaluate_destination(destination)
    assert decision.is_blocked is True
    assert decision.overall_action == ProtectionAction.BLOCK

@pytest.mark.parametrize("destination", [
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
    "Internal Payment",
    "internal-payment",
])
def test_known_destination_not_blocked(destination):
    decision = _evaluate_destination(destination)
    assert decision.is_blocked is False
    assert decision.overall_action != ProtectionAction.BLOCK
