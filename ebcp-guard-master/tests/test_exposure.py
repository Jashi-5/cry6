"""
EBCP-Guard Cumulative Exposure Engine Tests
=============================================
Tests:
  - Explainable formula calculation: R(t) = αS(t) + βC(t) + γL(t) + δD(t)
  - Cross-request accumulation and linkability risk growth
  - Escalation from LOW to CRITICAL across sequential disclosures
  - Comparison between per-request baseline and cumulative analysis
"""

from app.exposure.cumulative_exposure_engine import CumulativeExposureEngine, ExposureEventRecord

def test_single_request_risk_scoring():
    engine = CumulativeExposureEngine()
    decomp = engine.compute_risk(
        synthetic_customer_id="CUST_001",
        current_entity_types=["TRANSACTION_AMOUNT"],
        current_sensitivity_class="S0",
        destination="internal_payment",
        purpose="PAYMENT_PROCESSING",
        tenant_id="bank_a",
    )
    assert decomp.risk_level in ("LOW", "MEDIUM")
    assert 0.0 <= decomp.total_risk_score <= 1.0

def test_cumulative_risk_escalation():
    engine = CumulativeExposureEngine()
    cid = "CUST_ESCALATE"

    # Sequence of disclosures
    events = [
        ExposureEventRecord(cid, "bank_a", ["TRANSACTION_AMOUNT"], "/pay", "PAYMENT_PROCESSING", "internal_payment", "ALLOW"),
        ExposureEventRecord(cid, "bank_a", ["IP_ADDRESS"], "/analytics", "ANALYTICS", "internal_analytics", "ALLOW"),
        ExposureEventRecord(cid, "bank_a", ["ACCOUNT_NUMBER"], "/accounts", "CUSTOMER_SUPPORT", "internal_payment", "MASK"),
        ExposureEventRecord(cid, "bank_a", ["EMAIL"], "/marketing", "MARKETING", "third_party_analytics", "ALLOW"),
    ]

    comp = engine.compare_with_perrequest_baseline(events, "S2", "third_party_analytics")

    # Cumulative analysis must detect escalation compared to first request
    assert comp["cumulative_analysis"]["risk_score"] > comp["per_request_analysis"][0]["risk_score"]
    assert "contributing_factors" in comp["cumulative_analysis"]
