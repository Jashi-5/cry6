"""Exposure history endpoint."""
from fastapi import APIRouter, Path
from app.api.schemas.schemas import ExposureHistoryResponse, ExposureScoreSchema, RiskLevel
from app.exposure.cumulative_exposure_engine import get_exposure_engine

router = APIRouter()

@router.get("/exposure/{customer_id}", response_model=ExposureHistoryResponse)
async def get_exposure_history(
    customer_id: str = Path(..., description="Synthetic customer identifier (not real PII)")
) -> ExposureHistoryResponse:
    """
    Return the cumulative exposure history for a synthetic customer.
    Uses protected identifiers only — no original PII.
    """
    engine = get_exposure_engine()
    history = engine.get_exposure_history(customer_id, limit=50)

    from collections import Counter
    entity_types = [et for evt in history for et in evt.get("entity_types", [])]
    distribution = dict(Counter(entity_types))

    # Compute current risk
    current_risk = None
    if history:
        risk = engine.compute_risk(
            synthetic_customer_id=customer_id,
            current_entity_types=[],
            current_sensitivity_class="S0",
            destination="unknown",
            purpose="OTHER",
            tenant_id="default",
        )
        current_risk = ExposureScoreSchema(
            sensitivity_score=risk.sensitivity_score,
            cumulative_score=risk.cumulative_score,
            linkability_score=risk.linkability_score,
            destination_trust_score=risk.destination_trust_score,
            total_risk_score=risk.total_risk_score,
            risk_level=RiskLevel(risk.risk_level),
            contributing_factors=risk.contributing_factors,
        )

    return ExposureHistoryResponse(
        synthetic_customer_id=customer_id,
        tenant_id="default",
        total_events=len(history),
        current_risk_score=current_risk,
        recent_events=history,
        entity_type_distribution=distribution,
    )
