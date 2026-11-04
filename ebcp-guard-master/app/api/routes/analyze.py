"""Analyze endpoint."""
from fastapi import APIRouter, Depends
from app.api.schemas.schemas import AnalyzeRequest, AnalyzeResponse
from app.core.auth import ServiceIdentity, require_service_outside_development, require_tenant
from app.services.analysis_service import run_analysis

router = APIRouter()

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    service: ServiceIdentity | None = Depends(require_service_outside_development),
) -> AnalyzeResponse:
    """
    Analyze an API payload for sensitive entities, classify sensitivity and purpose,
    score cumulative exposure risk, and recommend a protection action.
    The original payload is processed transiently and never persisted.
    """
    if service:
        require_tenant(service, request.tenant_id)
    return await run_analysis(request)
