"""Analyze endpoint."""
from fastapi import APIRouter
from app.api.schemas.schemas import AnalyzeRequest, AnalyzeResponse
from app.services.analysis_service import run_analysis

router = APIRouter()

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze an API payload for sensitive entities, classify sensitivity and purpose,
    score cumulative exposure risk, and recommend a protection action.
    The original payload is processed transiently and never persisted.
    """
    return await run_analysis(request)
