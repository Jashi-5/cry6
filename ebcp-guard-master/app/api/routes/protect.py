"""Protect endpoint."""
from fastapi import APIRouter
from app.api.schemas.schemas import ProtectRequest, ProtectResponse
from app.services.protection_service import run_protection

router = APIRouter()

@router.post("/protect", response_model=ProtectResponse)
async def protect(request: ProtectRequest) -> ProtectResponse:
    """
    Analyze and apply cryptographic protection to a payload.
    Returns the sanitized/protected payload with audit trail reference.
    """
    return await run_protection(request)
