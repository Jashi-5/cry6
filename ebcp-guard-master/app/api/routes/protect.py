"""Protect endpoint."""
from fastapi import APIRouter, Depends
from app.api.schemas.schemas import ProtectRequest, ProtectResponse
from app.core.auth import ServiceIdentity, require_service_outside_development, require_tenant
from app.services.protection_service import run_protection

router = APIRouter()

@router.post("/protect", response_model=ProtectResponse)
async def protect(
    request: ProtectRequest,
    service: ServiceIdentity | None = Depends(require_service_outside_development),
) -> ProtectResponse:
    """
    Analyze and apply cryptographic protection to a payload.
    Returns the sanitized/protected payload with audit trail reference.
    """
    if service:
        require_tenant(service, request.tenant_id)
    return await run_protection(request)
