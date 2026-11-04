"""Models status endpoint."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from app.api.schemas.schemas import ModelStatusResponse
from app.config import get_settings
from app.core.auth import ServiceIdentity, require_service
from app.nlp.model_loader import get_model_registry

router = APIRouter()
settings = get_settings()

@router.get("/models/status", response_model=ModelStatusResponse)
async def models_status(service: ServiceIdentity = Depends(require_service)) -> ModelStatusResponse:
    """Return status of all loaded AI models."""
    registry = get_model_registry()
    return ModelStatusResponse(
        models=registry.status_report(),
        device=settings.model_device,
        all_ready=registry.all_ready,
    )
