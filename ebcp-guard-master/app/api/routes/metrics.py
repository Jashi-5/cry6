"""Models status and evaluation report endpoints."""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends
from app.api.schemas.schemas import ModelStatusResponse
from app.config import BASE_DIR, get_settings
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


@router.get("/evaluation")
async def evaluation() -> dict:
    """The stored test reports, so pages show these numbers rather than a copy of them."""
    reports = BASE_DIR / "dataset" / "reports"
    return {
        "head_to_head": json.loads((reports / "head_to_head_report.json").read_text(encoding="utf-8")),
        "model_evaluation": json.loads((reports / "model_evaluation_report.json").read_text(encoding="utf-8")),
    }
