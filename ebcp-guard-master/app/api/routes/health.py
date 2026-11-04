"""Health check endpoint."""
from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter
from tortoise import Tortoise
from app.api.schemas.schemas import HealthResponse
from app.config import get_settings
from app.nlp.model_loader import get_model_registry

router = APIRouter()
settings = get_settings()

@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return application health status."""
    db_status = "unknown"
    try:
        if getattr(Tortoise, "_inited", False):
            conn = Tortoise.get_connection("default")
            await conn.execute_query("SELECT 1")
            db_status = "healthy"
        else:
            db_status = "uninitialized"
    except Exception:
        db_status = "unhealthy"

    registry = get_model_registry()
    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        version=settings.app_version,
        database=db_status,
        models_loaded=registry.all_ready,
        timestamp=datetime.now(tz=timezone.utc),
    )
