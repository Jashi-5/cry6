"""
EBCP-Guard FastAPI Application Entry Point
===========================================
Initializes the FastAPI application with:
  - Tortoise ORM database connection.
  - AI model loading via lifespan.
  - Structured logging.
  - CORS middleware.
  - Request size limits.
  - Centralized exception handling.
  - All API routers.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from tortoise import Tortoise

from app.config import get_settings
from app.core.exceptions import (
    AuthenticationTagError,
    EBCPGuardError,
    ModelNotLoadedError,
    PayloadTooLargeError,
    PolicyBlockedError,
    UnauthorizedDecryptionError,
    UnauthorizedServiceError,
)
from app.core.logging import configure_logging, get_logger
from app.api.routes import health, analyze, protect, tokenize, audit, exposure, metrics, simulate, decrypt

logger = get_logger(__name__)
settings = get_settings()

# ------------------------------------------------------------------ #
# Database configuration for Tortoise ORM
# ------------------------------------------------------------------ #

TORTOISE_ORM = {
    "connections": {
        "default": settings.database_url,
    },
    "apps": {
        "models": {
            "models": ["app.database.models"],
            "default_connection": "default",
        },
    },
}


# ------------------------------------------------------------------ #
# Application lifespan (startup / shutdown)
# ------------------------------------------------------------------ #

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    Handles startup (model loading, DB init) and shutdown (cleanup).
    """
    configure_logging()
    logger.info("ebcp_guard_starting", version=settings.app_version, env=settings.app_env)

    # Initialize Tortoise ORM
    try:
        await Tortoise.init(config=TORTOISE_ORM)
        await Tortoise.generate_schemas()
        logger.info("tortoise_db_initialized")
    except Exception as exc:
        logger.warning("tortoise_db_init_skipped_or_failed", error=str(exc))

    # Lazy model loading — models imported here to avoid import-time GPU allocation
    from app.nlp.model_loader import get_model_registry
    model_registry = get_model_registry()
    await model_registry.load_all_models()
    logger.info("models_loaded", all_ready=model_registry.all_ready)

    yield  # Application runs here

    try:
        await Tortoise.close_connections()
    except Exception:
        pass
    logger.info("ebcp_guard_shutdown")


# ------------------------------------------------------------------ #
# FastAPI application instance
# ------------------------------------------------------------------ #

def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="EBCP-Guard",
        description=(
            "Exposure-Budgeted Cryptographic Protection Framework — "
            "AI-Powered Context-Aware Sensitive Data Leakage Prevention"
        ),
        version=settings.app_version,
        docs_url="/docs" if settings.is_development() else None,
        redoc_url="/redoc" if settings.is_development() else None,
        lifespan=lifespan,
    )

    # --- CORS ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Exception handlers ---
    _register_exception_handlers(app)

    # --- Routers ---
    prefix = settings.api_prefix
    app.include_router(health.router, prefix=prefix, tags=["Health"])
    app.include_router(analyze.router, prefix=prefix, tags=["Analysis"])
    app.include_router(protect.router, prefix=prefix, tags=["Protection"])
    app.include_router(tokenize.router, prefix=prefix, tags=["Tokenization"])
    app.include_router(audit.router, prefix=prefix, tags=["Audit"])
    app.include_router(exposure.router, prefix=prefix, tags=["Exposure"])
    app.include_router(metrics.router, prefix=prefix, tags=["Metrics"])
    app.include_router(simulate.router, prefix=prefix, tags=["Simulation"])
    app.include_router(decrypt.router, prefix=prefix, tags=["Decryption"])

    # --- Static & Root UI ---
    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        @app.get("/", include_in_schema=False)
        async def root_ui():
            """Serve the EBCP-Guard scroll story."""
            return FileResponse(str(static_dir / "index.html"))

        @app.get("/app", include_in_schema=False)
        async def dashboard_ui():
            """Serve the working dashboard."""
            return FileResponse(str(static_dir / "app.html"))

    return app


# ------------------------------------------------------------------ #
# Exception handlers
# ------------------------------------------------------------------ #

def _register_exception_handlers(app: FastAPI) -> None:
    """Register centralized exception handlers."""

    @app.exception_handler(PolicyBlockedError)
    async def policy_blocked_handler(request: Request, exc: PolicyBlockedError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error_code": "POLICY_BLOCKED", "message": exc.detail},
        )

    @app.exception_handler(UnauthorizedDecryptionError)
    async def unauth_decrypt_handler(request: Request, exc: UnauthorizedDecryptionError) -> JSONResponse:
        logger.warning("unauthorized_decryption_attempt", path=str(request.url))
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error_code": "UNAUTHORIZED_DECRYPTION", "message": exc.detail},
        )

    @app.exception_handler(UnauthorizedServiceError)
    async def unauth_service_handler(request: Request, exc: UnauthorizedServiceError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error_code": "UNAUTHORIZED_SERVICE", "message": exc.detail},
        )

    @app.exception_handler(AuthenticationTagError)
    async def auth_tag_handler(request: Request, exc: AuthenticationTagError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error_code": "CIPHERTEXT_TAMPERED", "message": exc.detail},
        )

    @app.exception_handler(ModelNotLoadedError)
    async def model_not_loaded_handler(request: Request, exc: ModelNotLoadedError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error_code": "MODEL_UNAVAILABLE", "message": exc.detail},
        )

    @app.exception_handler(PayloadTooLargeError)
    async def payload_too_large_handler(request: Request, exc: PayloadTooLargeError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"error_code": "PAYLOAD_TOO_LARGE", "message": exc.detail},
        )

    @app.exception_handler(EBCPGuardError)
    async def general_error_handler(request: Request, exc: EBCPGuardError) -> JSONResponse:
        logger.error("application_error", error=exc.detail, path=str(request.url))
        return JSONResponse(
            status_code=exc.status_code,
            content={"error_code": type(exc).__name__.upper(), "message": exc.detail},
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_exception", path=str(request.url), error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error_code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred. Please check the application logs.",
            },
        )


app = create_application()
