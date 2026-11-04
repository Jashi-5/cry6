"""
EBCP-Guard Structured Logging
==============================
Configures structlog for structured, context-aware application logging.

Security contract:
  - Log messages MUST NOT contain original PII or sensitive field values.
  - Log ONLY: request_id, synthetic_customer_id, entity_type labels,
    risk scores, protection decisions, and safe metadata.
  - Any function logging a sensitive value violates this contract.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

from app.config import get_settings


def _censor_sensitive_keys(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """
    Structlog processor that redacts any key whose name suggests it
    may carry sensitive data.  This is a safety net — the primary
    contract is that callers never pass PII to log calls.
    """
    FORBIDDEN_KEYS = {
        "password", "passwd", "secret", "key", "token",
        "account_number", "card_number", "cvv", "pin",
        "aadhaar", "pan", "ssn", "dob", "email", "phone",
        "address", "name", "customer_name",
    }
    for key in list(event_dict.keys()):
        if key.lower() in FORBIDDEN_KEYS:
            event_dict[key] = "[REDACTED]"
    return event_dict


def configure_logging() -> None:
    """Configure structlog and stdlib logging for the application."""
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        _censor_sensitive_keys,
    ]

    if settings.is_development():
        # Pretty console output for development
        renderer: Any = structlog.dev.ConsoleRenderer()
    else:
        # JSON output for production log aggregation
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level)

    # Suppress noisy third-party loggers
    for noisy in ["asyncio", "aiohttp", "multipart"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a named structured logger."""
    return structlog.get_logger(name)
