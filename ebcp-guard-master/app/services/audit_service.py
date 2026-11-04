"""EBCP-Guard Audit Service — hash chain management."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any
from app.cryptography.audit_integrity import (
    build_safe_audit_metadata, compute_event_hash, GENESIS_HASH
)
from app.core.logging import get_logger

logger = get_logger(__name__)

# In-memory chain state (per tenant) — replaced by DB queries in production
_chain_state: dict[str, tuple[str, int]] = {}  # tenant_id → (last_hash, sequence)


async def record_audit_event(
    request_id: str | None,
    tenant_id: str,
    synthetic_customer_id: str | None,
    event_type: str,
    entity_types: list[str],
    sensitivity_class: str | None,
    protection_action: str | None,
    risk_score: float | None,
    model_versions: dict[str, str] | None = None,
) -> tuple[str, str]:
    """
    Create and store an audit event in the hash chain.
    Returns (event_id, current_hash).
    """
    event_id = str(uuid.uuid4())
    prev_hash, seq = _chain_state.get(tenant_id, (GENESIS_HASH, 0))

    metadata = build_safe_audit_metadata(
        request_id=request_id,
        tenant_id=tenant_id,
        synthetic_customer_id=synthetic_customer_id,
        event_type=event_type,
        entity_types=entity_types,
        sensitivity_class=sensitivity_class,
        protection_action=protection_action,
        risk_score=risk_score,
        model_versions=model_versions,
    )

    current_hash = compute_event_hash(prev_hash, metadata)
    new_seq = seq + 1
    _chain_state[tenant_id] = (current_hash, new_seq)

    # Persist to DB (async, non-blocking for now)
    try:
        from app.database.models import AuditEvent
        await AuditEvent.create(
            event_id=event_id,
            request_id=request_id,
            tenant_id=tenant_id,
            synthetic_customer_id=synthetic_customer_id,
            event_type=event_type,
            safe_metadata=metadata,
            previous_hash=prev_hash,
            current_hash=current_hash,
            sequence_number=new_seq,
        )
    except Exception as exc:
        logger.warning("audit_db_write_failed", event_id=event_id, error=str(exc))

    return event_id, current_hash
