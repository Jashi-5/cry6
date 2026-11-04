"""EBCP-Guard Audit Service — hash chain management."""
from __future__ import annotations
import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any
from app.config import get_settings
from app.cryptography.audit_integrity import (
    build_safe_audit_metadata, compute_event_hash, GENESIS_HASH
)
from app.cryptography.key_manager import get_key_manager
from app.core.logging import get_logger

logger = get_logger(__name__)

# ponytail: one lock and one local checkpoint file assume a single server process.
# Multiple workers need a database lock, and real tamper resistance needs the
# checkpoint shipped to storage the database's operators cannot change.
_chain_lock = asyncio.Lock()


def _read_checkpoints() -> dict[str, Any]:
    path = Path(get_settings().audit_checkpoint_path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _advance_checkpoint(tenant_id: str, prev: tuple[str, int], new: tuple[str, int]) -> None:
    """
    Record the newest event outside the database.

    If the database no longer ends where the checkpoint says, events were removed.
    The checkpoint then stays frozen, so verification keeps failing however much
    new traffic is built on the shortened chain.
    """
    checkpoints = _read_checkpoints()
    current = checkpoints.get(tenant_id)
    if current and (current["hash"], current["sequence"]) != prev:
        logger.error("audit_checkpoint_mismatch", tenant_id=tenant_id, checkpoint_sequence=current["sequence"])
        return
    checkpoints[tenant_id] = {"hash": new[0], "sequence": new[1]}
    path = Path(get_settings().audit_checkpoint_path)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(checkpoints), encoding="utf-8")
    os.replace(temp, path)


def checkpoint_failure(tenant_id: str, events: list[dict[str, Any]]) -> int | None:
    """Return the checkpointed sequence if the chain no longer contains that event."""
    checkpoint = _read_checkpoints().get(tenant_id)
    if not checkpoint:
        return None
    present = any(
        e["sequence_number"] == checkpoint["sequence"] and e["current_hash"] == checkpoint["hash"]
        for e in events
    )
    return None if present else checkpoint["sequence"]


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
    The chain continues from the database, so it survives restarts.
    Returns (event_id, current_hash).
    """
    from app.database.models import AuditEvent

    event_id = str(uuid.uuid4())
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
    audit_key = get_key_manager().derive_audit_key(tenant_id)

    # Held across read and write, so concurrent requests cannot fork the chain.
    async with _chain_lock:
        prev_hash, seq = GENESIS_HASH, 0
        try:
            last = await AuditEvent.filter(tenant_id=tenant_id).order_by("-sequence_number").first()
            if last:
                prev_hash, seq = last.current_hash, last.sequence_number
        except Exception as exc:
            logger.warning("audit_db_read_failed", event_id=event_id, error=str(exc))

        current_hash = compute_event_hash(prev_hash, metadata, audit_key)
        new_seq = seq + 1

        try:
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
            _advance_checkpoint(tenant_id, (prev_hash, seq), (current_hash, new_seq))
        except Exception as exc:
            logger.warning("audit_db_write_failed", event_id=event_id, error=str(exc))

    return event_id, current_hash
