"""Audit verification endpoint."""
from datetime import datetime, timezone
from fastapi import APIRouter
from app.api.schemas.schemas import VerifyAuditRequest, VerifyAuditResponse
from app.cryptography.audit_integrity import verify_chain, build_merkle_tree, GENESIS_HASH

router = APIRouter()

@router.post("/verify-audit", response_model=VerifyAuditResponse)
async def verify_audit(request: VerifyAuditRequest) -> VerifyAuditResponse:
    """
    Verify the integrity of the audit hash chain using PostgreSQL records.
    Detects any tampering with audit events.
    """
    from app.database.models import AuditEvent
    from tortoise.expressions import Q

    query = AuditEvent.filter(tenant_id=request.tenant_id)
    if request.batch_id is not None:
        query = query.filter(batch_id=request.batch_id)
    if request.start_sequence is not None:
        query = query.filter(sequence_number__gte=request.start_sequence)
    if request.end_sequence is not None:
        query = query.filter(sequence_number__lte=request.end_sequence)

    events = await query.order_by("sequence_number").values(
        "event_id", "previous_hash", "current_hash",
        "safe_metadata", "sequence_number"
    )

    is_valid, failed_seq, failed_id = verify_chain(events, GENESIS_HASH)

    event_hashes = [e["current_hash"] for e in events]
    merkle_root = None
    if event_hashes:
        merkle_root, _ = build_merkle_tree(event_hashes)

    return VerifyAuditResponse(
        verified=is_valid,
        checked_events=len(events),
        first_failed_sequence=failed_seq,
        first_failed_event_id=failed_id,
        merkle_root=merkle_root,
        verification_timestamp=datetime.now(tz=timezone.utc),
    )
