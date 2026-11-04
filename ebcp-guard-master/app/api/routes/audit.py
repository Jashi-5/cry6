"""Audit verification endpoint."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from app.api.schemas.schemas import VerifyAuditRequest, VerifyAuditResponse
from app.core.auth import ServiceIdentity, require_service, require_tenant
from app.cryptography.audit_integrity import verify_chain, build_merkle_tree, GENESIS_HASH
from app.cryptography.key_manager import get_key_manager
from app.services.audit_service import checkpoint_failure

router = APIRouter()

@router.post("/verify-audit", response_model=VerifyAuditResponse)
async def verify_audit(
    request: VerifyAuditRequest,
    service: ServiceIdentity = Depends(require_service),
) -> VerifyAuditResponse:
    """
    Verify the integrity of the audit hash chain using PostgreSQL records.
    Detects any tampering with audit events.
    """
    require_tenant(service, request.tenant_id)

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

    audit_key = get_key_manager().derive_audit_key(request.tenant_id)
    is_valid, failed_seq, failed_id = verify_chain(events, GENESIS_HASH, audit_key)

    # A full-chain check must also still reach the last event recorded outside the database.
    is_full_chain = request.batch_id is None and request.start_sequence is None and request.end_sequence is None
    if is_valid and is_full_chain:
        failed_seq = checkpoint_failure(request.tenant_id, events)
        is_valid = failed_seq is None

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
