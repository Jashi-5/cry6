"""Decrypt endpoint."""
from __future__ import annotations
import uuid
from fastapi import APIRouter
from app.api.schemas.schemas import DecryptRequest, DecryptResponse
from app.config import get_settings
from app.core.exceptions import UnauthorizedDecryptionError, UnauthorizedServiceError
from app.core.logging import get_logger
from app.cryptography.encryption import decrypt_value
from app.services.audit_service import record_audit_event

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()

@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt(request: DecryptRequest) -> DecryptResponse:
    """
    Decrypt an AES-256-GCM protected value after strict authorization verification.
    Unauthorized attempts are denied, logged, and audited.
    """
    # 1. Authorization check
    if request.requesting_service not in settings.authorized_decrypt_services:
        logger.warning(
            "unauthorized_decrypt_denied",
            service=request.requesting_service,
            cipher_id=request.cipher_id,
            tenant_id=request.tenant_id,
        )
        raise UnauthorizedServiceError(
            f"Service '{request.requesting_service}' is not authorized to perform decryption."
        )

    # 2. Reversible decryption under scoped context
    # Note: If entity_type and purpose are stored in metadata, retrieve or default
    entity_type = "ACCOUNT_NUMBER"
    purpose = "PAYMENT_PROCESSING"

    try:
        decrypted_text = decrypt_value(
            cipher_package_b64=request.ciphertext_b64,
            entity_type=entity_type,
            tenant_id=request.tenant_id,
            purpose=purpose,
            key_version=settings.key_version,
        )
    except Exception as exc:
        logger.error("decryption_operation_failed", cipher_id=request.cipher_id, error=str(exc))
        raise

    # 3. Cryptographically verifiable audit record
    audit_id, _ = await record_audit_event(
        request_id=f"dec-{uuid.uuid4().hex[:8]}",
        tenant_id=request.tenant_id,
        synthetic_customer_id=None,
        event_type="AUTHORIZED_DECRYPTION",
        entity_types=[entity_type],
        sensitivity_class="S4",
        protection_action="DECRYPTED",
        risk_score=0.0,
        model_versions={},
    )

    return DecryptResponse(
        cipher_id=request.cipher_id,
        decrypted_value=decrypted_text,
        entity_type=entity_type,
        audit_event_id=audit_id,
    )
