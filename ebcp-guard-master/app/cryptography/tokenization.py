"""
EBCP-Guard Purpose-Bound Pseudonymization (HMAC-SHA-256)
=========================================================
Implements context-scoped, keyed pseudonymization using HMAC-SHA-256.

WHY NOT plain SHA-256?
  SHA256(email) is deterministic and predictable.
  An attacker with a dictionary of likely emails can pre-compute hashes
  and match them against the token table — a classic dictionary attack.

  HMAC-SHA-256 with a secret key prevents this:
  T = HMAC-SHA256(K_context, normalize(value))
  The attacker must possess K_context to generate or verify any token.

WHY purpose-scoping?
  The same entity (e.g., a customer email) produces DIFFERENT tokens
  under different (tenant, purpose, epoch) contexts.
  This prevents unauthorized cross-context correlation:
    HMAC(K_payment, email)  ≠  HMAC(K_analytics, email)

  Only an authorized party with the purpose-specific derived key
  can link the same entity across requests within the same scope.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
import uuid
from datetime import datetime, timezone

from app.core.exceptions import CryptographyError
from app.core.logging import get_logger
from app.cryptography.key_manager import KeyManager, get_key_manager

logger = get_logger(__name__)


def _normalize_value(value: str) -> bytes:
    """
    Normalize a sensitive value before tokenization:
    - Unicode NFC normalization to collapse equivalent representations.
    - Strip leading/trailing whitespace.
    - Encode to UTF-8.

    Normalization ensures that semantically identical values produce
    identical tokens even if their byte representations differ.
    """
    normalized = unicodedata.normalize("NFC", value.strip()).lower()
    return normalized.encode("utf-8")


def generate_token(
    value: str,
    entity_type: str,
    tenant_id: str,
    purpose: str,
    epoch_id: str | None = None,
    key_manager: KeyManager | None = None,
) -> tuple[str, str, str]:
    """
    Generate a purpose-bound pseudonymization token for a sensitive value.

    Construction:
        K = HKDF(hmac_master, salt=None, info=version||tenant||purpose||epoch)
        T = HMAC-SHA256(K, normalize(value))

    The token is encoded as a hex string with an entity-type prefix
    for readability: e.g. "EMAIL_a3f9c2d1..."

    Args:
        value:       Original sensitive value (transient — discarded after call).
        entity_type: Category label (EMAIL, PHONE, PAN, etc.).
        tenant_id:   Tenant identifier for scope separation.
        purpose:     Processing purpose for scope separation.
        epoch_id:    Optional epoch override (defaults to current epoch).
        key_manager: Optional injected KeyManager (uses singleton if None).

    Returns:
        Tuple of (token_string, epoch_id_used, key_version).

    Raises:
        CryptographyError: If tokenization fails.
    """
    if not value or not value.strip():
        raise CryptographyError("Cannot tokenize empty or whitespace-only value.")

    km = key_manager or get_key_manager()

    if epoch_id is None:
        epoch_id = km.current_epoch_id()

    try:
        derived_key = km.derive_hmac_key(
            tenant_id=tenant_id,
            purpose=purpose,
            epoch_id=epoch_id,
        )

        normalized = _normalize_value(value)

        # HMAC-SHA256: cryptographically keyed hash
        mac = hmac.new(derived_key, normalized, hashlib.sha256)
        token_hex = mac.hexdigest()

        # Prefix with entity type for human readability in logs/output
        safe_label = entity_type.upper().replace(" ", "_")[:20]
        token = f"{safe_label}_{token_hex}"

        return token, epoch_id, km.key_version

    except Exception as exc:
        logger.error("tokenization_failed", entity_type=entity_type, error=str(exc))
        raise CryptographyError(f"Tokenization failed: {exc}") from exc


def verify_token(
    value: str,
    expected_token: str,
    entity_type: str,
    tenant_id: str,
    purpose: str,
    epoch_id: str,
    key_manager: KeyManager | None = None,
) -> bool:
    """
    Verify that a token matches the given value under the same scope.

    Uses hmac.compare_digest for constant-time comparison
    to prevent timing-oracle attacks.

    Returns:
        True if the token is valid for the given value and scope.
        False otherwise.
    """
    km = key_manager or get_key_manager()
    try:
        candidate_token, _, _ = generate_token(
            value=value,
            entity_type=entity_type,
            tenant_id=tenant_id,
            purpose=purpose,
            epoch_id=epoch_id,
            key_manager=km,
        )
        # Constant-time comparison
        return hmac.compare_digest(candidate_token, expected_token)
    except CryptographyError:
        return False


def tokens_are_scope_separated(
    value: str,
    entity_type: str,
    tenant_id_a: str,
    purpose_a: str,
    tenant_id_b: str,
    purpose_b: str,
    epoch_id: str,
    key_manager: KeyManager | None = None,
) -> bool:
    """
    Assert that two different (tenant, purpose) scopes produce
    different tokens for the same input value.

    Returns True if tokens are DIFFERENT (scope separation holds).
    Returns False if tokens are the same (scope separation is VIOLATED — bug!).

    Used in security demonstration Attack 3.
    """
    km = key_manager or get_key_manager()
    token_a, _, _ = generate_token(value, entity_type, tenant_id_a, purpose_a, epoch_id, km)
    token_b, _, _ = generate_token(value, entity_type, tenant_id_b, purpose_b, epoch_id, km)
    return not hmac.compare_digest(token_a, token_b)


def generate_batch_tokens(
    entries: list[dict[str, str]],
    tenant_id: str,
    purpose: str,
    epoch_id: str | None = None,
    key_manager: KeyManager | None = None,
) -> list[dict[str, str]]:
    """
    Generate tokens for a list of {'entity_type': ..., 'value': ...} dicts.

    Returns:
        List of {'entity_type': ..., 'token': ..., 'epoch_id': ..., 'key_version': ...} dicts.
    """
    km = key_manager or get_key_manager()
    results = []
    for entry in entries:
        entity_type = entry.get("entity_type", "UNKNOWN")
        value = entry.get("value", "")
        try:
            token, eid, kv = generate_token(
                value=value,
                entity_type=entity_type,
                tenant_id=tenant_id,
                purpose=purpose,
                epoch_id=epoch_id,
                key_manager=km,
            )
            results.append({
                "entity_type": entity_type,
                "token": token,
                "epoch_id": eid,
                "key_version": kv,
            })
        except CryptographyError as exc:
            results.append({
                "entity_type": entity_type,
                "token": "TOKENIZATION_FAILED",
                "error": str(exc),
            })
    return results
