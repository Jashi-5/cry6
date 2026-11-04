"""
EBCP-Guard AES-256-GCM Encryption Module
==========================================
Implements authenticated encryption for values that must be
recoverable by authorized downstream services.

Security guarantees (AES-256-GCM):
  - Confidentiality: 256-bit AES in counter mode.
  - Integrity:       GHASH authentication tag (128-bit).
  - Authenticity:    Any modification to ciphertext, nonce, or AAD
                     causes decryption to fail with an authentication error.

NONCE POLICY:
  - Every encryption call generates a fresh 96-bit (12-byte) random nonce.
  - Nonce is NEVER reused under the same key.
  - Nonce is prepended to ciphertext: [nonce(12)] || [ciphertext] || [tag(16)]
  - Full package is Base64-encoded for transport.

KEY POLICY:
  - Keys are derived per (tenant, purpose, epoch) via HKDF.
  - Raw keys are never stored in the database or returned via API.
  - Only cipher_id and key_version identifiers are persisted.
"""

from __future__ import annotations

import base64
import os
import uuid
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.exceptions import AuthenticationTagError, CryptographyError
from app.core.logging import get_logger
from app.cryptography.key_manager import KeyManager, get_key_manager

logger = get_logger(__name__)

NONCE_SIZE = 12   # 96 bits — recommended for AES-GCM
TAG_SIZE = 16     # 128-bit authentication tag (implicit in Python's AESGCM)


class EncryptedPackage(NamedTuple):
    """
    Result of an encryption operation.
    cipher_package_b64: Base64(nonce || ciphertext || tag) — safe for transport.
    cipher_id:          Unique identifier for this encryption event.
    key_version:        Key version identifier for future decryption routing.
    """
    cipher_package_b64: str
    cipher_id: str
    key_version: str
    entity_type: str


def encrypt_value(
    plaintext: str,
    entity_type: str,
    tenant_id: str,
    purpose: str,
    associated_data: str | None = None,
    epoch_id: str | None = None,
    key_manager: KeyManager | None = None,
) -> EncryptedPackage:
    """
    Encrypt a sensitive plaintext value using AES-256-GCM.

    Package format (all bytes concatenated, then Base64-encoded):
        [12-byte nonce] || [variable ciphertext] || [16-byte tag]

    The authentication tag is implicitly appended by Python's AESGCM.

    Args:
        plaintext:        Original sensitive value (discarded after encryption).
        entity_type:      Entity category label for metadata tracking.
        tenant_id:        Tenant scope for key derivation.
        purpose:          Processing purpose for key derivation.
        associated_data:  Optional authenticated additional data (AAD).
                          Included in authentication but not encrypted.
        epoch_id:         Optional epoch override.
        key_manager:      Optional injected KeyManager.

    Returns:
        EncryptedPackage containing Base64 ciphertext, cipher_id, key_version.

    Raises:
        CryptographyError: If encryption fails for any reason.
    """
    if not plaintext:
        raise CryptographyError("Cannot encrypt empty value.")

    km = key_manager or get_key_manager()
    if epoch_id is None:
        epoch_id = km.current_epoch_id()

    try:
        aes_key = km.derive_aes_key(
            tenant_id=tenant_id,
            purpose=purpose,
            epoch_id=epoch_id,
        )

        # Fresh random nonce — never reused
        nonce = os.urandom(NONCE_SIZE)

        aesgcm = AESGCM(aes_key)

        aad: bytes | None = None
        if associated_data:
            aad = associated_data.encode("utf-8")

        # AESGCM.encrypt(nonce, data, associated_data)
        ciphertext_with_tag = aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            aad,
        )

        # Package: nonce || ciphertext || tag
        package = nonce + ciphertext_with_tag
        cipher_package_b64 = base64.b64encode(package).decode("ascii")

        cipher_id = f"AES256GCM_{uuid.uuid4().hex}"

        # Securely zero out the key from memory where possible
        # (best-effort in Python — GC may delay deallocation)
        del aes_key

        return EncryptedPackage(
            cipher_package_b64=cipher_package_b64,
            cipher_id=cipher_id,
            key_version=km.key_version,
            entity_type=entity_type,
        )

    except Exception as exc:
        logger.error("encryption_failed", entity_type=entity_type, error=str(exc))
        raise CryptographyError(f"Encryption failed: {exc}") from exc


def decrypt_value(
    cipher_package_b64: str,
    entity_type: str,
    tenant_id: str,
    purpose: str,
    key_version: str,
    associated_data: str | None = None,
    epoch_id: str | None = None,
    key_manager: KeyManager | None = None,
) -> str:
    """
    Decrypt an AES-256-GCM encrypted package.

    Args:
        cipher_package_b64: Base64-encoded [nonce || ciphertext || tag].
        entity_type:        Entity category (for logging — no PII).
        tenant_id:          Tenant scope for key re-derivation.
        purpose:            Processing purpose for key re-derivation.
        key_version:        Key version identifier (must match encryption version).
        associated_data:    Optional AAD (must match what was used during encryption).
        epoch_id:           Optional epoch override.
        key_manager:        Optional injected KeyManager.

    Returns:
        Decrypted plaintext string.

    Raises:
        AuthenticationTagError: If GCM authentication verification fails
                                (ciphertext or nonce has been tampered with).
        CryptographyError:      For other decryption failures.
    """
    km = key_manager or get_key_manager()
    if epoch_id is None:
        epoch_id = km.current_epoch_id()

    try:
        package = base64.b64decode(cipher_package_b64.encode("ascii"))

        if len(package) < NONCE_SIZE + TAG_SIZE + 1:
            raise CryptographyError("Cipher package is too short to be valid.")

        nonce = package[:NONCE_SIZE]
        ciphertext_with_tag = package[NONCE_SIZE:]

        aes_key = km.derive_aes_key(
            tenant_id=tenant_id,
            purpose=purpose,
            epoch_id=epoch_id,
        )

        aesgcm = AESGCM(aes_key)

        aad: bytes | None = None
        if associated_data:
            aad = associated_data.encode("utf-8")

        try:
            plaintext_bytes = aesgcm.decrypt(
                nonce,
                ciphertext_with_tag,
                aad,
            )
        except InvalidTag:
            logger.warning(
                "aes_gcm_auth_tag_failure",
                entity_type=entity_type,
                tenant_id=tenant_id,
                purpose=purpose,
            )
            raise AuthenticationTagError(
                "AES-GCM authentication tag verification failed. "
                "The ciphertext may have been modified or the wrong key was used."
            )

        del aes_key
        return plaintext_bytes.decode("utf-8")

    except (AuthenticationTagError, CryptographyError):
        raise
    except Exception as exc:
        logger.error("decryption_failed", entity_type=entity_type, error=str(exc))
        raise CryptographyError(f"Decryption failed: {exc}") from exc


def test_nonce_uniqueness(num_samples: int = 1000) -> bool:
    """
    Generate multiple nonces and verify none are duplicated.
    Used in test suite to demonstrate nonce uniqueness property.
    Returns True if all nonces are unique.
    """
    nonces = [os.urandom(NONCE_SIZE) for _ in range(num_samples)]
    unique_nonces = set(nonces)
    return len(unique_nonces) == num_samples
