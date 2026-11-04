"""
EBCP-Guard Key Manager
========================
Manages the cryptographic key hierarchy:

  Master Key
  └─ Tenant Key  (HKDF: master + salt + tenant_id)
     └─ Purpose Key  (HKDF: tenant_key + purpose)
        └─ Epoch Key  (HKDF: purpose_key + epoch_id)

Keys are DERIVED on demand and NEVER stored in the database.
Only key VERSION IDENTIFIERS are stored.

Security notes:
  - Uses HKDF-SHA-256 for all key derivation.
  - Domain separation via unambiguous length-prefixed info strings.
  - Master keys are loaded once from environment at startup.
  - Key rotation: increment KEY_VERSION env var; old keys re-derivable
    only with explicit version tracking (future HSM integration).
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
from datetime import datetime, timezone
from functools import lru_cache

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings
from app.core.exceptions import InvalidKeyError
from app.core.logging import get_logger

logger = get_logger(__name__)


def _hkdf_expand(
    input_key_material: bytes,
    length: int,
    info: bytes,
    salt: bytes | None = None,
) -> bytes:
    """
    Derive a key using HKDF-SHA-256.

    Args:
        input_key_material: Source key bytes.
        length: Desired output key length in bytes.
        info: Domain-separation context string (must be unique per purpose).
        salt: Optional random salt (recommended for HKDF extract phase).

    Returns:
        Derived key bytes of `length` bytes.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)


def _encode_component(value: str) -> bytes:
    """
    Length-prefix encode a string component for safe domain separation.
    Format: [4-byte big-endian length][UTF-8 encoded value]
    This avoids ambiguity when concatenating multiple components.
    """
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


class KeyManager:
    """
    Purpose-bound cryptographic key manager.

    Derives keys on demand from environment-loaded master keys.
    Keys are never persisted — only version identifiers are stored.

    Usage:
        km = KeyManager()
        hmac_key = km.derive_hmac_key(tenant_id="bank_a", purpose="PAYMENT", epoch_id="2024-01")
        aes_key  = km.derive_aes_key(tenant_id="bank_a", purpose="FRAUD", epoch_id="2024-01")
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._hmac_master: bytes = settings.get_hmac_master_key_bytes()
        self._aes_master: bytes = settings.get_aes_master_key_bytes()
        self._audit_master: bytes = settings.get_audit_hmac_key_bytes()
        self._key_version: str = settings.key_version
        self._token_epoch_hours: int = settings.token_epoch_hours

        if len(self._hmac_master) != 32:
            raise InvalidKeyError("HMAC master key must be 32 bytes (256 bits).")
        if len(self._aes_master) != 32:
            raise InvalidKeyError("AES master key must be 32 bytes (256 bits).")

    # ------------------------------------------------------------------ #
    # Epoch Management
    # ------------------------------------------------------------------ #

    def current_epoch_id(self) -> str:
        """
        Compute the current token epoch identifier based on epoch duration.
        Format: 'epoch-YYYYMMDD-HH' (truncated to epoch_hours boundary).

        The epoch changes every `token_epoch_hours` hours,
        causing tokens to be scoped to a time window.
        """
        now = datetime.now(tz=timezone.utc)
        epoch_index = math.floor(now.hour / self._token_epoch_hours)
        return f"epoch-{now.strftime('%Y%m%d')}-{epoch_index:02d}"

    # ------------------------------------------------------------------ #
    # HMAC Key Derivation (for pseudonymization)
    # ------------------------------------------------------------------ #

    def derive_hmac_key(
        self,
        tenant_id: str,
        purpose: str,
        epoch_id: str | None = None,
        salt: bytes | None = None,
    ) -> bytes:
        """
        Derive a 32-byte HMAC key scoped to (tenant, purpose, epoch).

        The info string uses length-prefixed encoding to prevent
        collision between different (tenant, purpose, epoch) combinations.

        K_context = HKDF(
            master_key  = hmac_master,
            salt        = salt,
            info        = version || tenant_id || purpose || epoch_id
        )
        """
        if epoch_id is None:
            epoch_id = self.current_epoch_id()

        info = (
            _encode_component(f"ebcp-hmac-v{self._key_version}")
            + _encode_component(tenant_id)
            + _encode_component(purpose)
            + _encode_component(epoch_id)
        )

        return _hkdf_expand(
            input_key_material=self._hmac_master,
            length=32,
            info=info,
            salt=salt,
        )

    # ------------------------------------------------------------------ #
    # AES Key Derivation (for reversible encryption)
    # ------------------------------------------------------------------ #

    def derive_aes_key(
        self,
        tenant_id: str,
        purpose: str,
        epoch_id: str | None = None,
        salt: bytes | None = None,
    ) -> bytes:
        """
        Derive a 32-byte AES-256 key scoped to (tenant, purpose, epoch).
        Uses a distinct domain label ("ebcp-aes") to prevent key reuse
        with HMAC derivation.
        """
        if epoch_id is None:
            epoch_id = self.current_epoch_id()

        info = (
            _encode_component(f"ebcp-aes-v{self._key_version}")
            + _encode_component(tenant_id)
            + _encode_component(purpose)
            + _encode_component(epoch_id)
        )

        return _hkdf_expand(
            input_key_material=self._aes_master,
            length=32,
            info=info,
            salt=salt,
        )

    # ------------------------------------------------------------------ #
    # Audit Key Derivation
    # ------------------------------------------------------------------ #

    def derive_audit_key(self, tenant_id: str) -> bytes:
        """
        Derive a 32-byte audit HMAC key for the hash chain.
        Not epoch-scoped — audit keys are stable per tenant per version.
        """
        info = (
            _encode_component(f"ebcp-audit-v{self._key_version}")
            + _encode_component(tenant_id)
        )
        return _hkdf_expand(
            input_key_material=self._audit_master,
            length=32,
            info=info,
        )

    # ------------------------------------------------------------------ #
    # Cross-Tenant Separation Test
    # ------------------------------------------------------------------ #

    def keys_are_distinct(
        self,
        tenant_a: str,
        tenant_b: str,
        purpose: str,
        epoch_id: str,
    ) -> bool:
        """
        Verify that different tenants produce distinct derived keys.
        Used in test suites to validate scope separation.
        """
        key_a = self.derive_hmac_key(tenant_a, purpose, epoch_id)
        key_b = self.derive_hmac_key(tenant_b, purpose, epoch_id)
        return not hmac.compare_digest(key_a, key_b)

    @property
    def key_version(self) -> str:
        return self._key_version


@lru_cache(maxsize=1)
def get_key_manager() -> KeyManager:
    """Return cached KeyManager singleton."""
    return KeyManager()
