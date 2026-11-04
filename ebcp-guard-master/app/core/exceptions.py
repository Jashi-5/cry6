"""
EBCP-Guard Custom Exceptions
==============================
Centralised exception hierarchy for consistent error handling
across all application layers.
"""

from __future__ import annotations


class EBCPGuardError(Exception):
    """Base exception for all EBCP-Guard application errors."""
    status_code: int = 500
    detail: str = "An internal error occurred."

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail or self.__class__.detail
        super().__init__(self.detail)


# ------------------------------------------------------------------ #
# Detection errors
# ------------------------------------------------------------------ #

class DetectionError(EBCPGuardError):
    """Raised when entity detection fails."""
    status_code = 500
    detail = "Entity detection pipeline failed."


class ModelNotLoadedError(EBCPGuardError):
    """Raised when a required AI model is not loaded."""
    status_code = 503
    detail = "Required AI model is not available. Request cannot be processed."


class ModelInferenceError(EBCPGuardError):
    """Raised when model inference fails at runtime."""
    status_code = 500
    detail = "Model inference failed."


# ------------------------------------------------------------------ #
# Cryptography errors
# ------------------------------------------------------------------ #

class CryptographyError(EBCPGuardError):
    """Base class for cryptographic errors."""
    status_code = 500
    detail = "A cryptographic operation failed."


class InvalidKeyError(CryptographyError):
    """Raised when a cryptographic key is invalid or missing."""
    status_code = 500
    detail = "Cryptographic key is invalid or unavailable."


class AuthenticationTagError(CryptographyError):
    """Raised when AES-GCM authentication tag verification fails."""
    status_code = 400
    detail = "Ciphertext authentication failed — data may have been tampered with."


class KeyRotationError(CryptographyError):
    """Raised when key rotation cannot be completed safely."""
    status_code = 500
    detail = "Key rotation failed."


# ------------------------------------------------------------------ #
# Policy errors
# ------------------------------------------------------------------ #

class PolicyError(EBCPGuardError):
    """Raised when a policy evaluation fails."""
    status_code = 500
    detail = "Policy evaluation failed."


class PolicyBlockedError(EBCPGuardError):
    """Raised when a request is blocked by the policy engine."""
    status_code = 403
    detail = "Request blocked by privacy policy."


class UnauthorizedDecryptionError(EBCPGuardError):
    """Raised when a service attempts unauthorized decryption."""
    status_code = 403
    detail = "Decryption not authorized for the requesting service."


class UnauthorizedServiceError(EBCPGuardError):
    """Raised when a service is not in the authorized service registry."""
    status_code = 403
    detail = "Service identity is not authorized."


# ------------------------------------------------------------------ #
# Audit errors
# ------------------------------------------------------------------ #

class AuditIntegrityError(EBCPGuardError):
    """Raised when audit chain integrity verification fails."""
    status_code = 500
    detail = "Audit chain integrity verification failed — possible tampering detected."


# ------------------------------------------------------------------ #
# Exposure errors
# ------------------------------------------------------------------ #

class ExposureTrackingError(EBCPGuardError):
    """Raised when the exposure engine encounters a tracking failure."""
    status_code = 500
    detail = "Exposure tracking failed."


# ------------------------------------------------------------------ #
# Input validation errors
# ------------------------------------------------------------------ #

class InputValidationError(EBCPGuardError):
    """Raised when input payload fails validation."""
    status_code = 422
    detail = "Input validation failed."


class PayloadTooLargeError(EBCPGuardError):
    """Raised when an input payload exceeds the configured size limit."""
    status_code = 413
    detail = "Request payload exceeds the maximum allowed size."
