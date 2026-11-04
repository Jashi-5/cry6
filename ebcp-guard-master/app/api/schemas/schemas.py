"""
EBCP-Guard Pydantic API Schemas
=================================
Request / response schemas for all FastAPI endpoints.
Validated via Pydantic v2.

Security note:
  - OriginalPayload and detected entity text are transient.
  - Responses NEVER return raw secret keys.
  - Protected output replaces sensitive values with tokens/ciphertext.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ------------------------------------------------------------------ #
# Enumerations
# ------------------------------------------------------------------ #

class SensitivityClass(str, Enum):
    S0 = "S0"  # Public
    S1 = "S1"  # Internal
    S2 = "S2"  # Personal
    S3 = "S3"  # Highly sensitive financial
    S4 = "S4"  # Critical identifying


class ProcessingPurpose(str, Enum):
    PAYMENT_PROCESSING = "PAYMENT_PROCESSING"
    FRAUD_DETECTION = "FRAUD_DETECTION"
    CUSTOMER_SUPPORT = "CUSTOMER_SUPPORT"
    ANALYTICS = "ANALYTICS"
    MARKETING = "MARKETING"
    AUTHENTICATION = "AUTHENTICATION"
    REPORTING = "REPORTING"
    OTHER = "OTHER"


class ProtectionAction(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    TOKENIZE = "TOKENIZE"
    ENCRYPT = "ENCRYPT"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionMethod(str, Enum):
    GLINER = "gliner"
    REGEX = "regex"
    HYBRID = "hybrid"
    PRESIDIO = "presidio"


# ------------------------------------------------------------------ #
# Shared sub-models
# ------------------------------------------------------------------ #

class DetectedEntitySchema(BaseModel):
    entity_type: str
    entity_label: str | None = None
    start_offset: int
    end_offset: int
    confidence: float = Field(ge=0.0, le=1.0)
    detection_method: DetectionMethod
    sensitivity_class: SensitivityClass | None = None
    is_validated: bool = False


class ExposureScoreSchema(BaseModel):
    sensitivity_score: float = Field(ge=0.0, le=1.0, description="S(t)")
    cumulative_score: float = Field(ge=0.0, le=1.0, description="C(t)")
    linkability_score: float = Field(ge=0.0, le=1.0, description="L(t)")
    destination_trust_score: float = Field(ge=0.0, le=1.0, description="D(t)")
    total_risk_score: float = Field(ge=0.0, le=1.0, description="R(t)")
    risk_level: RiskLevel
    contributing_factors: dict[str, Any] = Field(default_factory=dict)


class EntityProtectionResult(BaseModel):
    entity_type: str
    original_offset: tuple[int, int]
    action: ProtectionAction
    protected_value: str | None = None  # token / ciphertext / masked value
    cipher_id: str | None = None        # for encrypted values
    token_id: str | None = None         # for tokenized values
    # Encrypted values only: what an authorized service needs to call /decrypt.
    ciphertext_b64: str | None = None
    purpose: str | None = None


# ------------------------------------------------------------------ #
# /analyze
# ------------------------------------------------------------------ #

class AnalyzeRequest(BaseModel):
    payload: dict[str, Any] = Field(
        description="The API payload (JSON object) to analyze. Original values are transient."
    )
    endpoint: str = Field(default="/unknown", max_length=512)
    http_method: str = Field(default="POST", max_length=16)
    destination_service: str | None = Field(default=None, max_length=128)
    source_service: str | None = Field(default=None, max_length=128)
    tenant_id: str = Field(default="default", max_length=128)
    synthetic_customer_id: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)
    processing_purpose_hint: ProcessingPurpose | None = None

    @field_validator("payload")
    @classmethod
    def payload_not_empty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("Payload must not be empty.")
        return v


class AnalyzeResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    request_id: str
    detected_entities: list[DetectedEntitySchema]
    entity_count: int
    sensitivity_class: SensitivityClass
    sensitivity_confidence: float
    purpose: ProcessingPurpose
    purpose_confidence: float
    requires_review: bool
    exposure_score: ExposureScoreSchema
    recommended_action: ProtectionAction
    processing_latency_ms: float
    model_versions: dict[str, str]


# ------------------------------------------------------------------ #
# /protect
# ------------------------------------------------------------------ #

class ProtectRequest(BaseModel):
    payload: dict[str, Any]
    endpoint: str = Field(default="/unknown", max_length=512)
    http_method: str = Field(default="POST", max_length=16)
    destination_service: str | None = None
    source_service: str | None = None
    tenant_id: str = Field(default="default", max_length=128)
    synthetic_customer_id: str | None = None
    session_id: str | None = None
    processing_purpose_hint: ProcessingPurpose | None = None
    # Override: force a specific protection action
    force_action: ProtectionAction | None = None


class ProtectResponse(BaseModel):
    request_id: str
    protected_payload: dict[str, Any]
    protection_decision: ProtectionAction
    entity_decisions: list[EntityProtectionResult]
    risk_score: float
    risk_level: RiskLevel
    audit_event_id: str
    audit_event_hash: str
    processing_latency_ms: float


# ------------------------------------------------------------------ #
# /decrypt
# ------------------------------------------------------------------ #

class DecryptRequest(BaseModel):
    cipher_id: str = Field(description="Cipher ID from encryption metadata")
    ciphertext_b64: str = Field(description="Base64-encoded ciphertext+nonce+tag")
    requesting_service: str | None = Field(
        default=None,
        description="Optional and never trusted: identity comes from X-API-Key. A mismatch is refused.",
    )
    tenant_id: str = Field(default="default", max_length=128)
    # Together with the tenant, these select the key. A wrong value fails GCM authentication.
    entity_type: str = Field(default="ACCOUNT_NUMBER", pattern=r"^[A-Z_]{1,32}$")
    purpose: ProcessingPurpose = ProcessingPurpose.PAYMENT_PROCESSING
    justification: str = Field(
        default="",
        max_length=512,
        description="Reason for decryption (audited)"
    )


class DecryptResponse(BaseModel):
    cipher_id: str
    decrypted_value: str
    entity_type: str
    audit_event_id: str


# ------------------------------------------------------------------ #
# /tokenize
# ------------------------------------------------------------------ #

class TokenizeRequest(BaseModel):
    values: list[dict[str, str]] = Field(
        description="List of {'entity_type': ..., 'value': ...} dicts"
    )
    tenant_id: str = Field(default="default")
    purpose: ProcessingPurpose = Field(default=ProcessingPurpose.OTHER)
    epoch_override: str | None = None


class TokenizeResponse(BaseModel):
    tokens: list[dict[str, str]]
    tenant_id: str
    purpose: str
    epoch_id: str
    key_version: str


# ------------------------------------------------------------------ #
# /verify-audit
# ------------------------------------------------------------------ #

class VerifyAuditRequest(BaseModel):
    tenant_id: str = Field(default="default")
    batch_id: int | None = None
    start_sequence: int | None = None
    end_sequence: int | None = None


class VerifyAuditResponse(BaseModel):
    verified: bool
    checked_events: int
    first_failed_sequence: int | None = None
    first_failed_event_id: str | None = None
    merkle_root: str | None = None
    verification_timestamp: datetime


# ------------------------------------------------------------------ #
# /exposure/{customer_id}
# ------------------------------------------------------------------ #

class ExposureHistoryResponse(BaseModel):
    synthetic_customer_id: str
    tenant_id: str
    total_events: int
    current_risk_score: ExposureScoreSchema | None
    recent_events: list[dict[str, Any]]
    entity_type_distribution: dict[str, int]


# ------------------------------------------------------------------ #
# /models/status
# ------------------------------------------------------------------ #

class ModelStatusResponse(BaseModel):
    models: list[dict[str, Any]]
    device: str
    all_ready: bool


# ------------------------------------------------------------------ #
# /metrics
# ------------------------------------------------------------------ #

class MetricsResponse(BaseModel):
    total_requests_analyzed: int
    total_entities_detected: int
    protection_action_counts: dict[str, int]
    average_latency_ms: float
    p95_latency_ms: float
    sensitivity_class_distribution: dict[str, int]
    purpose_distribution: dict[str, int]
    risk_level_distribution: dict[str, int]


# ------------------------------------------------------------------ #
# /health
# ------------------------------------------------------------------ #

class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    models_loaded: bool
    timestamp: datetime


# ------------------------------------------------------------------ #
# /simulate-attack
# ------------------------------------------------------------------ #

class AttackSimulationRequest(BaseModel):
    scenario: str = Field(
        description="Attack scenario ID: plaintext_log | dict_attack | cross_tenant | "
                    "cumulative | unauth_decrypt | audit_tamper | exfiltration | evasion"
    )
    tenant_id: str = Field(default="default")
    custom_params: dict[str, Any] = Field(default_factory=dict)


class AttackSimulationResponse(BaseModel):
    scenario: str
    baseline_outcome: str
    ebcp_guard_outcome: str
    result: str  # PROTECTED | PARTIAL | VULNERABLE
    details: dict[str, Any]
    explanation: str


# ------------------------------------------------------------------ #
# Error response
# ------------------------------------------------------------------ #

class ErrorResponse(BaseModel):
    error_code: str
    message: str
    request_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
