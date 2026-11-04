"""
EBCP-Guard Database Models (Tortoise ORM)
==========================================
Defines all persistent data models.

Security contract:
  - Original PII values are NEVER stored in any of these tables.
  - Sensitive entity values are stored only as HMAC tokens, AES-GCM
    ciphertext (for fields requiring recovery), or type-labels.
  - Audit records reference safe metadata only.
"""

from __future__ import annotations

from tortoise import fields
from tortoise.models import Model


# ------------------------------------------------------------------ #
# Tenant & Policy
# ------------------------------------------------------------------ #

class TenantPolicy(Model):
    """
    Per-tenant privacy policy configuration.
    Determines which purposes, destinations, and entity types
    are permitted for a given tenant.
    """
    id = fields.UUIDField(pk=True)
    tenant_id = fields.CharField(max_length=128, unique=True, index=True)
    allowed_purposes = fields.JSONField(default=list)
    authorized_destinations = fields.JSONField(default=list)
    entity_permissions = fields.JSONField(default=dict)
    risk_thresholds = fields.JSONField(default=dict)
    fail_closed = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "tenant_policies"


class AuthorizedService(Model):
    """
    Registry of services authorized to call protected operations
    such as decryption endpoints.
    """
    id = fields.UUIDField(pk=True)
    service_id = fields.CharField(max_length=128, unique=True, index=True)
    tenant_id = fields.CharField(max_length=128, index=True)
    display_name = fields.CharField(max_length=256)
    allowed_operations = fields.JSONField(default=list)
    allowed_entity_types = fields.JSONField(default=list)
    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "authorized_services"


# ------------------------------------------------------------------ #
# API Requests
# ------------------------------------------------------------------ #

class APIRequest(Model):
    """
    Metadata record for each analyzed API request.
    The payload body is NEVER stored — only metadata.
    """
    id = fields.UUIDField(pk=True)
    request_id = fields.CharField(max_length=128, unique=True, index=True)
    session_id = fields.CharField(max_length=128, null=True, index=True)
    synthetic_customer_id = fields.CharField(max_length=128, null=True, index=True)
    tenant_id = fields.CharField(max_length=128, default="default", index=True)
    endpoint = fields.CharField(max_length=512)
    http_method = fields.CharField(max_length=16)
    source_service = fields.CharField(max_length=128, null=True)
    destination_service = fields.CharField(max_length=128, null=True)
    content_type = fields.CharField(max_length=128, null=True)
    processing_latency_ms = fields.FloatField(null=True)
    pipeline_stage_latencies = fields.JSONField(default=dict)
    created_at = fields.DatetimeField(auto_now_add=True, index=True)

    # Reverse relations populated by Tortoise
    detected_entities: fields.ReverseRelation["DetectedEntity"]
    sensitivity_prediction: fields.ReverseRelation["SensitivityPrediction"]
    purpose_prediction: fields.ReverseRelation["PurposePrediction"]
    protection_decision: fields.ReverseRelation["ProtectionDecision"]

    class Meta:
        table = "api_requests"
        indexes = [
            ("tenant_id", "created_at"),
            ("synthetic_customer_id", "created_at"),
        ]


# ------------------------------------------------------------------ #
# Entity Detection
# ------------------------------------------------------------------ #

class DetectedEntity(Model):
    """
    Records a single detected sensitive entity span.
    The original entity text value is NEVER stored.
    Only the entity type, confidence, and detection metadata are stored.
    """
    id = fields.UUIDField(pk=True)
    api_request = fields.ForeignKeyField(
        "models.APIRequest", related_name="detected_entities", on_delete=fields.CASCADE
    )
    entity_type = fields.CharField(max_length=64, index=True)
    entity_label = fields.CharField(max_length=128, null=True)
    start_offset = fields.IntField()
    end_offset = fields.IntField()
    confidence = fields.FloatField()
    detection_method = fields.CharField(
        max_length=32,
        description="gliner | regex | hybrid | presidio"
    )
    sensitivity_class = fields.CharField(
        max_length=4,
        null=True,
        description="S0–S4"
    )
    is_validated = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "detected_entities"
        indexes = [
            ("entity_type", "confidence"),
        ]


# ------------------------------------------------------------------ #
# NLP Predictions
# ------------------------------------------------------------------ #

class SensitivityPrediction(Model):
    """
    Five-class sensitivity classification result for a request.
    Classes: S0 (public) → S4 (critical identifying).
    """
    id = fields.UUIDField(pk=True)
    api_request = fields.ForeignKeyField(
        "models.APIRequest", related_name="sensitivity_prediction", on_delete=fields.CASCADE
    )
    predicted_class = fields.CharField(max_length=4, index=True)
    confidence = fields.FloatField()
    class_probabilities = fields.JSONField(default=dict)
    model_name = fields.CharField(max_length=128)
    model_version = fields.CharField(max_length=64)
    requires_review = fields.BooleanField(default=False)
    predicted_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "sensitivity_predictions"


class PurposePrediction(Model):
    """
    API purpose classification result.
    Informs the policy engine about the intended processing context.
    IMPORTANT: Never used alone for authorization — deterministic policy
    rules always have the final say.
    """
    id = fields.UUIDField(pk=True)
    api_request = fields.ForeignKeyField(
        "models.APIRequest", related_name="purpose_prediction", on_delete=fields.CASCADE
    )
    predicted_purpose = fields.CharField(max_length=64, index=True)
    confidence = fields.FloatField()
    class_probabilities = fields.JSONField(default=dict)
    model_name = fields.CharField(max_length=128)
    model_version = fields.CharField(max_length=64)
    requires_review = fields.BooleanField(default=False)
    predicted_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "purpose_predictions"


# ------------------------------------------------------------------ #
# Exposure Intelligence
# ------------------------------------------------------------------ #

class ExposureEvent(Model):
    """
    Records a single disclosure event for a synthetic customer.
    Used by the cumulative exposure engine to track historical risk.
    Original entity values are NEVER stored.
    """
    id = fields.UUIDField(pk=True)
    synthetic_customer_id = fields.CharField(max_length=128, index=True)
    tenant_id = fields.CharField(max_length=128, index=True)
    session_id = fields.CharField(max_length=128, null=True)
    disclosure_sequence_id = fields.CharField(max_length=128, null=True, index=True)
    entity_type = fields.CharField(max_length=64)
    # Safe one-way hash of the entity value for deduplication — not reversible
    entity_type_hash = fields.CharField(max_length=64, null=True)
    endpoint = fields.CharField(max_length=512)
    purpose = fields.CharField(max_length=64)
    destination = fields.CharField(max_length=128, null=True)
    protection_action = fields.CharField(max_length=32)
    risk_contribution = fields.FloatField(default=0.0)
    occurred_at = fields.DatetimeField(auto_now_add=True, index=True)

    class Meta:
        table = "exposure_events"
        indexes = [
            ("synthetic_customer_id", "occurred_at"),
            ("tenant_id", "occurred_at"),
            ("disclosure_sequence_id",),
        ]


class ExposureScore(Model):
    """
    Computed cumulative exposure risk score for a synthetic customer.
    Stores the decomposed risk formula components for explainability.
    R(t) = α·S(t) + β·C(t) + γ·L(t) + δ·D(t)
    """
    id = fields.UUIDField(pk=True)
    synthetic_customer_id = fields.CharField(max_length=128, index=True)
    tenant_id = fields.CharField(max_length=128, index=True)
    sensitivity_score = fields.FloatField()      # S(t)
    cumulative_score = fields.FloatField()        # C(t)
    linkability_score = fields.FloatField()       # L(t)
    destination_trust_score = fields.FloatField() # D(t)
    total_risk_score = fields.FloatField(index=True)
    risk_level = fields.CharField(max_length=16)  # LOW | MEDIUM | HIGH | CRITICAL
    contributing_factors = fields.JSONField(default=dict)
    event_count = fields.IntField(default=0)
    scored_at = fields.DatetimeField(auto_now_add=True, index=True)

    class Meta:
        table = "exposure_scores"
        indexes = [
            ("synthetic_customer_id", "scored_at"),
        ]


# ------------------------------------------------------------------ #
# Protection Decisions
# ------------------------------------------------------------------ #

class ProtectionDecision(Model):
    """
    Records the final policy decision and per-entity actions taken.
    """
    id = fields.UUIDField(pk=True)
    api_request = fields.ForeignKeyField(
        "models.APIRequest", related_name="protection_decision", on_delete=fields.CASCADE
    )
    decision = fields.CharField(
        max_length=32,
        description="ALLOW | MASK | TOKENIZE | ENCRYPT | BLOCK | QUARANTINE"
    )
    policy_rule_id = fields.CharField(max_length=128, null=True)
    entity_decisions = fields.JSONField(default=list)
    risk_score = fields.FloatField(null=True)
    risk_level = fields.CharField(max_length=16, null=True)
    override_applied = fields.BooleanField(default=False)
    decided_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "protection_decisions"


# ------------------------------------------------------------------ #
# Cryptographic Metadata
# ------------------------------------------------------------------ #

class TokenMetadata(Model):
    """
    Metadata about a generated pseudonymization token.
    Secret keys are NEVER stored here.
    """
    id = fields.UUIDField(pk=True)
    token_id = fields.CharField(max_length=256, unique=True, index=True)
    entity_type = fields.CharField(max_length=64)
    tenant_id = fields.CharField(max_length=128, index=True)
    purpose = fields.CharField(max_length=64)
    epoch_id = fields.CharField(max_length=64)
    key_version = fields.CharField(max_length=16)
    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField(null=True)

    class Meta:
        table = "token_metadata"
        indexes = [
            ("tenant_id", "purpose"),
            ("entity_type", "is_active"),
        ]


class EncryptionMetadata(Model):
    """
    Metadata about an AES-256-GCM encrypted value.
    The ciphertext itself is returned to the caller, not stored here.
    This table tracks key versions and authorization for decryption.
    """
    id = fields.UUIDField(pk=True)
    cipher_id = fields.CharField(max_length=256, unique=True, index=True)
    entity_type = fields.CharField(max_length=64)
    key_version = fields.CharField(max_length=16)
    algorithm = fields.CharField(max_length=32, default="AES-256-GCM")
    authorized_services = fields.JSONField(default=list)
    created_at = fields.DatetimeField(auto_now_add=True)
    last_accessed_at = fields.DatetimeField(null=True)

    class Meta:
        table = "encryption_metadata"


# ------------------------------------------------------------------ #
# Audit Trail
# ------------------------------------------------------------------ #

class AuditEvent(Model):
    """
    Tamper-evident audit record.
    Forms part of a SHA-256 hash chain: H_i = SHA256(H_{i-1} || event_i)
    Safe metadata only — no original PII.
    """
    id = fields.UUIDField(pk=True)
    event_id = fields.CharField(max_length=128, unique=True, index=True)
    request_id = fields.CharField(max_length=128, null=True, index=True)
    tenant_id = fields.CharField(max_length=128, index=True)
    synthetic_customer_id = fields.CharField(max_length=128, null=True, index=True)
    event_type = fields.CharField(max_length=64)
    # Safe metadata — entity TYPE labels, risk scores, decisions — no values
    safe_metadata = fields.JSONField(default=dict)
    previous_hash = fields.CharField(max_length=64)
    current_hash = fields.CharField(max_length=64, index=True)
    merkle_root = fields.CharField(max_length=64, null=True)
    batch_id = fields.IntField(null=True, index=True)
    sequence_number = fields.BigIntField(index=True)
    created_at = fields.DatetimeField(auto_now_add=True, index=True)

    class Meta:
        table = "audit_events"
        indexes = [
            ("tenant_id", "sequence_number"),
            ("batch_id", "sequence_number"),
        ]


# ------------------------------------------------------------------ #
# Model Registry
# ------------------------------------------------------------------ #

class ModelRegistry(Model):
    """
    Tracks loaded AI model versions and their evaluation metrics.
    """
    id = fields.UUIDField(pk=True)
    model_name = fields.CharField(max_length=128, index=True)
    model_version = fields.CharField(max_length=64)
    model_type = fields.CharField(
        max_length=32,
        description="gliner | sensitivity | purpose"
    )
    checkpoint_path = fields.CharField(max_length=512)
    eval_metrics = fields.JSONField(default=dict)
    device = fields.CharField(max_length=16, default="cpu")
    is_active = fields.BooleanField(default=True, index=True)
    registered_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "model_registry"


class EvaluationResult(Model):
    """
    Stores structured evaluation results for model performance tracking.
    """
    id = fields.UUIDField(pk=True)
    model_registry = fields.ForeignKeyField(
        "models.ModelRegistry", related_name="evaluation_results", on_delete=fields.SET_NULL, null=True
    )
    eval_dataset = fields.CharField(max_length=128)
    eval_split = fields.CharField(max_length=16, default="test")
    metrics = fields.JSONField(default=dict)
    confusion_matrix = fields.JSONField(default=dict)
    per_class_metrics = fields.JSONField(default=dict)
    sample_count = fields.IntField()
    evaluated_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "evaluation_results"
