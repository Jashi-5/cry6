"""
EBCP-Guard Protection Service
================================
Applies cryptographic protection to entities identified by the policy engine.
Coordinates between the policy engine, masking, tokenization, and encryption.
"""

from __future__ import annotations

import copy
import time
import uuid
from typing import Any

from app.api.schemas.schemas import (
    EntityProtectionResult, ProtectRequest, ProtectResponse,
    ProtectionAction, RiskLevel,
)
from app.config import get_settings
from app.core.logging import get_logger
from app.cryptography.encryption import encrypt_value
from app.cryptography.masking import mask_by_entity_type
from app.cryptography.tokenization import generate_token
from app.detection.gliner_detector import run_hybrid_detection
from app.exposure.cumulative_exposure_engine import ExposureEventRecord, get_exposure_engine
from app.nlp.model_loader import get_model_registry
from app.nlp.sensitivity_classifier import build_sensitivity_input, classify_sensitivity
from app.nlp.purpose_classifier import build_purpose_input, classify_purpose
from app.policy.policy_engine import get_policy_engine, PolicyDecision
from app.services.analysis_service import _flatten_payload
from app.services.audit_service import record_audit_event

logger = get_logger(__name__)
settings = get_settings()


def _find_value_at_path(payload: dict, path: str) -> str | None:
    """Navigate a dot-separated path in a nested dict."""
    parts = path.split(".")
    current: Any = payload
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return str(current) if current is not None else None


def _set_value_at_path(payload: dict, path: str, new_value: Any) -> None:
    """Set a value at a dot-separated path in a nested dict (in-place)."""
    parts = path.split(".")
    current = payload
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = new_value


def _apply_protection_to_payload(
    protected_payload: dict[str, Any],
    payload_text: str,
    raw_entities: list[dict[str, Any]],
    policy_decision: PolicyDecision,
    entity_decisions: list[dict[str, Any]],
    tenant_id: str,
    purpose: str,
) -> list[EntityProtectionResult]:
    """
    Apply cryptographic protection to the payload based on policy decisions.
    Modifies protected_payload in-place.

    Returns list of EntityProtectionResult for the response.
    """
    results: list[EntityProtectionResult] = []

    for ent_decision in policy_decision.entity_decisions:
        # Find the entity in raw_entities
        matching = [
            e for e in raw_entities
            if e["entity_type"] == ent_decision.entity_type
        ]
        if not matching:
            continue

        for entity in matching:
            value = entity.get("value", "")
            if not value:
                continue

            action = ent_decision.action
            offset = (entity["start_offset"], entity["end_offset"])
            protected_val: str | None = None
            cipher_id: str | None = None
            token_id: str | None = None

            if action == ProtectionAction.ALLOW:
                protected_val = value  # No change

            elif action == ProtectionAction.MASK:
                protected_val = mask_by_entity_type(value, entity["entity_type"])
                # Replace in payload text representation
                _replace_in_payload(protected_payload, value, protected_val)

            elif action == ProtectionAction.TOKENIZE:
                token, epoch_id, kv = generate_token(
                    value=value,
                    entity_type=entity["entity_type"],
                    tenant_id=tenant_id,
                    purpose=purpose,
                )
                token_id = token
                protected_val = token
                _replace_in_payload(protected_payload, value, protected_val)

            elif action == ProtectionAction.ENCRYPT:
                pkg = encrypt_value(
                    plaintext=value,
                    entity_type=entity["entity_type"],
                    tenant_id=tenant_id,
                    purpose=purpose,
                )
                cipher_id = pkg.cipher_id
                protected_val = f"[ENC:{pkg.cipher_id}:{pkg.cipher_package_b64[:16]}...]"
                _replace_in_payload(protected_payload, value, f"[ENCRYPTED:{pkg.cipher_id}]")

            results.append(EntityProtectionResult(
                entity_type=entity["entity_type"],
                original_offset=offset,
                action=action,
                protected_value=protected_val,
                cipher_id=cipher_id,
                token_id=token_id,
            ))

    return results


def _replace_in_payload(payload: dict[str, Any], original: str, replacement: str) -> None:
    """Replace occurrences of original string value in all payload fields."""
    for key, val in payload.items():
        if isinstance(val, str) and original in val:
            payload[key] = val.replace(original, replacement)
        elif isinstance(val, dict):
            _replace_in_payload(val, original, replacement)
        elif isinstance(val, list):
            for i, item in enumerate(val):
                if isinstance(item, str) and original in item:
                    payload[key][i] = item.replace(original, replacement)
                elif isinstance(item, dict):
                    _replace_in_payload(item, original, replacement)


async def run_protection(request: ProtectRequest) -> ProtectResponse:
    """
    Execute the full protection pipeline and return protected payload.
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())

    payload_text = _flatten_payload(request.payload)
    payload_keys = list(request.payload.keys())

    registry = get_model_registry()

    # Detection
    try:
        gliner = registry.get_gliner()
    except Exception:
        gliner = None
    raw_entities = run_hybrid_detection(payload_text, gliner_model=gliner)
    entity_types = [e["entity_type"] for e in raw_entities]

    # Sensitivity
    sensitivity_class = "S2"
    sensitivity_confidence = 0.0
    try:
        sm, st, _ = registry.get_sensitivity_classifier()
        sensitivity_class, sensitivity_confidence, _ = classify_sensitivity(
            sm, st, build_sensitivity_input(payload_text, entity_types, len(raw_entities)),
            settings.model_device
        )
    except Exception:
        sensitivity_class = "S3"; sensitivity_confidence = 0.0

    # Purpose
    purpose = "OTHER"
    purpose_confidence = 0.0
    try:
        pm, pt, _ = registry.get_purpose_classifier()
        purpose, purpose_confidence, _ = classify_purpose(
            pm, pt, build_purpose_input(
                request.endpoint, request.http_method,
                request.destination_service, payload_keys
            ), settings.model_device
        )
    except Exception:
        pass
    if request.processing_purpose_hint and purpose_confidence < settings.model_confidence_threshold:
        purpose = request.processing_purpose_hint.value
        purpose_confidence = 1.0

    # Exposure
    customer_id = request.synthetic_customer_id or f"anon_{request_id[:8]}"
    risk_decomp = get_exposure_engine().compute_risk(
        synthetic_customer_id=customer_id,
        current_entity_types=entity_types,
        current_sensitivity_class=sensitivity_class,
        destination=request.destination_service or "unknown",
        purpose=purpose,
        tenant_id=request.tenant_id,
    )

    # Policy
    policy_decision = get_policy_engine().evaluate(
        entities=raw_entities,
        sensitivity_class=sensitivity_class,
        sensitivity_confidence=sensitivity_confidence,
        purpose=purpose,
        purpose_confidence=purpose_confidence,
        exposure_risk_level=risk_decomp.risk_level,
        exposure_risk_score=risk_decomp.total_risk_score,
        destination=request.destination_service,
        tenant_id=request.tenant_id,
    )

    # Apply force_action override if requested (cannot loosen policy)
    if request.force_action:
        from app.policy.policy_engine import _ACTION_SEVERITY, _most_restrictive
        final_action_str = _most_restrictive(
            policy_decision.overall_action.value,
            request.force_action.value
        )
        policy_decision.overall_action = ProtectionAction(final_action_str)

    # A withheld request returns no payload data at all; otherwise protect a copy
    protected_payload: dict[str, Any] = {}
    entity_results: list[EntityProtectionResult] = []
    if policy_decision.overall_action not in (ProtectionAction.BLOCK, ProtectionAction.QUARANTINE):
        protected_payload = copy.deepcopy(request.payload)
        entity_results = _apply_protection_to_payload(
            protected_payload=protected_payload,
            payload_text=payload_text,
            raw_entities=raw_entities,
            policy_decision=policy_decision,
            entity_decisions=[],
            tenant_id=request.tenant_id,
            purpose=purpose,
        )

    # Record exposure event
    if entity_types:
        get_exposure_engine().record_event(ExposureEventRecord(
            synthetic_customer_id=customer_id,
            tenant_id=request.tenant_id,
            entity_types=entity_types,
            endpoint=request.endpoint,
            purpose=purpose,
            destination=request.destination_service or "unknown",
            protection_action=policy_decision.overall_action.value,
            session_id=request.session_id,
        ))

    # Audit
    audit_event_id, audit_event_hash = await record_audit_event(
        request_id=request_id,
        tenant_id=request.tenant_id,
        synthetic_customer_id=customer_id,
        event_type="PROTECTION_APPLIED",
        entity_types=entity_types,
        sensitivity_class=sensitivity_class,
        protection_action=policy_decision.overall_action.value,
        risk_score=risk_decomp.total_risk_score,
        model_versions=registry.get_versions(),
    )

    latency = (time.time() - start_time) * 1000
    logger.info(
        "protection_complete",
        request_id=request_id,
        action=policy_decision.overall_action.value,
        entity_count=len(raw_entities),
        latency_ms=round(latency, 2),
    )

    return ProtectResponse(
        request_id=request_id,
        protected_payload=protected_payload,
        protection_decision=policy_decision.overall_action,
        entity_decisions=entity_results,
        risk_score=risk_decomp.total_risk_score,
        risk_level=RiskLevel(risk_decomp.risk_level),
        audit_event_id=audit_event_id,
        audit_event_hash=audit_event_hash,
        processing_latency_ms=round(latency, 2),
    )
