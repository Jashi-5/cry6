"""
EBCP-Guard Analysis Service
=============================
Orchestrates the complete analysis pipeline for a single request:
  1. Parse and flatten payload to text.
  2. Hybrid entity detection (GLiNER + regex + validation).
  3. Contextual sensitivity classification.
  4. API purpose classification.
  5. Cumulative exposure risk scoring.
  6. Policy decision.

Returns a structured AnalyzeResponse.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from app.api.schemas.schemas import (
    AnalyzeRequest, AnalyzeResponse,
    DetectedEntitySchema, DetectionMethod, ExposureScoreSchema,
    ProtectionAction, ProcessingPurpose, RiskLevel, SensitivityClass,
)
from app.config import get_settings
from app.core.logging import get_logger
from app.detection.gliner_detector import run_hybrid_detection
from app.exposure.cumulative_exposure_engine import ExposureEventRecord, get_exposure_engine
from app.nlp.model_loader import get_model_registry
from app.nlp.sensitivity_classifier import build_sensitivity_input, classify_sensitivity
from app.nlp.purpose_classifier import build_purpose_input, classify_purpose
from app.policy.policy_engine import get_policy_engine

logger = get_logger(__name__)
settings = get_settings()


def _flatten_payload(payload: dict[str, Any], prefix: str = "") -> str:
    """Flatten a nested JSON payload to a text string for NLP processing."""
    parts = []
    for key, val in payload.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(val, dict):
            parts.append(_flatten_payload(val, full_key))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    parts.append(_flatten_payload(item, full_key))
                else:
                    parts.append(f"{full_key}: {item}")
        else:
            parts.append(f"{full_key}: {val}")
    return " | ".join(parts)


async def run_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Run the full EBCP-Guard analysis pipeline.

    Args:
        request: Validated AnalyzeRequest payload.

    Returns:
        AnalyzeResponse with detected entities, classifications, exposure score,
        and recommended protection action.
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())

    payload_text = _flatten_payload(request.payload)
    payload_keys = list(request.payload.keys())

    registry = get_model_registry()

    # --- Step 1: Entity Detection ---
    t1 = time.time()
    try:
        gliner = registry.get_gliner()
    except Exception:
        gliner = None

    raw_entities = run_hybrid_detection(payload_text, gliner_model=gliner)
    entity_types = [e["entity_type"] for e in raw_entities]
    t1_elapsed = (time.time() - t1) * 1000

    # --- Step 2: Sensitivity Classification ---
    t2 = time.time()
    sensitivity_class = "S2"
    sensitivity_confidence = 0.0
    sensitivity_probs: dict[str, float] = {}

    try:
        sens_model, sens_tokenizer, _ = registry.get_sensitivity_classifier()
        sens_input = build_sensitivity_input(payload_text, entity_types, len(raw_entities))
        sensitivity_class, sensitivity_confidence, sensitivity_probs = classify_sensitivity(
            sens_model, sens_tokenizer, sens_input, settings.model_device
        )
    except Exception as exc:
        logger.warning("sensitivity_classifier_unavailable", error=str(exc))
        # Fail-closed: escalate to S3 with zero confidence
        sensitivity_class = "S3"
        sensitivity_confidence = 0.0

    t2_elapsed = (time.time() - t2) * 1000

    # --- Step 3: Purpose Classification ---
    t3 = time.time()
    purpose = "OTHER"
    purpose_confidence = 0.0
    purpose_probs: dict[str, float] = {}

    try:
        purp_model, purp_tokenizer, _ = registry.get_purpose_classifier()
        purp_input = build_purpose_input(
            request.endpoint, request.http_method,
            request.destination_service, payload_keys
        )
        purpose, purpose_confidence, purpose_probs = classify_purpose(
            purp_model, purp_tokenizer, purp_input, settings.model_device
        )
    except Exception as exc:
        logger.warning("purpose_classifier_unavailable", error=str(exc))
        purpose = "OTHER"
        purpose_confidence = 0.0

    # Override with hint if provided and confidence is low
    if request.processing_purpose_hint and purpose_confidence < settings.model_confidence_threshold:
        purpose = request.processing_purpose_hint.value
        purpose_confidence = 1.0  # Trust explicit caller hint
    t3_elapsed = (time.time() - t3) * 1000

    # --- Step 4: Cumulative Exposure Scoring ---
    t4 = time.time()
    exposure_engine = get_exposure_engine()
    customer_id = request.synthetic_customer_id or f"anon_{request_id[:8]}"

    risk_decomp = exposure_engine.compute_risk(
        synthetic_customer_id=customer_id,
        current_entity_types=entity_types,
        current_sensitivity_class=sensitivity_class,
        destination=request.destination_service or "unknown",
        purpose=purpose,
        tenant_id=request.tenant_id,
    )
    t4_elapsed = (time.time() - t4) * 1000

    # --- Step 5: Policy Decision ---
    policy_engine = get_policy_engine()
    policy_decision = policy_engine.evaluate(
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

    total_latency = (time.time() - start_time) * 1000

    # Log safe event (no PII)
    logger.info(
        "analysis_complete",
        request_id=request_id,
        entity_count=len(raw_entities),
        entity_types=entity_types,
        sensitivity_class=sensitivity_class,
        purpose=purpose,
        risk_level=risk_decomp.risk_level,
        recommended_action=policy_decision.overall_action.value,
        latency_ms=round(total_latency, 2),
    )

    # Build response
    detected_schemas = [
        DetectedEntitySchema(
            entity_type=e["entity_type"],
            entity_label=e.get("entity_label"),
            start_offset=e["start_offset"],
            end_offset=e["end_offset"],
            confidence=e["confidence"],
            detection_method=DetectionMethod(
                "hybrid" if gliner is not None else "regex"
            ),
            sensitivity_class=SensitivityClass(sensitivity_class),
            is_validated=e.get("is_validated", False),
        )
        for e in raw_entities
    ]

    return AnalyzeResponse(
        request_id=request_id,
        detected_entities=detected_schemas,
        entity_count=len(detected_schemas),
        sensitivity_class=SensitivityClass(sensitivity_class),
        sensitivity_confidence=round(sensitivity_confidence, 4),
        purpose=ProcessingPurpose(purpose),
        purpose_confidence=round(purpose_confidence, 4),
        requires_review=policy_decision.requires_review,
        exposure_score=ExposureScoreSchema(
            sensitivity_score=risk_decomp.sensitivity_score,
            cumulative_score=risk_decomp.cumulative_score,
            linkability_score=risk_decomp.linkability_score,
            destination_trust_score=risk_decomp.destination_trust_score,
            total_risk_score=risk_decomp.total_risk_score,
            risk_level=RiskLevel(risk_decomp.risk_level),
            contributing_factors=risk_decomp.contributing_factors,
        ),
        recommended_action=policy_decision.overall_action,
        processing_latency_ms=round(total_latency, 2),
        model_versions=registry.get_versions(),
    )
