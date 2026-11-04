"""
EBCP-Guard GLiNER Entity Detector
====================================
Wraps the GLiNER-PII model for contextual entity detection.
GLiNER (Generalist and Lightweight Named Entity Recognition) uses
a bi-encoder approach to identify entities based on provided labels,
without requiring fine-tuning for every label set.
"""

from __future__ import annotations

import json
from typing import Any

from app.core.exceptions import ModelNotLoadedError
from app.core.logging import get_logger
from app.detection.entity_validator import validate_entity
from app.detection.regex_detector import RegexMatch, get_regex_detector

logger = get_logger(__name__)

# GLiNER entity labels to detect — mapped to our internal types
GLINER_LABELS = [
    "person",
    "email",
    "phone number",
    "address",
    "credit card number",
    "bank account number",
    "date of birth",
    "social security number",
    "passport number",
    "driver's license",
    "ip address",
    "organization",
    "location",
    "medical condition",
    "financial amount",
]

# Normalize GLiNER output labels to our internal entity type vocabulary
_GLINER_LABEL_MAP = {
    "person": "PERSON",
    "email": "EMAIL",
    "phone number": "PHONE",
    "address": "ADDRESS",
    "credit card number": "CARD_NUMBER",
    "bank account number": "ACCOUNT_NUMBER",
    "date of birth": "DATE_OF_BIRTH",
    "social security number": "SSN",
    "ip address": "IP_ADDRESS",
    "organization": "ORGANIZATION",
    "location": "LOCATION",
    "financial amount": "TRANSACTION_AMOUNT",
}


class GLiNERDetector:
    """
    Wraps GLiNER for entity detection against the provided label set.
    Integrates with regex detection for hybrid detection.
    """

    def __init__(self, model_object: Any) -> None:
        self._model = model_object
        self._regex = get_regex_detector()

    def detect_entities(
        self, text: str, threshold: float = 0.50
    ) -> list[dict[str, Any]]:
        """
        Detect entities using GLiNER model.

        Args:
            text:      Input text to analyze.
            threshold: Minimum confidence threshold for GLiNER predictions.

        Returns:
            List of entity dicts with type, span offsets, and confidence.
        """
        if not text or not text.strip():
            return []

        try:
            raw_entities = self._model.predict_entities(
                text=text,
                labels=GLINER_LABELS,
                threshold=threshold,
            )
        except Exception as exc:
            logger.error("gliner_inference_error", error=str(exc))
            raise

        results = []
        for ent in raw_entities:
            internal_type = _GLINER_LABEL_MAP.get(ent["label"].lower(), ent["label"].upper())
            val_result = validate_entity(internal_type, ent["text"])

            adj_confidence = min(1.0, max(0.0, ent["score"] + val_result.confidence_adjustment))

            results.append({
                "entity_type": internal_type,
                "entity_label": ent["label"],
                "start_offset": ent["start"],
                "end_offset": ent["end"],
                "value": ent["text"],
                "confidence": round(adj_confidence, 4),
                "detection_method": "gliner",
                "is_validated": val_result.is_valid,
            })

        return results


def run_hybrid_detection(
    text: str,
    gliner_model: Any | None = None,
    threshold: float = 0.50,
) -> list[dict[str, Any]]:
    """
    Run the hybrid detection pipeline:
    1. GLiNER contextual detection (if model available).
    2. Regex deterministic detection.
    3. Merge results, prefer higher-confidence detection at overlapping spans.
    4. Validate structured entities.

    Args:
        text:         Input text string.
        gliner_model: Optional loaded GLiNER model object.
        threshold:    Minimum confidence for GLiNER.

    Returns:
        Merged, deduplicated list of detected entity dicts.
    """
    all_entities: list[dict[str, Any]] = []

    # --- GLiNER detection ---
    if gliner_model is not None:
        try:
            detector = GLiNERDetector(gliner_model)
            gliner_entities = detector.detect_entities(text, threshold)
            all_entities.extend(gliner_entities)
        except Exception as exc:
            logger.warning("gliner_detection_failed_using_regex_only", error=str(exc))

    # --- Regex detection ---
    regex_detector = get_regex_detector()
    regex_matches: list[RegexMatch] = regex_detector.detect(text)
    for match in regex_matches:
        val_result = validate_entity(match.entity_type, match.value)
        adj_conf = min(1.0, max(0.0, match.confidence + val_result.confidence_adjustment))
        all_entities.append({
            "entity_type": match.entity_type,
            "entity_label": match.entity_type,
            "start_offset": match.start,
            "end_offset": match.end,
            "value": match.value,
            "confidence": round(adj_conf, 4),
            "detection_method": "regex" if gliner_model is None else "hybrid",
            "is_validated": val_result.is_valid,
        })

    return _merge_and_deduplicate(all_entities)


def _merge_and_deduplicate(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Remove overlapping entity spans, keeping the highest-confidence detection.
    Sorts result by start_offset for consistent processing.
    """
    if not entities:
        return []

    sorted_ents = sorted(
        entities,
        key=lambda e: (e["confidence"], e["end_offset"] - e["start_offset"]),
        reverse=True,
    )

    selected: list[dict[str, Any]] = []
    occupied: list[tuple[int, int]] = []

    for ent in sorted_ents:
        s, e = ent["start_offset"], ent["end_offset"]
        if not any(not (e <= os or s >= oe) for os, oe in occupied):
            selected.append(ent)
            occupied.append((s, e))

    return sorted(selected, key=lambda e: e["start_offset"])
