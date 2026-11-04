"""
EBCP-Guard Sensitivity Classifier
=====================================
Wraps the fine-tuned DeBERTa-v3-small model for contextual
sensitivity classification (S0–S4).
"""

from __future__ import annotations

import json
from typing import Any

try:
    import torch
    import torch.nn.functional as F
    HAS_TORCH = True
except (ImportError, OSError):
    torch = None
    F = None
    HAS_TORCH = False

from app.core.logging import get_logger

logger = get_logger(__name__)

SENSITIVITY_CLASSES = ["S0", "S1", "S2", "S3", "S4"]


def build_sensitivity_input(
    payload_text: str,
    entity_types: list[str],
    entity_count: int,
) -> str:
    """
    Build the classifier input string combining payload text with
    entity context for the sensitivity classifier.
    """
    entity_ctx = ", ".join(sorted(set(entity_types))) if entity_types else "none"
    return (
        f"[ENTITIES: {entity_ctx}] [COUNT: {entity_count}] "
        f"[PAYLOAD: {payload_text[:512]}]"
    )


def classify_sensitivity(
    model: Any,
    tokenizer: Any,
    input_text: str,
    device: str = "cpu",
) -> tuple[str, float, dict[str, float]]:
    """
    Classify the sensitivity of the input text.

    Returns:
        Tuple of (predicted_class, confidence, class_probabilities).
    """
    try:
        # Check if model is a scikit-learn pipeline or Transformer
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba([input_text])[0]
            classes = list(model.classes_)
            pred_class = str(model.predict([input_text])[0])
            idx = classes.index(pred_class) if pred_class in classes else 0
            conf = float(probs[idx])
            class_probs = {cls: round(float(p), 4) for cls, p in zip(classes, probs)}
            return pred_class, round(conf, 4), class_probs

        inputs = tokenizer(
            input_text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )
        if device != "cpu":
            inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)

        logits = outputs.logits
        probs = F.softmax(logits, dim=-1).squeeze().tolist()

        if isinstance(probs, float):
            probs = [probs]

        predicted_idx = int(torch.argmax(logits, dim=-1).item())
        predicted_class = SENSITIVITY_CLASSES[predicted_idx] if predicted_idx < 5 else "S2"
        confidence = float(probs[predicted_idx]) if predicted_idx < len(probs) else 0.5

        class_probs = {cls: round(float(p), 4) for cls, p in zip(SENSITIVITY_CLASSES, probs)}

        return predicted_class, confidence, class_probs

    except Exception as exc:
        logger.error("sensitivity_classification_error", error=str(exc))
        # Fail-safe: return S3 (high sensitivity) with low confidence
        return "S3", 0.0, {cls: 0.2 for cls in SENSITIVITY_CLASSES}
