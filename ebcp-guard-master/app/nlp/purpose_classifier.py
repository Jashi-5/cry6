"""
EBCP-Guard Purpose Classifier
================================
Wraps the fine-tuned DeBERTa-v3-small model for API purpose classification.
"""

from __future__ import annotations

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

PURPOSE_CLASSES = [
    "PAYMENT_PROCESSING", "FRAUD_DETECTION", "CUSTOMER_SUPPORT",
    "ANALYTICS", "MARKETING", "AUTHENTICATION", "REPORTING", "OTHER"
]


def build_purpose_input(
    endpoint: str,
    http_method: str,
    destination: str | None,
    payload_keys: list[str],
) -> str:
    """Build classifier input from API request metadata."""
    keys_ctx = ", ".join(payload_keys[:20]) if payload_keys else "none"
    dest_ctx = destination or "unknown"
    return (
        f"[ENDPOINT: {endpoint}] [METHOD: {http_method}] "
        f"[DESTINATION: {dest_ctx}] [FIELDS: {keys_ctx}]"
    )


def classify_purpose(
    model: Any,
    tokenizer: Any,
    input_text: str,
    device: str = "cpu",
) -> tuple[str, float, dict[str, float]]:
    """
    Classify the API processing purpose.

    Returns:
        Tuple of (predicted_purpose, confidence, class_probabilities).
    """
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba([input_text])[0]
            classes = list(model.classes_)
            pred_purpose = str(model.predict([input_text])[0])
            idx = classes.index(pred_purpose) if pred_purpose in classes else 0
            conf = float(probs[idx])
            class_probs = {cls: round(float(p), 4) for cls, p in zip(classes, probs)}
            return pred_purpose, round(conf, 4), class_probs

        inputs = tokenizer(
            input_text,
            return_tensors="pt",
            truncation=True,
            max_length=256,
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
        num_classes = len(PURPOSE_CLASSES)
        predicted_purpose = (
            PURPOSE_CLASSES[predicted_idx] if predicted_idx < num_classes else "OTHER"
        )
        confidence = float(probs[predicted_idx]) if predicted_idx < len(probs) else 0.0

        class_probs = {
            cls: round(float(p), 4)
            for cls, p in zip(PURPOSE_CLASSES, probs[:num_classes])
        }

        return predicted_purpose, confidence, class_probs

    except Exception as exc:
        logger.error("purpose_classification_error", error=str(exc))
        # Fail-safe: return OTHER with zero confidence (triggers conservative handling)
        return "OTHER", 0.0, {cls: 1.0 / len(PURPOSE_CLASSES) for cls in PURPOSE_CLASSES}
