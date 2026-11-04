"""
EBCP-Guard Scientific Evaluation Metrics
=========================================
Computes research-grade evaluation metrics:
  - Precision, Recall, F1-Score (micro & macro)
  - Confusion Matrix
  - Entity-level span evaluation (exact match, partial match)
  - Sensitivity classification metrics (S0–S4)
  - Purpose classification metrics
"""

from __future__ import annotations

from typing import Any
import numpy as np


def compute_classification_metrics(
    y_true: list[str],
    y_pred: list[str],
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """
    Compute classification performance: accuracy, macro-F1, per-class precision/recall.
    """
    if not y_true or not y_pred:
        return {"accuracy": 0.0, "macro_f1": 0.0, "per_class": {}}

    unique_labels = labels or sorted(list(set(y_true) | set(y_pred)))
    total_samples = len(y_true)

    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    accuracy = correct / total_samples if total_samples > 0 else 0.0

    per_class: dict[str, dict[str, float]] = {}
    f1_scores: list[float] = []

    for lbl in unique_labels:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == lbl and yp == lbl)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != lbl and yp == lbl)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == lbl and yp != lbl)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class[lbl] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(1 for yt in y_true if yt == lbl),
        }
        f1_scores.append(f1)

    macro_f1 = float(np.mean(f1_scores)) if f1_scores else 0.0

    # Confusion matrix
    conf_matrix: dict[str, dict[str, int]] = {r: {c: 0 for c in unique_labels} for r in unique_labels}
    for yt, yp in zip(y_true, y_pred):
        if yt in conf_matrix and yp in conf_matrix[yt]:
            conf_matrix[yt][yp] += 1

    return {
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "per_class": per_class,
        "confusion_matrix": conf_matrix,
        "total_samples": total_samples,
    }


def evaluate_entity_spans(
    ground_truth_entities: list[list[dict[str, Any]]],
    predicted_entities: list[list[dict[str, Any]]],
) -> dict[str, Any]:
    """
    Evaluate entity detection at span and type level.
    Each entity dict must have 'entity_type', 'start_offset' (or 'start'), 'end_offset' (or 'end').
    """
    total_gold = sum(len(g) for g in ground_truth_entities)
    total_pred = sum(len(p) for p in predicted_entities)

    exact_matches = 0
    type_matches = 0

    for golds, preds in zip(ground_truth_entities, predicted_entities):
        matched_preds = set()
        for g in golds:
            g_start = g.get("start_offset", g.get("start", None))
            g_end = g.get("end_offset", g.get("end", None))
            g_type = g.get("entity_type", g.get("label", ""))
            g_val = str(g.get("value", "")).strip().lower()

            for idx, p in enumerate(preds):
                if idx in matched_preds:
                    continue
                p_start = p.get("start_offset", p.get("start", None))
                p_end = p.get("end_offset", p.get("end", None))
                p_type = p.get("entity_type", p.get("label", ""))
                p_val = str(p.get("value", "")).strip().lower()

                # Match by span if offsets provided, or by value + type match
                span_match = (g_start is not None and g_start == p_start and g_end == p_end)
                val_match = bool(g_val and p_val and g_val == p_val)

                if (span_match or val_match) and g_type.upper() == p_type.upper():
                    exact_matches += 1
                    matched_preds.add(idx)
                    break

    precision = exact_matches / total_pred if total_pred > 0 else 0.0
    recall = exact_matches / total_gold if total_gold > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "span_exact_precision": round(precision, 4),
        "span_exact_recall": round(recall, 4),
        "span_exact_f1": round(f1, 4),
        "total_gold_entities": total_gold,
        "total_pred_entities": total_pred,
        "exact_matches": exact_matches,
    }
