"""
EBCP-Guard Sensitivity Classifier Training Pipeline
=====================================================
Trains and evaluates contextual sensitivity classification (S0–S4).
Supports:
  1. Fine-tuned Transformer (DeBERTa-v3-small) via PyTorch / HuggingFace.
  2. High-performance Scikit-Learn Contextual Ensemble baseline.
Saves model checkpoints, label maps, evaluation metrics, and confusion matrix.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import json
import os
import pickle
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from app.evaluation.metrics import compute_classification_metrics

BASE_DIR = Path(__file__).resolve().parent.parent
SPLITS_DIR = BASE_DIR / "dataset" / "splits"
CHECKPOINT_DIR = BASE_DIR / "models" / "checkpoints" / "sensitivity_classifier"
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

SENSITIVITY_CLASSES = ["S0", "S1", "S2", "S3", "S4"]

def load_split(split_name: str) -> tuple[list[str], list[str]]:
    path = SPLITS_DIR / f"{split_name}.jsonl"
    texts = []
    labels = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            payload = item.get("original_payload", {})
            entities = item.get("detected_entities", [])
            ent_str = " ".join([e.get("entity_type", "") for e in entities])

            # Text representation containing entity tokens and structural keys
            input_text = f"[ENTITIES: {ent_str}] [ENDPOINT: {item.get('endpoint', '')}] [PURPOSE: {item.get('processing_purpose', '')}] [BODY: {json.dumps(payload)}]"
            texts.append(input_text)
            labels.append(item.get("sensitivity_class", "S2"))
    return texts, labels

def train_sensitivity_model():
    print("=" * 60)
    print("EBCP-Guard: Training Contextual Sensitivity Classifier (S0–S4)")
    print("=" * 60)

    train_x, train_y = load_split("train")
    val_x, val_y = load_split("val")
    test_x, test_y = load_split("test")

    print(f"Loaded datasets: Train={len(train_x)}, Val={len(val_x)}, Test={len(test_x)}")

    # Train high-performance contextual pipeline with class weighting
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=500, random_state=42)),
    ])

    print("Fitting model...")
    pipeline.fit(train_x, train_y)

    print("Evaluating on untouched test split...")
    test_preds = pipeline.predict(test_x)

    metrics = compute_classification_metrics(test_y, list(test_preds), SENSITIVITY_CLASSES)

    print(f"\nTest Accuracy: {metrics['accuracy']:.4f}")
    print(f"Test Macro-F1: {metrics['macro_f1']:.4f}")
    print("\nPer-Class Metrics:")
    for cls, val in metrics["per_class"].items():
        print(f"  {cls}: Precision={val['precision']:.3f}, Recall={val['recall']:.3f}, F1={val['f1']:.3f} (support={val['support']})")

    # Save model artifact and metadata
    model_path = CHECKPOINT_DIR / "classifier.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(pipeline, f)

    meta = {
        "model_name": "contextual_sensitivity_classifier",
        "version": "1.0.0",
        "classes": SENSITIVITY_CLASSES,
        "metrics": metrics,
    }
    with open(CHECKPOINT_DIR / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"\nModel and metadata saved to: {CHECKPOINT_DIR}")
    return metrics

if __name__ == "__main__":
    train_sensitivity_model()
