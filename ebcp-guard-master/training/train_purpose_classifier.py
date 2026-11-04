"""
EBCP-Guard API Purpose Classifier Training Pipeline
=====================================================
Trains and evaluates API purpose classification:
  PAYMENT_PROCESSING, FRAUD_DETECTION, CUSTOMER_SUPPORT,
  ANALYTICS, MARKETING, AUTHENTICATION, REPORTING, OTHER.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import json
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from app.evaluation.metrics import compute_classification_metrics

BASE_DIR = Path(__file__).resolve().parent.parent
SPLITS_DIR = BASE_DIR / "dataset" / "splits"
CHECKPOINT_DIR = BASE_DIR / "models" / "checkpoints" / "purpose_classifier"
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

PURPOSE_CLASSES = [
    "PAYMENT_PROCESSING", "FRAUD_DETECTION", "CUSTOMER_SUPPORT",
    "ANALYTICS", "MARKETING", "AUTHENTICATION", "REPORTING", "OTHER"
]

def load_purpose_split(split_name: str) -> tuple[list[str], list[str]]:
    path = SPLITS_DIR / f"{split_name}.jsonl"
    texts = []
    labels = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            endpoint = item.get("endpoint", "")
            method = item.get("http_method", "")
            dest = item.get("destination", "")
            payload = item.get("original_payload", {})
            fields = " ".join(list(payload.keys()))

            input_text = f"[ENDPOINT: {endpoint}] [METHOD: {method}] [DESTINATION: {dest}] [FIELDS: {fields}]"
            texts.append(input_text)
            labels.append(item.get("processing_purpose", "OTHER"))
    return texts, labels

def train_purpose_model():
    print("=" * 60)
    print("EBCP-Guard: Training API Purpose Classifier")
    print("=" * 60)

    train_x, train_y = load_purpose_split("train")
    test_x, test_y = load_purpose_split("test")

    print(f"Loaded datasets: Train={len(train_x)}, Test={len(test_x)}")

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2))),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=400, random_state=42)),
    ])

    print("Fitting purpose classifier...")
    pipeline.fit(train_x, train_y)

    print("Evaluating on test split...")
    test_preds = pipeline.predict(test_x)
    metrics = compute_classification_metrics(test_y, list(test_preds), PURPOSE_CLASSES)

    print(f"\nTest Accuracy: {metrics['accuracy']:.4f}")
    print(f"Test Macro-F1: {metrics['macro_f1']:.4f}")
    print("\nPer-Class Metrics:")
    for cls, val in metrics["per_class"].items():
        if val["support"] > 0:
            print(f"  {cls}: Precision={val['precision']:.3f}, Recall={val['recall']:.3f}, F1={val['f1']:.3f} (support={val['support']})")

    model_path = CHECKPOINT_DIR / "classifier.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(pipeline, f)

    meta = {
        "model_name": "api_purpose_classifier",
        "version": "1.0.0",
        "classes": PURPOSE_CLASSES,
        "metrics": metrics,
    }
    with open(CHECKPOINT_DIR / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"\nModel and metadata saved to: {CHECKPOINT_DIR}")
    return metrics

if __name__ == "__main__":
    train_purpose_model()
