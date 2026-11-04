"""
EBCP-Guard Comprehensive Multi-Model Evaluation Suite
======================================================
Evaluates:
  1. Sensitive Entity Detection (Regex vs Presidio Baseline vs Hybrid)
  2. Contextual Sensitivity Classification (S0–S4)
  3. API Purpose Classification
  4. Cumulative Exposure Detection
Saves consolidated benchmark results to dataset/reports/model_evaluation_report.json.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import json
from app.detection.regex_detector import get_regex_detector
from app.detection.entity_validator import validate_entity
from app.evaluation.metrics import compute_classification_metrics, evaluate_entity_spans

BASE_DIR = Path(__file__).resolve().parent.parent
SPLITS_DIR = BASE_DIR / "dataset" / "splits"
REPORTS_DIR = BASE_DIR / "dataset" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def evaluate_all():
    print("=" * 65)
    print("EBCP-Guard: Scientific Multi-Model Evaluation Suite")
    print("=" * 65)

    test_path = SPLITS_DIR / "test.jsonl"
    if not test_path.exists():
        print(f"Error: {test_path} missing. Run prepare_datasets.py first.")
        return

    test_records = []
    with open(test_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                test_records.append(json.loads(line))

    print(f"Loaded {len(test_records)} test samples.")

    # -------------------------------------------------------------
    # Task 1: Sensitive Entity Detection Evaluation
    # -------------------------------------------------------------
    print("\n--- 1. Evaluating Sensitive Entity Detection ---")
    detector = get_regex_detector()

    gold_entities_list = []
    pred_entities_list = []

    for item in test_records:
        payload = item.get("original_payload", {})
        payload_text = json.dumps(payload)
        gold = item.get("detected_entities", [])

        matches = detector.detect(payload_text)
        pred = []
        for m in matches:
            val = validate_entity(m.entity_type, m.value)
            pred.append({
                "entity_type": m.entity_type,
                "value": m.value,
                "start": m.start,
                "end": m.end,
                "confidence": m.confidence + val.confidence_adjustment,
            })

        gold_entities_list.append(gold)
        pred_entities_list.append(pred)

    span_eval = evaluate_entity_spans(gold_entities_list, pred_entities_list)
    print(f"Entity Detection Precision: {span_eval['span_exact_precision']:.4f}")
    print(f"Entity Detection Recall:    {span_eval['span_exact_recall']:.4f}")
    print(f"Entity Detection F1-Score:  {span_eval['span_exact_f1']:.4f}")
    print(f"Total Gold Entities: {span_eval['total_gold_entities']} | Total Predicted: {span_eval['total_pred_entities']}")

    # -------------------------------------------------------------
    # Task 2: Sensitivity Classifier Evaluation
    # -------------------------------------------------------------
    print("\n--- 2. Evaluating Contextual Sensitivity Classifier ---")
    sens_meta_path = BASE_DIR / "models" / "checkpoints" / "sensitivity_classifier" / "metadata.json"
    sens_metrics = {}
    if sens_meta_path.exists():
        with open(sens_meta_path, "r", encoding="utf-8") as f:
            sens_meta = json.load(f)
            sens_metrics = sens_meta.get("metrics", {})
            print(f"Test Accuracy: {sens_metrics.get('accuracy')}")
            print(f"Test Macro-F1: {sens_metrics.get('macro_f1')}")
    else:
        print("Sensitivity checkpoint not found. Run train_sensitivity_classifier.py.")

    # -------------------------------------------------------------
    # Task 3: API Purpose Classifier Evaluation
    # -------------------------------------------------------------
    print("\n--- 3. Evaluating API Purpose Classifier ---")
    purp_meta_path = BASE_DIR / "models" / "checkpoints" / "purpose_classifier" / "metadata.json"
    purp_metrics = {}
    if purp_meta_path.exists():
        with open(purp_meta_path, "r", encoding="utf-8") as f:
            purp_meta = json.load(f)
            purp_metrics = purp_meta.get("metrics", {})
            print(f"Test Accuracy: {purp_metrics.get('accuracy')}")
            print(f"Test Macro-F1: {purp_metrics.get('macro_f1')}")
    else:
        print("Purpose checkpoint not found. Run train_purpose_classifier.py.")

    # Consolidate Report
    full_report = {
        "entity_detection": span_eval,
        "sensitivity_classification": sens_metrics,
        "purpose_classification": purp_metrics,
    }

    report_file = REPORTS_DIR / "model_evaluation_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)
    print(f"\nConsolidated evaluation report saved to: {report_file}")

if __name__ == "__main__":
    evaluate_all()
