"""
Head-to-head sensitive-entity detection benchmark: EBCP-Guard vs Microsoft Presidio.

Runs both detectors on the same held-out test split (dataset/splits/test.jsonl),
on the same input text (the JSON-serialised request payload), and scores them
against the same gold entities. Only the 7 gold entity types in the dataset are
scored, so neither side is penalised for detecting extra types (IFSC, DOB, ...).

Systems:
  A. EBCP-Guard        : app.detection.regex_detector (+ entity_validator confidence)
  B. Presidio (default): AnalyzerEngine with stock recognizers, en_core_web_lg
  C. Presidio + custom : same as B, plus the EBCP-Guard UPI and account-number
                         regexes added as PatternRecognizers (isolates the engine
                         difference from the coverage difference)

Requires presidio-analyzer and the en_core_web_lg spaCy model (see requirements.txt).
Run from the project root:  python scripts/head_to_head.py
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.detection.entity_validator import validate_entity  # noqa: E402
from app.detection.regex_detector import _PATTERNS, get_regex_detector  # noqa: E402

TEST_PATH = BASE_DIR / "dataset" / "splits" / "test.jsonl"
REPORT_PATH = BASE_DIR / "dataset" / "reports" / "head_to_head_report.json"

GOLD_TYPES = ["EMAIL", "PHONE", "PERSON", "ACCOUNT_NUMBER", "UPI_ID", "PAN", "AADHAAR"]

# Gold type -> Presidio entity name (stock recognizers only)
PRESIDIO_STOCK = {
    "EMAIL": "EMAIL_ADDRESS",
    "PHONE": "PHONE_NUMBER",
    "PERSON": "PERSON",
    "PAN": "IN_PAN",
    "AADHAAR": "IN_AADHAAR",
}
PRESIDIO_TO_GOLD = {v: k for k, v in PRESIDIO_STOCK.items()}


def norm(value: str) -> str:
    return re.sub(r"[\s\-]", "", str(value)).lower()


def load_records(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def gold_set(record: dict) -> set[tuple[str, str]]:
    return {
        (e["entity_type"], norm(e["value"]))
        for e in record.get("detected_entities", [])
        if e["entity_type"] in GOLD_TYPES
    }


def score(records: list[dict], preds: list[set[tuple[str, str]]]) -> dict:
    counts = {t: {"tp": 0, "fp": 0, "fn": 0} for t in GOLD_TYPES}
    for rec, pred in zip(records, preds):
        gold = gold_set(rec)
        for t, v in gold:
            counts[t]["tp" if (t, v) in pred else "fn"] += 1
        for t, v in pred - gold:
            if t in counts:
                counts[t]["fp"] += 1

    def prf(c: dict) -> dict:
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return {**c, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}

    total = {k: sum(c[k] for c in counts.values()) for k in ("tp", "fp", "fn")}
    return {"micro": prf(total), "per_type": {t: prf(c) for t, c in counts.items()}}


def run_ebcp(records: list[dict]) -> tuple[list[set], list[float]]:
    detector = get_regex_detector()
    preds, times = [], []
    for rec in records:
        text = json.dumps(rec["original_payload"])
        t0 = time.perf_counter()
        matches = detector.detect(text)
        out = set()
        for m in matches:
            validate_entity(m.entity_type, m.value)  # confidence only; kept as in repo eval
            out.add((m.entity_type, norm(m.value)))
        times.append((time.perf_counter() - t0) * 1000)
        preds.append(out)
    return preds, times


def build_presidio(custom: bool):
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    })
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=["en"], nlp_engine=provider.create_engine())
    if custom:
        for entity, name in [("UPI_ID", "upi"), ("ACCOUNT_NUMBER", "account")]:
            pats = [
                Pattern(name=f"ebcp_{p.pattern_name}", regex=p.pattern.pattern, score=p.confidence)
                for p in _PATTERNS if p.entity_type == entity
            ]
            registry.add_recognizer(PatternRecognizer(supported_entity=entity, patterns=pats))
    return AnalyzerEngine(nlp_engine=provider.create_engine(), registry=registry, supported_languages=["en"])


def run_presidio(records: list[dict], custom: bool) -> tuple[list[set], list[float]]:
    analyzer = build_presidio(custom)
    entities = list(PRESIDIO_STOCK.values()) + (["UPI_ID", "ACCOUNT_NUMBER"] if custom else [])
    preds, times = [], []
    for rec in records:
        text = json.dumps(rec["original_payload"])
        t0 = time.perf_counter()
        results = analyzer.analyze(text=text, language="en", entities=entities)
        out = set()
        for r in results:
            gold_type = PRESIDIO_TO_GOLD.get(r.entity_type, r.entity_type)
            out.add((gold_type, norm(text[r.start:r.end])))
        times.append((time.perf_counter() - t0) * 1000)
        preds.append(out)
    return preds, times


def latency(times: list[float]) -> dict:
    s = sorted(times)
    return {
        "mean_ms": round(sum(s) / len(s), 3),
        "p50_ms": round(s[len(s) // 2], 3),
        "p95_ms": round(s[int(len(s) * 0.95) - 1], 3),
    }


def print_table(results: dict) -> None:
    header = f"{'System':<28}{'Precision':>10}{'Recall':>9}{'F1':>8}{'TP':>6}{'FP':>6}{'FN':>6}{'p95 ms':>9}"
    print(header)
    print("-" * len(header))
    for name, r in results.items():
        m = r["scores"]["micro"]
        print(f"{name:<28}{m['precision']:>10.4f}{m['recall']:>9.4f}{m['f1']:>8.4f}"
              f"{m['tp']:>6}{m['fp']:>6}{m['fn']:>6}{r['latency']['p95_ms']:>9.3f}")
    print("\nPer-type F1:")
    types_line = f"{'System':<28}" + "".join(f"{t:>16}" for t in GOLD_TYPES)
    print(types_line)
    for name, r in results.items():
        row = f"{name:<28}" + "".join(f"{r['scores']['per_type'][t]['f1']:>16.4f}" for t in GOLD_TYPES)
        print(row)


def main() -> None:
    records = load_records(TEST_PATH)
    print(f"Test records: {len(records)} | gold entities (scored types): "
          f"{sum(len(gold_set(r)) for r in records)}\n")

    systems = {}
    preds, times = run_ebcp(records)
    systems["EBCP-Guard (regex)"] = {"scores": score(records, preds), "latency": latency(times)}

    preds, times = run_presidio(records, custom=False)
    systems["Presidio (stock)"] = {"scores": score(records, preds), "latency": latency(times)}

    preds, times = run_presidio(records, custom=True)
    systems["Presidio + EBCP regexes"] = {"scores": score(records, preds), "latency": latency(times)}

    print_table(systems)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump({"test_records": len(records), "gold_types": GOLD_TYPES, "systems": systems}, f, indent=2)
    print(f"\nSaved: {REPORT_PATH}")


if __name__ == "__main__":
    main()
