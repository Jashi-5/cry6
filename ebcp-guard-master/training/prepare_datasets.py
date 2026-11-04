"""
EBCP-Guard Dataset Splitting and Preparation Pipeline
======================================================
Splits the synthetic dataset into identity-disjoint Train (70%), Val (15%), Test (15%).
Preserves multi-request sequences within splits to prevent temporal leakage.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SYNTHETIC_DIR = BASE_DIR / "dataset" / "synthetic"
SPLITS_DIR = BASE_DIR / "dataset" / "splits"
SPLITS_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42

def prepare_splits():
    random.seed(SEED)
    input_file = SYNTHETIC_DIR / "bankpii_api_requests.jsonl"
    if not input_file.exists():
        print(f"Error: {input_file} not found. Run generate_bankpii_dataset.py first.")
        return

    records = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    # Group by customer ID to enforce identity-disjoint splitting
    customer_groups: dict[str, list[dict]] = {}
    for r in records:
        cid = r.get("synthetic_customer_id", "unknown")
        customer_groups.setdefault(cid, []).append(r)

    customers = list(customer_groups.keys())
    random.shuffle(customers)

    n_total = len(customers)
    n_train = int(n_total * 0.70)
    n_val = int(n_total * 0.15)

    train_cids = set(customers[:n_train])
    val_cids = set(customers[n_train:n_train + n_val])
    test_cids = set(customers[n_train + n_val:])

    train_records = [r for cid in train_cids for r in customer_groups[cid]]
    val_records = [r for cid in val_cids for r in customer_groups[cid]]
    test_records = [r for cid in test_cids for r in customer_groups[cid]]

    def save_split(data: list[dict], name: str):
        p = SPLITS_DIR / f"{name}.jsonl"
        with open(p, "w", encoding="utf-8") as f:
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"Saved {name}: {len(data)} records across {len(set(r.get('synthetic_customer_id') for r in data))} unique identities to {p}")

    save_split(train_records, "train")
    save_split(val_records, "val")
    save_split(test_records, "test")

    print("\nIdentity leakage check:")
    assert len(train_cids & val_cids) == 0, "Leakage between train and val!"
    assert len(train_cids & test_cids) == 0, "Leakage between train and test!"
    assert len(val_cids & test_cids) == 0, "Leakage between val and test!"
    print("Verification PASSED: 0 identity overlap across train/val/test splits.")

if __name__ == "__main__":
    prepare_splits()
