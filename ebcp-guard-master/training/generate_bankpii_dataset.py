"""
EBCP-Guard Synthetic Banking Dataset Generator
================================================
Generates realistic synthetic banking API records for the BankPII-API dataset.
All data is SYNTHETIC — no real customer identifiers, valid credentials,
or actual financial data.

Generation targets (initial batch):
  - General PII:           5,000
  - Financial PII:         4,000
  - Indian banking PII:    2,500
  - API request/response:  3,000
  - Application logs:      2,500
  - Purpose classification: 1,500
  - Multi-request exposure:  1,000
  Total: ~20,000 (expandable to 195,000)
"""

from __future__ import annotations

import json
import random
import re
import string
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    from faker import Faker
    from faker.providers import bank, internet, person, phone_number
    HAS_FAKER = True
except ImportError:
    HAS_FAKER = False
    print("WARNING: Faker not installed. Run: pip install faker")

# Indian locale faker
fake_in = Faker("en_IN") if HAS_FAKER else None
fake_us = Faker("en_US") if HAS_FAKER else None

OUTPUT_DIR = Path(__file__).parent.parent / "dataset" / "synthetic"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------------ #
# Synthetic Indian Banking Identifier Generators
# ------------------------------------------------------------------ #

def gen_pan() -> str:
    """Generate a synthetic PAN-format identifier (non-functional)."""
    letters = string.ascii_uppercase
    entity_codes = "PCFHGABTLJBG"
    return (
        "".join(random.choices(letters, k=3))
        + random.choice(entity_codes)
        + random.choice(letters)
        + "".join(random.choices(string.digits, k=4))
        + random.choice(letters)
    )


def gen_aadhaar() -> str:
    """Generate a 12-digit synthetic Aadhaar-format number."""
    first = random.choice("23456789")
    rest = "".join(random.choices(string.digits, k=11))
    num = first + rest
    return f"{num[:4]} {num[4:8]} {num[8:]}"


def gen_ifsc() -> str:
    """Generate a synthetic IFSC code."""
    banks = ["HDFC", "SBIN", "ICIC", "AXIS", "KOTK", "INDB", "PUNB", "CNRB"]
    bank_code = random.choice(banks)
    branch = "".join(random.choices(string.digits + string.ascii_uppercase, k=6))
    return f"{bank_code}0{branch}"


def gen_upi() -> str:
    """Generate a synthetic UPI ID."""
    handles = ["oksbi", "okaxis", "okhdfcbank", "okicici", "ybl", "paytm", "ibl"]
    local_part = fake_in.user_name() if fake_in else "user" + str(random.randint(100, 9999))
    return f"{local_part}@{random.choice(handles)}"


def gen_account_number() -> str:
    """Generate a synthetic Indian bank account number (11–18 digits)."""
    length = random.randint(11, 16)
    return "".join(random.choices(string.digits, k=length))


def gen_indian_phone() -> str:
    """Generate a synthetic Indian mobile number."""
    first_digit = random.choice("6789")
    rest = "".join(random.choices(string.digits, k=9))
    return f"+91{first_digit}{rest}"


def gen_transaction_id() -> str:
    return f"TXN{random.randint(10**11, 10**12-1)}"


def gen_customer_id() -> str:
    return f"CUST{random.randint(10**7, 10**8-1)}"


def gen_amount() -> float:
    """Generate a realistic INR transaction amount."""
    amounts = [
        random.uniform(10, 500),
        random.uniform(500, 5000),
        random.uniform(5000, 50000),
        random.uniform(50000, 500000),
    ]
    weights = [0.4, 0.35, 0.2, 0.05]
    return round(random.choices(amounts, weights=weights)[0], 2)


def gen_synthetic_name() -> str:
    return fake_in.name() if fake_in else "Rahul Sharma"


def gen_synthetic_email() -> str:
    return fake_in.email() if fake_in else f"user{random.randint(100,9999)}@example.com"


def gen_synthetic_address() -> str:
    return fake_in.address() if fake_in else "123 MG Road, Pune, Maharashtra"


def gen_dob() -> str:
    start = datetime(1960, 1, 1)
    end = datetime(2000, 12, 31)
    dob = start + timedelta(days=random.randint(0, (end - start).days))
    return dob.strftime("%d/%m/%Y")


# ------------------------------------------------------------------ #
# Record generators
# ------------------------------------------------------------------ #

API_ENDPOINTS = [
    ("/api/v1/payments/transfer", "POST", "PAYMENT_PROCESSING"),
    ("/api/v1/accounts/balance", "GET", "PAYMENT_PROCESSING"),
    ("/api/v1/fraud/score", "POST", "FRAUD_DETECTION"),
    ("/api/v1/customers/profile", "GET", "CUSTOMER_SUPPORT"),
    ("/api/v1/analytics/events", "POST", "ANALYTICS"),
    ("/api/v1/marketing/campaign", "POST", "MARKETING"),
    ("/api/v1/auth/login", "POST", "AUTHENTICATION"),
    ("/api/v1/auth/otp/verify", "POST", "AUTHENTICATION"),
    ("/api/v1/reports/statement", "GET", "REPORTING"),
    ("/api/v1/kyc/verify", "POST", "CUSTOMER_SUPPORT"),
]

DESTINATIONS = [
    ("payment_gateway", 0.90),
    ("fraud_service", 0.88),
    ("internal_analytics", 0.70),
    ("third_party_analytics", 0.40),
    ("marketing_platform", 0.25),
]


def gen_api_request_record(sensitivity_level: int = 3) -> dict[str, Any]:
    """
    Generate a synthetic API request record.
    sensitivity_level: 1=low, 2=medium, 3=high, 4=critical
    """
    endpoint, method, purpose = random.choice(API_ENDPOINTS)
    customer_id = gen_customer_id()
    pan = gen_pan()
    aadhaar = gen_aadhaar()
    name = gen_synthetic_name()
    email = gen_synthetic_email()
    phone = gen_indian_phone()
    account = gen_account_number()
    upi = gen_upi()
    ifsc = gen_ifsc()
    amount = gen_amount()
    txn_id = gen_transaction_id()
    dob = gen_dob()

    # Build payload based on sensitivity level
    payload_fields: dict[str, Any] = {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "customer_id": customer_id,
    }

    if sensitivity_level >= 1:
        payload_fields["transaction_amount"] = amount
        payload_fields["transaction_id"] = txn_id

    if sensitivity_level >= 2:
        payload_fields["email"] = email
        payload_fields["phone"] = phone

    if sensitivity_level >= 3:
        payload_fields["customer_name"] = name
        payload_fields["account_number"] = account
        payload_fields["ifsc_code"] = ifsc
        payload_fields["upi_id"] = upi

    if sensitivity_level >= 4:
        payload_fields["pan"] = pan
        payload_fields["aadhaar"] = aadhaar
        payload_fields["date_of_birth"] = dob
        payload_fields["address"] = gen_synthetic_address()

    # Entity annotations
    entities = []
    if "email" in payload_fields:
        entities.append({"entity_type": "EMAIL", "value": email, "sensitivity": "S2"})
    if "phone" in payload_fields:
        entities.append({"entity_type": "PHONE", "value": phone, "sensitivity": "S2"})
    if "customer_name" in payload_fields:
        entities.append({"entity_type": "PERSON", "value": name, "sensitivity": "S2"})
    if "account_number" in payload_fields:
        entities.append({"entity_type": "ACCOUNT_NUMBER", "value": account, "sensitivity": "S3"})
    if "pan" in payload_fields:
        entities.append({"entity_type": "PAN", "value": pan, "sensitivity": "S4"})
    if "aadhaar" in payload_fields:
        entities.append({"entity_type": "AADHAAR", "value": aadhaar, "sensitivity": "S4"})
    if "upi_id" in payload_fields:
        entities.append({"entity_type": "UPI_ID", "value": upi, "sensitivity": "S2"})

    sensitivity_map = {1: "S0", 2: "S1", 3: "S3", 4: "S4"}
    dest, _ = random.choice(DESTINATIONS)

    return {
        "sample_id": str(uuid.uuid4()),
        "synthetic_customer_id": customer_id,
        "request_id": payload_fields["request_id"],
        "endpoint": endpoint,
        "http_method": method,
        "processing_purpose": purpose,
        "destination": dest,
        "original_payload": payload_fields,
        "detected_entities": entities,
        "sensitivity_class": sensitivity_map.get(sensitivity_level, "S2"),
        "expected_action": ["ALLOW", "MASK", "TOKENIZE", "ENCRYPT"][sensitivity_level - 1],
        "timestamp": datetime.utcnow().isoformat(),
    }


def gen_application_log_record() -> dict[str, Any]:
    """Generate a synthetic application log record that may contain PII."""
    name = gen_synthetic_name()
    email = gen_synthetic_email()
    account = gen_account_number()
    phone = gen_indian_phone()
    pan = gen_pan()

    templates = [
        f"User {name} logged in from IP 192.168.1.{random.randint(1,254)}",
        f"Payment initiated by {email} for account {account} amount INR {gen_amount()}",
        f"KYC verification for customer {name}, PAN: {pan}",
        f"OTP sent to {phone} for transaction verification",
        f"Account {account} balance query by {name} ({email})",
        f"Failed login attempt for user {email} from device mobile-{random.randint(1000,9999)}",
        f"Transaction {gen_transaction_id()} processed for {name}, account ending {account[-4:]}",
    ]

    log_text = random.choice(templates)

    entities = []
    if name in log_text:
        idx = log_text.index(name)
        entities.append({
            "entity_type": "PERSON",
            "start": idx,
            "end": idx + len(name),
            "sensitivity": "S2",
        })
    if email in log_text:
        idx = log_text.index(email)
        entities.append({
            "entity_type": "EMAIL",
            "start": idx,
            "end": idx + len(email),
            "sensitivity": "S2",
        })
    if account in log_text:
        idx = log_text.index(account)
        entities.append({
            "entity_type": "ACCOUNT_NUMBER",
            "start": idx,
            "end": idx + len(account),
            "sensitivity": "S3",
        })

    return {
        "sample_id": str(uuid.uuid4()),
        "log_text": log_text,
        "detected_entities": entities,
        "sensitivity_class": "S3" if any(e["sensitivity"] == "S3" for e in entities) else "S2",
        "timestamp": datetime.utcnow().isoformat(),
        "log_level": random.choice(["INFO", "WARN", "ERROR"]),
    }


def gen_multi_request_sequence(sequence_length: int = 4) -> list[dict[str, Any]]:
    """
    Generate a sequence of API requests for the same synthetic customer
    that individually appear low-risk but collectively reveal sensitive info.
    """
    customer_id = gen_customer_id()
    session_id = str(uuid.uuid4())
    sequence_id = str(uuid.uuid4())

    # Progressive disclosure pattern
    sequence_steps = [
        {"fields": ["customer_id", "transaction_amount", "transaction_id"],
         "entities": [], "sensitivity": "S0", "label": "amount_only"},
        {"fields": ["customer_id", "location", "timestamp"],
         "entities": [], "sensitivity": "S1", "label": "location_time"},
        {"fields": ["customer_id", "account_suffix"],
         "entities": [("ACCOUNT_NUMBER", "S3")], "sensitivity": "S2", "label": "partial_account"},
        {"fields": ["customer_id", "email", "transaction_reference"],
         "entities": [("EMAIL", "S2")], "sensitivity": "S3", "label": "email_ref"},
    ]

    records = []
    for i, step in enumerate(sequence_steps[:sequence_length]):
        records.append({
            "sample_id": str(uuid.uuid4()),
            "synthetic_customer_id": customer_id,
            "session_id": session_id,
            "disclosure_sequence_id": sequence_id,
            "sequence_position": i + 1,
            "fields_disclosed": step["fields"],
            "entity_types": [e[0] for e in step["entities"]],
            "individual_sensitivity": step["sensitivity"],
            "cumulative_sensitivity": "S3" if i >= 3 else step["sensitivity"],
            "label": step["label"],
            "timestamp": (datetime.utcnow() + timedelta(minutes=i * 5)).isoformat(),
        })

    return records


def generate_dataset(
    n_api_requests: int = 3000,
    n_logs: int = 2500,
    n_sequences: int = 1000,
    output_dir: Path | None = None,
) -> dict[str, int]:
    """
    Generate the full BankPII-API synthetic dataset.
    Returns counts per category.
    """
    out = output_dir or OUTPUT_DIR

    api_records = []
    for _ in range(n_api_requests):
        level = random.choices([1, 2, 3, 4], weights=[0.1, 0.25, 0.4, 0.25])[0]
        api_records.append(gen_api_request_record(level))

    log_records = [gen_application_log_record() for _ in range(n_logs)]

    sequence_records = []
    for _ in range(n_sequences // 4):
        sequence_records.extend(gen_multi_request_sequence(4))

    # Save JSONL files
    def save_jsonl(records: list[dict], filename: str) -> None:
        path = out / filename
        with open(path, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        print(f"Saved {len(records)} records to {path}")

    save_jsonl(api_records, "bankpii_api_requests.jsonl")
    save_jsonl(log_records, "bankpii_application_logs.jsonl")
    save_jsonl(sequence_records, "bankpii_multi_request_sequences.jsonl")

    return {
        "api_requests": len(api_records),
        "application_logs": len(log_records),
        "multi_request_sequences": len(sequence_records),
        "total": len(api_records) + len(log_records) + len(sequence_records),
    }


if __name__ == "__main__":
    if not HAS_FAKER:
        print("ERROR: Install faker first: pip install faker")
        exit(1)
    print("Generating BankPII-API synthetic dataset...")
    counts = generate_dataset(n_api_requests=3000, n_logs=2500, n_sequences=1000)
    print(f"Dataset generation complete: {counts}")
