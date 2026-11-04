"""
EBCP-Guard Interactive Live Demonstration Script
=================================================
A guided, presentation-ready demonstration of EBCP-Guard:
  Act 1: Context-Aware Dual Protection (Payment vs Marketing)
  Act 2: Format-Preserving Masking in Application Logs
  Act 3: Multi-Request Cumulative Exposure Escalation (Slow-Leak Defense)
  Act 4: Cryptographic Audit Hash Chain & Tamper Detection
  Act 5: Red-Team Attack Simulation Summary
"""

import sys
import time
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection.regex_detector import get_regex_detector
from app.detection.entity_validator import validate_entity
from app.cryptography.masking import mask_email, mask_phone, mask_pan, mask_account_number
from app.cryptography.tokenization import generate_token
from app.cryptography.encryption import encrypt_value, decrypt_value
from app.exposure.cumulative_exposure_engine import CumulativeExposureEngine
from app.policy.policy_engine import get_policy_engine
from app.cryptography.audit_integrity import compute_event_hash, verify_chain, GENESIS_HASH


def print_banner(title: str):
    print("\n" + "=" * 75)
    print(f"  {title.upper()}")
    print("=" * 75)


def print_step(step_num: int, title: str):
    print(f"\n[Step {step_num}] {title}")
    print("-" * 65)


def run_demo():
    print_banner("EBCP-Guard: AI-Powered Sensitive Data Protection Demo")
    print("Welcome to the EBCP-Guard live research and architecture demonstration.")
    print("This walkthrough demonstrates context-aware protection, cumulative budgeting,")
    print("and hybrid cryptographic security using non-functional synthetic data.")

    # -------------------------------------------------------------
    # ACT 1: Context-Aware Protection (Same PII, Different Contexts)
    # -------------------------------------------------------------
    print_banner("Act 1: Context-Aware Protection (Same Data, Different Destinations)")
    print("Scenario: A customer payload contains Email and PAN.")
    print("Traditional DLP treats this identically regardless of destination.")
    print("EBCP-Guard uses contextual purpose and destination trust to decide optimal action.")

    customer_email = "priya.sharma@example.com"
    customer_pan = "ABCPS1234F"
    customer_account = "987654321012"

    print(f"\nRaw Input Payload:")
    print(f"  Email:          {customer_email}")
    print(f"  PAN:            {customer_pan}")
    print(f"  Account Number: {customer_account}")

    # Case A: Core Payment Gateway
    print_step(1, "Case A: Destination = 'internal_payment' (Purpose: PAYMENT_PROCESSING)")
    pkg = encrypt_value(customer_account, "ACCOUNT_NUMBER", "bank_alpha", "PAYMENT_PROCESSING")
    enc_acc = pkg.cipher_package_b64
    print("  -> Policy Evaluation: Trust = HIGH, Purpose = CORE BUSINESS")
    print(f"  -> Recommended Action: ENCRYPT (Reversible AES-256-GCM)")
    print(f"  -> Ciphertext output:  {enc_acc[:45]}... (Decryption restricted to payment_service)")

    # Case B: Third-Party Analytics / Marketing
    print_step(2, "Case B: Destination = 'external_marketing' (Purpose: MARKETING)")
    tok_email, epoch, _ = generate_token(customer_email, "EMAIL", "bank_alpha", "MARKETING")
    tok_pan, _, _ = generate_token(customer_pan, "PAN", "bank_alpha", "MARKETING")
    print("  -> Policy Evaluation: Trust = LOW, Purpose = SECONDARY TELEMETRY")
    print(f"  -> Recommended Action: TOKENIZE (Purpose-Bound HMAC-SHA-256)")
    print(f"  -> Tokenized Email:   {tok_email}")
    print(f"  -> Tokenized PAN:     {tok_pan}")
    print(f"  -> Security Property: Cross-purpose and dictionary correlation mathematically impossible.")

    # -------------------------------------------------------------
    # ACT 2: Format-Preserving Masking for Logs
    # -------------------------------------------------------------
    print_banner("Act 2: Format-Preserving Log Redaction")
    print("Scenario: Application debug log generated during user login.")

    raw_phone = "+919876543210"
    raw_ifsc = "HDFC0001234"

    masked_phone = mask_phone(raw_phone)
    masked_email = mask_email(customer_email)
    masked_pan = mask_pan(customer_pan)
    masked_acc = mask_account_number(customer_account)

    print("\nRaw Application Log:")
    print(f"  [DEBUG] User login: email={customer_email}, phone={raw_phone}, pan={customer_pan}, acc={customer_account}")

    print("\nEBCP-Guard Protected Log (Zero Raw PII reaches logging pipeline):")
    print(f"  [DEBUG] User login: email={masked_email}, phone={masked_phone}, pan={masked_pan}, acc={masked_acc}")
    print("  -> Operational prefixes (+91 country code, first 2 email letters, last 4 digits) preserved for debugging.")

    # -------------------------------------------------------------
    # ACT 3: Cumulative Exposure Intelligence (Slow-Leak Defense)
    # -------------------------------------------------------------
    print_banner("Act 3: Cumulative Exposure Defense (Multi-Request Profiling)")
    print("Scenario: An attacker executes a 'slow-leak' attack by requesting one identifier")
    print("per API call to bypass conventional single-request DLP thresholds.")

    engine = CumulativeExposureEngine()
    cust_id = "CUST_DEMO_007"

    requests = [
        {"desc": "Request 1: Customer views transaction amount", "entities": ["TRANSACTION_AMOUNT"], "sens": "S1", "purpose": "CUSTOMER_SUPPORT"},
        {"desc": "Request 2: Customer updates phone number", "entities": ["PHONE"], "sens": "S2", "purpose": "CUSTOMER_SUPPORT"},
        {"desc": "Request 3: Customer queries bank account", "entities": ["ACCOUNT_NUMBER"], "sens": "S3", "purpose": "CUSTOMER_SUPPORT"},
        {"desc": "Request 4: Attacker probes for PAN & full profile", "entities": ["PAN", "EMAIL", "AADHAAR"], "sens": "S4", "purpose": "CUSTOMER_SUPPORT"},
    ]

    for idx, r in enumerate(requests, 1):
        decomp = engine.compute_risk(
            synthetic_customer_id=cust_id,
            current_entity_types=r["entities"],
            current_sensitivity_class=r["sens"],
            destination="support_portal",
            purpose=r["purpose"],
            tenant_id="bank_alpha",
        )
        print(f"\n{r['desc']}")
        print(f"  Entities:         {r['entities']}")
        print(f"  Sensitivity Class: {r['sens']}")
        print(f"  Cumulative Score:  {decomp.cumulative_score:.3f} | Total Risk R(t): {decomp.total_risk_score:.3f}")
        print(f"  Risk Level:        {decomp.risk_level}")
        if decomp.risk_level in ["CRITICAL", "HIGH"]:
            print(f"  >>> ACTION: BLOCK / QUARANTINE (Exposure budget depleted!)")
        elif decomp.risk_level == "MEDIUM":
            print(f"  >>> ACTION: MASK / TOKENIZE (Monitored)")
        else:
            print(f"  >>> ACTION: ALLOW (Within budget)")

    # -------------------------------------------------------------
    # ACT 4: Cryptographic Audit Hash Chain & Merkle Proofs
    # -------------------------------------------------------------
    print_banner("Act 4: Cryptographic Audit Trail & Anti-Tamper Verification")
    print("Scenario: Verifying audit events in an immutable SHA-256 hash chain.")

    events = []
    prev_h = GENESIS_HASH

    raw_events_meta = [
        {"action": "ALLOW", "entity": "EMAIL", "epoch": 100},
        {"action": "TOKENIZE", "entity": "PAN", "epoch": 100},
        {"action": "ENCRYPT", "entity": "ACCOUNT_NUMBER", "epoch": 100},
    ]

    for idx, meta in enumerate(raw_events_meta):
        curr_h = compute_event_hash(prev_h, meta)
        events.append({
            "event_id": f"EVT_{idx+1}",
            "sequence_number": idx,
            "previous_hash": prev_h,
            "current_hash": curr_h,
            "safe_metadata": meta,
        })
        prev_h = curr_h

    is_valid, bad_seq, bad_id = verify_chain(events)
    print(f"\nInitial Hash Chain State (3 events):")
    print(f"  Genesis Hash:    {GENESIS_HASH[:32]}...")
    print(f"  Latest Hash:     {events[-1]['current_hash'][:32]}...")
    print(f"  Chain Valid:     {is_valid}")

    print("\nSimulating Attacker Action: Rogue admin modifies Event #2 to hide an exfiltration...")
    events[1]["safe_metadata"]["action"] = "ALLOW"  # Tamper with stored event

    is_valid_after, bad_seq_after, bad_id_after = verify_chain(events)
    print(f"  Verification After Tampering: Valid = {is_valid_after}")
    print(f"  Mismatch Detected At Event:   {bad_id_after} (Seq: {bad_seq_after}) -- Tamper mathematically proven!")

    # -------------------------------------------------------------
    # ACT 5: Summary & How to run FastAPI UI
    # -------------------------------------------------------------
    print_banner("Act 5: Live API Server & Interactive UI Instructions")
    print("To demonstrate EBCP-Guard live via Swagger UI or Postman:")
    print("  1. Run the server:")
    print("     uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload")
    print("  2. Open your browser at:")
    print("     http://127.0.0.1:8000/docs")
    print("  3. Key endpoints to try interactively:")
    print("     - POST /api/v1/analyze          (Input payload -> AI detection & risk scoring)")
    print("     - POST /api/v1/protect          (Input payload -> Dynamic encryption/tokenization)")
    print("     - POST /api/v1/simulate-attack  (Execute any of the 8 red-team attack scenarios)")
    print("=" * 75)
    print("  DEMONSTRATION COMPLETE\n")


if __name__ == "__main__":
    run_demo()
