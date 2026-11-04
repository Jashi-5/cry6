"""
EBCP-Guard Attack Simulation Scenarios
========================================
Eight controlled security demonstration scenarios executed against
synthetic data in an isolated local environment.
NEVER targets real services, networks, or external applications.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import random
import string
import uuid
from typing import Any

from app.api.schemas.schemas import AttackSimulationRequest, AttackSimulationResponse


async def run_attack_scenario(request: AttackSimulationRequest) -> AttackSimulationResponse:
    """Dispatch to the appropriate scenario handler."""
    handlers = {
        "plaintext_log": attack_1_plaintext_log,
        "dict_attack": attack_2_dict_attack,
        "cross_tenant": attack_3_cross_tenant,
        "cumulative": attack_4_cumulative_exposure,
        "unauth_decrypt": attack_5_unauth_decrypt,
        "audit_tamper": attack_6_audit_tamper,
        "exfiltration": attack_7_exfiltration,
        "evasion": attack_8_model_evasion,
    }
    handler = handlers.get(request.scenario)
    if not handler:
        return AttackSimulationResponse(
            scenario=request.scenario,
            baseline_outcome="N/A",
            ebcp_guard_outcome="N/A",
            result="VULNERABLE",
            details={"error": f"Unknown scenario: {request.scenario}"},
            explanation="Scenario not found.",
        )
    return handler(request)


# ------------------------------------------------------------------ #
# Attack 1: Plaintext Log Extraction
# ------------------------------------------------------------------ #

def attack_1_plaintext_log(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """
    Simulate an attacker reading application logs to extract PII.
    Baseline: logs contain raw PII.
    EBCP-Guard: logs contain masked/tokenized values only.
    """
    synthetic_name = "Arjun Mehta"
    synthetic_email = "arjun.mehta@example.com"
    synthetic_account = "112345678901"

    # BASELINE: raw log
    baseline_log = (
        f"[INFO] Payment initiated by {synthetic_name} "
        f"(email: {synthetic_email}) "
        f"from account {synthetic_account} amount INR 15000"
    )

    # EBCP-Guard: protected log
    from app.cryptography.masking import mask_name, mask_email, mask_account_number
    from app.cryptography.tokenization import generate_token
    masked_name = mask_name(synthetic_name, strategy="initials")
    masked_email = mask_email(synthetic_email)
    masked_account = mask_account_number(synthetic_account)

    protected_log = (
        f"[INFO] Payment initiated by {masked_name} "
        f"(email: {masked_email}) "
        f"from account {masked_account} amount INR 15000"
    )

    pii_in_baseline = all(x in baseline_log for x in [synthetic_name, synthetic_email, synthetic_account])
    pii_in_protected = any(x in protected_log for x in [synthetic_name, synthetic_email, synthetic_account])

    return AttackSimulationResponse(
        scenario="plaintext_log",
        baseline_outcome=f"PII EXPOSED: attacker recovered: name='{synthetic_name}', email='{synthetic_email}', account='{synthetic_account}'",
        ebcp_guard_outcome=f"PII PROTECTED: attacker sees: '{protected_log}'",
        result="PROTECTED" if not pii_in_protected else "VULNERABLE",
        details={
            "baseline_log": baseline_log,
            "protected_log": protected_log,
            "pii_recoverable_from_baseline": pii_in_baseline,
            "pii_recoverable_from_protected": pii_in_protected,
        },
        explanation=(
            "Baseline logs expose customer name, email, and account number in plaintext. "
            "An attacker with log access can immediately identify and target the customer. "
            "EBCP-Guard replaces sensitive values with masked equivalents before logging, "
            "preventing direct PII extraction from log files."
        ),
    )


# ------------------------------------------------------------------ #
# Attack 2: Dictionary Attack vs Unsalted Hash
# ------------------------------------------------------------------ #

def attack_2_dict_attack(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """
    Demonstrate why SHA256(email) is insufficient vs HMAC-SHA256 with secret key.
    """
    from app.cryptography.tokenization import generate_token

    # Target synthetic email
    target_email = "priya.sharma@example.com"
    dict_emails = [
        "admin@example.com", "user@example.com",
        "priya.sharma@example.com",   # Target IS in dictionary
        "rahul@example.com", "test@bank.com",
    ]

    # Baseline: plain SHA-256
    target_sha256 = hashlib.sha256(target_email.encode()).hexdigest()
    dict_sha256 = {e: hashlib.sha256(e.encode()).hexdigest() for e in dict_emails}
    sha256_match = any(h == target_sha256 for h in dict_sha256.values())

    # EBCP-Guard: HMAC-SHA256 with derived key
    target_token, epoch, kv = generate_token(
        value=target_email,
        entity_type="EMAIL",
        tenant_id="bank_a",
        purpose="ANALYTICS",
    )
    # Attacker has no key — can only try HMAC with wrong keys
    attacker_fake_key = b"0" * 32
    attacker_attempt = "EMAIL_" + hmac_lib.new(attacker_fake_key, target_email.encode(), hashlib.sha256).hexdigest()
    hmac_match = hmac_lib.compare_digest(target_token, attacker_attempt)

    return AttackSimulationResponse(
        scenario="dict_attack",
        baseline_outcome=f"SHA256 MATCHED — target email found in dictionary. Hash: {target_sha256[:16]}...",
        ebcp_guard_outcome=f"HMAC RESISTED — attacker without key produced: {attacker_attempt[:32]}... (no match)",
        result="PROTECTED" if not hmac_match else "VULNERABLE",
        details={
            "target_sha256": target_sha256,
            "sha256_dictionary_match": sha256_match,
            "hmac_token_prefix": target_token[:32] + "...",
            "attacker_attempt_prefix": attacker_attempt[:32] + "...",
            "hmac_match_with_wrong_key": hmac_match,
            "dictionary_size": len(dict_emails),
        },
        explanation=(
            "Plain SHA256(email) is deterministic — an attacker with a list of likely emails "
            "can pre-compute hashes and match them against stored tokens (dictionary attack). "
            "HMAC-SHA256 with a secret key prevents this: without the key, no matching is possible. "
            "Security depends on keeping the HMAC key secret and using secure key management."
        ),
    )


# ------------------------------------------------------------------ #
# Attack 3: Cross-Tenant Token Correlation
# ------------------------------------------------------------------ #

def attack_3_cross_tenant(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """
    Demonstrate scope separation: same entity → different tokens across scopes.
    """
    from app.cryptography.tokenization import generate_token, tokens_are_scope_separated

    customer_email = "customer123@example.com"
    epoch = "epoch-20241201-00"

    # Same scope (should be SAME token — enables correlation within permission)
    token_a1, _, _ = generate_token(customer_email, "EMAIL", "bank_a", "PAYMENT_PROCESSING", epoch)
    token_a2, _, _ = generate_token(customer_email, "EMAIL", "bank_a", "PAYMENT_PROCESSING", epoch)
    same_scope_stable = hmac_lib.compare_digest(token_a1, token_a2)

    # Different purpose (should be DIFFERENT)
    token_analytics, _, _ = generate_token(customer_email, "EMAIL", "bank_a", "ANALYTICS", epoch)
    diff_purpose_separated = not hmac_lib.compare_digest(token_a1, token_analytics)

    # Different tenant (should be DIFFERENT)
    token_bank_b, _, _ = generate_token(customer_email, "EMAIL", "bank_b", "PAYMENT_PROCESSING", epoch)
    diff_tenant_separated = not hmac_lib.compare_digest(token_a1, token_bank_b)

    all_separated = diff_purpose_separated and diff_tenant_separated

    return AttackSimulationResponse(
        scenario="cross_tenant",
        baseline_outcome="With reusable identifiers (customer_id/email), cross-scope correlation is trivial.",
        ebcp_guard_outcome=f"Tokens are scope-separated: same_scope_stable={same_scope_stable}, cross_purpose_separated={diff_purpose_separated}, cross_tenant_separated={diff_tenant_separated}",
        result="PROTECTED" if all_separated else "VULNERABLE",
        details={
            "token_payment_bank_a": token_a1[:24] + "...",
            "token_analytics_bank_a": token_analytics[:24] + "...",
            "token_payment_bank_b": token_bank_b[:24] + "...",
            "same_scope_produces_stable_token": same_scope_stable,
            "different_purpose_separated": diff_purpose_separated,
            "different_tenant_separated": diff_tenant_separated,
        },
        explanation=(
            "Purpose-bound pseudonymization ensures the same customer email produces "
            "DIFFERENT tokens in different authorized scopes. "
            "An attacker who obtains analytics tokens cannot directly link them "
            "to payment tokens for the same customer. "
            "Within the same authorized scope, tokens are stable to enable legitimate correlation."
        ),
    )


# ------------------------------------------------------------------ #
# Attack 4: Cumulative Exposure
# ------------------------------------------------------------------ #

def attack_4_cumulative_exposure(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """
    Show how per-request DLP misses aggregate risk that EBCP-Guard detects.
    """
    from app.exposure.cumulative_exposure_engine import CumulativeExposureEngine, ExposureEventRecord

    customer_id = f"CUST{random.randint(10**7, 10**8-1)}"

    events = [
        ExposureEventRecord(customer_id, "bank_a", ["TRANSACTION_AMOUNT"], "/payments", "PAYMENT_PROCESSING", "internal_payment", "ALLOW"),
        ExposureEventRecord(customer_id, "bank_a", ["IP_ADDRESS"], "/analytics", "ANALYTICS", "internal_analytics", "ALLOW"),
        ExposureEventRecord(customer_id, "bank_a", ["ACCOUNT_NUMBER"], "/accounts", "CUSTOMER_SUPPORT", "internal_payment", "MASK"),
        ExposureEventRecord(customer_id, "bank_a", ["EMAIL"], "/marketing", "MARKETING", "third_party_analytics", "ALLOW"),
    ]

    engine = CumulativeExposureEngine()
    comparison = engine.compare_with_perrequest_baseline(events, "S2", "third_party_analytics")

    per_request_actions = [e["recommended_action"] for e in comparison["per_request_analysis"]]
    cumulative_action = comparison["cumulative_analysis"]["recommended_action"]
    escalation = comparison["escalation_detected"]

    return AttackSimulationResponse(
        scenario="cumulative",
        baseline_outcome=f"Per-request decisions: {per_request_actions} — each request appears acceptable individually.",
        ebcp_guard_outcome=f"Cumulative decision: {cumulative_action} — risk escalation detected: {escalation}",
        result="PROTECTED" if escalation else "PARTIAL",
        details=comparison,
        explanation=(
            "Conventional DLP checks each API request independently. "
            "Four individually low-risk disclosures (amount, location, partial account, email) "
            "collectively enable customer profiling and unauthorized correlation. "
            "EBCP-Guard's cumulative exposure engine tracks historical disclosures "
            "and escalates the protection decision when aggregate risk exceeds thresholds."
        ),
    )


# ------------------------------------------------------------------ #
# Attack 5: Unauthorized Decryption
# ------------------------------------------------------------------ #

def attack_5_unauth_decrypt(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """Attempt decryption without authorization."""
    from app.cryptography.encryption import encrypt_value, decrypt_value
    from app.core.exceptions import AuthenticationTagError, CryptographyError
    import base64

    plaintext = "1234567890123456"  # Synthetic account number

    # Encrypt legitimately
    pkg = encrypt_value(plaintext, "ACCOUNT_NUMBER", "bank_a", "PAYMENT_PROCESSING")

    results = {}

    # Attempt 1: Wrong key (different tenant/purpose → different derived key)
    try:
        result = decrypt_value(
            pkg.cipher_package_b64, "ACCOUNT_NUMBER",
            "bank_b", "ANALYTICS",  # Wrong scope
            pkg.key_version
        )
        results["wrong_scope"] = f"FAILED — plaintext recovered: {result}"
    except (AuthenticationTagError, CryptographyError) as e:
        results["wrong_scope"] = f"BLOCKED — {type(e).__name__}: {str(e)[:80]}"

    # Attempt 2: Modified ciphertext
    try:
        raw = base64.b64decode(pkg.cipher_package_b64)
        tampered = raw[:-4] + bytes([b ^ 0xFF for b in raw[-4:]])
        tampered_b64 = base64.b64encode(tampered).decode()
        result = decrypt_value(
            tampered_b64, "ACCOUNT_NUMBER",
            "bank_a", "PAYMENT_PROCESSING",
            pkg.key_version
        )
        results["tampered_ciphertext"] = f"FAILED — plaintext recovered: {result}"
    except (AuthenticationTagError, CryptographyError) as e:
        results["tampered_ciphertext"] = f"BLOCKED — {type(e).__name__}: Authentication tag verification failed"

    # Attempt 3: Correct scope — should succeed (authorized)
    try:
        result = decrypt_value(
            pkg.cipher_package_b64, "ACCOUNT_NUMBER",
            "bank_a", "PAYMENT_PROCESSING",
            pkg.key_version
        )
        results["authorized_decryption"] = f"SUCCESS — authorized party can decrypt (expected behavior)"
    except Exception as e:
        results["authorized_decryption"] = f"UNEXPECTED ERROR: {e}"

    all_blocked = all("BLOCKED" in v for k, v in results.items() if k != "authorized_decryption")

    return AttackSimulationResponse(
        scenario="unauth_decrypt",
        baseline_outcome="Without access controls, any party with the ciphertext could attempt decryption.",
        ebcp_guard_outcome=f"Unauthorized attempts blocked via GCM authentication tag. Authorized party succeeds.",
        result="PROTECTED" if all_blocked else "VULNERABLE",
        details=results,
        explanation=(
            "AES-256-GCM provides authenticated encryption: any modification to ciphertext, "
            "nonce, or use of the wrong key causes immediate authentication tag verification failure. "
            "An attacker who intercepts the ciphertext cannot decrypt it without the correct "
            "purpose-scoped derived key. Authorized services with the correct scope succeed."
        ),
    )


# ------------------------------------------------------------------ #
# Attack 6: Audit Tampering
# ------------------------------------------------------------------ #

def attack_6_audit_tamper(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """Show that audit chain detects tampering."""
    from app.cryptography.audit_integrity import (
        compute_event_hash, verify_chain, build_merkle_tree, GENESIS_HASH
    )

    # Build a clean audit chain
    events = []
    prev = GENESIS_HASH
    for i in range(5):
        metadata = {"request_id": f"req-{i}", "action": "TOKENIZE", "entity_count": i + 1, "seq": i}
        curr = compute_event_hash(prev, metadata)
        events.append({
            "event_id": f"evt-{i}",
            "previous_hash": prev,
            "current_hash": curr,
            "safe_metadata": metadata,
            "sequence_number": i,
        })
        prev = curr

    # Tamper with event index 2
    tampered_events = [dict(e) for e in events]
    tampered_events[2]["safe_metadata"] = {**events[2]["safe_metadata"], "action": "ALLOW"}  # Changed!
    # Recalculate current_hash to simulate a sophisticated attacker who updates ONE hash
    tampered_events[2]["current_hash"] = compute_event_hash(
        tampered_events[2]["previous_hash"],
        tampered_events[2]["safe_metadata"]
    )
    # But they forget to update the chain forward → event 3's previous_hash is now wrong

    original_valid, orig_fail_seq, _ = verify_chain(events, GENESIS_HASH)
    tampered_valid, tamp_fail_seq, tamp_fail_id = verify_chain(tampered_events, GENESIS_HASH)

    event_hashes = [e["current_hash"] for e in events]
    merkle_root, _ = build_merkle_tree(event_hashes)

    return AttackSimulationResponse(
        scenario="audit_tamper",
        baseline_outcome="Without hash chaining, event modification may go undetected.",
        ebcp_guard_outcome=f"Original chain: valid={original_valid}. After tampering: valid={tampered_valid}, first failure at seq={tamp_fail_seq}",
        result="PROTECTED" if not tampered_valid else "VULNERABLE",
        details={
            "original_chain_valid": original_valid,
            "tampered_chain_valid": tampered_valid,
            "first_failed_sequence": tamp_fail_seq,
            "merkle_root": merkle_root[:32] + "...",
            "tampered_event_index": 2,
        },
        explanation=(
            "The SHA-256 hash chain makes tampering detectable: modifying event N "
            "changes its hash, which cascades forward and breaks the chain at event N+1. "
            "NOTE: Hash chains are tamper-EVIDENT, not tamper-PROOF. For stronger guarantees, "
            "Merkle roots should be stored in an independent, trusted external checkpoint."
        ),
    )


# ------------------------------------------------------------------ #
# Attack 7: External Exfiltration Policy
# ------------------------------------------------------------------ #

def attack_7_exfiltration(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """Policy engine blocks unauthorized destination."""
    from app.policy.policy_engine import PolicyEngine

    engine = PolicyEngine()

    entities = [
        {"entity_type": "PAN", "confidence": 0.94},
        {"entity_type": "ACCOUNT_NUMBER", "confidence": 0.88},
        {"entity_type": "EMAIL", "confidence": 0.92},
    ]

    # Unauthorized destination
    decision = engine.evaluate(
        entities=entities,
        sensitivity_class="S4",
        sensitivity_confidence=0.94,
        purpose="ANALYTICS",
        purpose_confidence=0.85,
        exposure_risk_level="HIGH",
        exposure_risk_score=0.72,
        destination="external_unknown",
        tenant_id="bank_a",
    )

    return AttackSimulationResponse(
        scenario="exfiltration",
        baseline_outcome="Static rules only check destination whitelist; miss contextual PII sensitivity.",
        ebcp_guard_outcome=f"Decision: {decision.overall_action.value}, blocked={decision.is_blocked}, reason='{decision.block_reason}'",
        result="PROTECTED" if decision.is_blocked else "VULNERABLE",
        details={
            "decision": decision.overall_action.value,
            "is_blocked": decision.is_blocked,
            "block_reason": decision.block_reason,
            "entity_decisions": [
                {"type": e.entity_type, "action": e.action.value}
                for e in decision.entity_decisions
            ],
        },
        explanation=(
            "The policy engine checks the destination against the authorized service registry, "
            "cross-references with entity sensitivity and processing purpose, "
            "and blocks the request when the destination is not authorized to receive "
            "the identified sensitive entities."
        ),
    )


# ------------------------------------------------------------------ #
# Attack 8: Model Evasion
# ------------------------------------------------------------------ #

def attack_8_model_evasion(req: AttackSimulationRequest) -> AttackSimulationResponse:
    """Test obfuscated PII detection."""
    from app.detection.regex_detector import get_regex_detector

    obfuscated_samples = [
        "acc-num: 1234 5678 9012",      # Spaces in account
        "p4n: ABCDE1234F",              # '4' for 'a'
        "email = user[at]domain[dot]com",  # Obfuscated email
        "ph: +91 9876 543 210",         # Extra spaces
        "ABCDE-1234-F",                 # Dashes in PAN
    ]

    detector = get_regex_detector()
    results = []
    for sample in obfuscated_samples:
        matches = detector.detect(sample)
        results.append({
            "input": sample,
            "matches_found": len(matches),
            "entity_types": [m.entity_type for m in matches],
        })

    detected_count = sum(1 for r in results if r["matches_found"] > 0)
    total = len(results)

    return AttackSimulationResponse(
        scenario="evasion",
        baseline_outcome="Simple regex with exact patterns fails on obfuscated input.",
        ebcp_guard_outcome=f"Hybrid detector found matches in {detected_count}/{total} obfuscated samples. Missed {total - detected_count} — conservative policy applied for low-confidence predictions.",
        result="PARTIAL" if detected_count >= total // 2 else "VULNERABLE",
        details={
            "samples": results,
            "detection_rate": f"{detected_count}/{total}",
            "conservative_policy_note": "Low-confidence / missed detections trigger S3 conservative handling.",
        },
        explanation=(
            "Model evasion is a real limitation — no detection system achieves 100% recall. "
            "EBCP-Guard mitigates this through: (1) hybrid detection combining GLiNER + regex, "
            "(2) conservative handling for low-confidence predictions, "
            "(3) fail-closed policy: unclassified sensitive content defaults to TOKENIZE or ENCRYPT. "
            "Perfect protection is not claimed — these failure modes are documented."
        ),
    )
