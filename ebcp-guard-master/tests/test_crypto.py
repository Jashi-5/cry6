"""
EBCP-Guard Cryptographic Test Suite
====================================
Tests:
  - HKDF-SHA-256 key derivation & domain separation
  - Purpose-bound HMAC-SHA-256 pseudonymization (determinism in scope, separation across scopes)
  - AES-256-GCM reversible encryption & decryption
  - Nonce uniqueness property
  - Authentication tag verification & tampering rejection
  - Format-preserving selective masking
  - SHA-256 audit hash chain & Merkle tree inclusion verification
"""

import pytest
import hmac
import hashlib
from app.cryptography.key_manager import KeyManager
from app.cryptography.tokenization import (
    generate_token, verify_token, tokens_are_scope_separated
)
from app.cryptography.encryption import (
    encrypt_value, decrypt_value, test_nonce_uniqueness
)
from app.cryptography.masking import (
    mask_email, mask_phone, mask_account_number, mask_pan, mask_aadhaar, mask_by_entity_type
)
from app.cryptography.audit_integrity import (
    compute_event_hash, verify_chain, build_merkle_tree, generate_merkle_proof, verify_merkle_proof, GENESIS_HASH
)
from app.core.exceptions import AuthenticationTagError

def test_key_manager_derivation_separation():
    km = KeyManager()
    key_pay = km.derive_hmac_key("tenant_a", "PAYMENT_PROCESSING", "epoch-1")
    key_anal = km.derive_hmac_key("tenant_a", "ANALYTICS", "epoch-1")
    key_tenant_b = km.derive_hmac_key("tenant_b", "PAYMENT_PROCESSING", "epoch-1")

    assert len(key_pay) == 32
    assert len(key_anal) == 32
    # Ensure distinct keys for different scopes
    assert not hmac.compare_digest(key_pay, key_anal)
    assert not hmac.compare_digest(key_pay, key_tenant_b)

def test_hmac_token_stability_and_scope_separation():
    val = "rahul.sharma@example.com"
    token1, epoch1, _ = generate_token(val, "EMAIL", "tenant_a", "PAYMENT_PROCESSING", "epoch-1")
    token2, epoch2, _ = generate_token(val, "EMAIL", "tenant_a", "PAYMENT_PROCESSING", "epoch-1")

    # Same scope must yield stable token
    assert token1 == token2

    # Different purpose must yield distinct token
    token_anal, _, _ = generate_token(val, "EMAIL", "tenant_a", "ANALYTICS", "epoch-1")
    assert token1 != token_anal

    # Verify helper
    assert verify_token(val, token1, "EMAIL", "tenant_a", "PAYMENT_PROCESSING", "epoch-1")
    assert not verify_token(val, token_anal, "EMAIL", "tenant_a", "PAYMENT_PROCESSING", "epoch-1")

def test_aes_gcm_roundtrip():
    original = "123456789012"
    pkg = encrypt_value(original, "ACCOUNT_NUMBER", "bank_a", "PAYMENT_PROCESSING")

    recovered = decrypt_value(
        cipher_package_b64=pkg.cipher_package_b64,
        entity_type="ACCOUNT_NUMBER",
        tenant_id="bank_a",
        purpose="PAYMENT_PROCESSING",
        key_version=pkg.key_version,
    )
    assert recovered == original

def test_aes_gcm_tamper_detection():
    import base64
    original = "SECRET_123"
    pkg = encrypt_value(original, "SECRET", "bank_a", "PAYMENT_PROCESSING")

    # Flip bits in ciphertext
    raw = bytearray(base64.b64decode(pkg.cipher_package_b64))
    raw[-1] ^= 0xFF
    tampered_b64 = base64.b64encode(raw).decode()

    with pytest.raises(AuthenticationTagError):
        decrypt_value(
            cipher_package_b64=tampered_b64,
            entity_type="SECRET",
            tenant_id="bank_a",
            purpose="PAYMENT_PROCESSING",
            key_version=pkg.key_version,
        )

def test_nonce_uniqueness_guarantee():
    assert test_nonce_uniqueness(num_samples=1000)

def test_selective_masking():
    assert mask_email("rahul.sharma@gmail.com") == "r**********a@gmail.com"
    assert mask_phone("+91-9876543210") == "+91-XXXXXX3210"
    assert mask_account_number("123456789012") == "********9012"
    assert mask_pan("ABCDE1234F") == "ABCDE****F"
    assert mask_aadhaar("1234 5678 9012") == "XXXX XXXX 9012"

def test_audit_hash_chain_and_merkle():
    events = []
    prev = GENESIS_HASH
    for i in range(10):
        meta = {"req": f"req-{i}", "val": i * 10}
        curr = compute_event_hash(prev, meta)
        events.append({
            "event_id": f"id-{i}",
            "previous_hash": prev,
            "current_hash": curr,
            "safe_metadata": meta,
            "sequence_number": i,
        })
        prev = curr

    valid, fail_seq, _ = verify_chain(events, GENESIS_HASH)
    assert valid is True
    assert fail_seq is None

    # Test Merkle tree & proof
    event_hashes = [e["current_hash"] for e in events]
    root, _ = build_merkle_tree(event_hashes)
    assert len(root) == 64

    # Verify proof for event index 4
    proof = generate_merkle_proof(4, event_hashes)
    assert verify_merkle_proof(event_hashes[4], proof, root) is True
