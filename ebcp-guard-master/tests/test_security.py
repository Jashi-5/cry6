"""
EBCP-Guard Security and Red-Team Test Suite
============================================
Automated regression tests covering all 8 core security attack scenarios:
  1. Plaintext log extraction prevention
  2. Unsalted SHA-256 vs keyed HMAC dictionary attack resistance
  3. Purpose & tenant scope token isolation
  4. Cumulative multi-request exposure escalation
  5. Cryptographic unauthorized decryption prevention
  6. Audit trail tampering detection
  7. Data exfiltration destination blocking
  8. Obfuscated identifier defense-in-depth
"""

import pytest
from app.api.schemas.schemas import AttackSimulationRequest
from simulations.attack_scenarios import (
    attack_1_plaintext_log,
    attack_2_dict_attack,
    attack_3_cross_tenant,
    attack_4_cumulative_exposure,
    attack_5_unauth_decrypt,
    attack_6_audit_tamper,
    attack_7_exfiltration,
    attack_8_model_evasion,
)

def test_attack_1_plaintext_log():
    req = AttackSimulationRequest(scenario="plaintext_log", tenant_id="bank_test")
    res = attack_1_plaintext_log(req)
    assert res.result == "PROTECTED"
    assert res.details["pii_recoverable_from_protected"] is False

def test_attack_2_dictionary_attack():
    req = AttackSimulationRequest(scenario="dict_attack", tenant_id="bank_test")
    res = attack_2_dict_attack(req)
    assert res.result == "PROTECTED"
    assert res.details["hmac_match_with_wrong_key"] is False

def test_attack_3_cross_tenant_separation():
    req = AttackSimulationRequest(scenario="cross_tenant", tenant_id="bank_test")
    res = attack_3_cross_tenant(req)
    assert res.result == "PROTECTED"
    assert res.details["different_purpose_separated"] is True
    assert res.details["different_tenant_separated"] is True

def test_attack_4_cumulative_disclosure():
    req = AttackSimulationRequest(scenario="cumulative", tenant_id="bank_test")
    res = attack_4_cumulative_exposure(req)
    assert res.result in ("PROTECTED", "PARTIAL")
    assert res.details["escalation_detected"] is True

def test_attack_5_unauthorized_decryption():
    req = AttackSimulationRequest(scenario="unauth_decrypt", tenant_id="bank_test")
    res = attack_5_unauth_decrypt(req)
    assert res.result == "PROTECTED"
    assert "BLOCKED" in res.details["wrong_scope"]
    assert "BLOCKED" in res.details["tampered_ciphertext"]

def test_attack_6_audit_tampering():
    req = AttackSimulationRequest(scenario="audit_tamper", tenant_id="bank_test")
    res = attack_6_audit_tamper(req)
    assert res.result == "PROTECTED"
    assert res.details["tampered_chain_valid"] is False

def test_attack_7_exfiltration_policy():
    req = AttackSimulationRequest(scenario="exfiltration", tenant_id="bank_test")
    res = attack_7_exfiltration(req)
    assert res.result == "PROTECTED"
    assert res.details["is_blocked"] is True

def test_attack_8_model_evasion():
    req = AttackSimulationRequest(scenario="evasion", tenant_id="bank_test")
    res = attack_8_model_evasion(req)
    assert res.result in ("PROTECTED", "PARTIAL")
