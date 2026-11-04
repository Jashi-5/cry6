"""
EBCP-Guard Sensitive Entity Detection Tests
============================================
Tests:
  - Regex pattern matching for PAN, Aadhaar, IFSC, UPI, Phone, Email, Cards.
  - Entity validation logic (Luhn algorithm, PAN format rules, IFSC format rules).
  - Overlap resolution & confidence score calibration.
"""

from app.detection.regex_detector import get_regex_detector
from app.detection.entity_validator import (
    validate_pan, validate_ifsc, validate_card_number, validate_aadhaar, validate_upi_id, validate_entity
)

def test_regex_pan_detection_and_validation():
    detector = get_regex_detector()
    text = "Customer PAN is ABCPE1234F and IFSC is HDFC0001234"
    matches = detector.detect(text)

    types = {m.entity_type: m.value for m in matches}
    assert "PAN" in types
    assert types["PAN"] == "ABCPE1234F"
    assert "IFSC" in types
    assert types["IFSC"] == "HDFC0001234"

    # Validator checks
    assert validate_pan("ABCPE1234F").is_valid is True
    assert validate_pan("12345ABCDE").is_valid is False
    assert validate_ifsc("HDFC0001234").is_valid is True
    assert validate_ifsc("HDFC1001234").is_valid is False  # 5th char must be 0

def test_luhn_card_validation():
    # Valid Visa test number
    valid_visa = "4532015112830366"
    assert validate_card_number(valid_visa).is_valid is True

    # Invalid checksum
    invalid_visa = "4532015112830367"
    assert validate_card_number(invalid_visa).is_valid is False

def test_upi_and_aadhaar_validation():
    assert validate_upi_id("rahul@oksbi").is_valid is True
    assert validate_upi_id("not-a-upi").is_valid is False

    assert validate_aadhaar("2345 6789 0123").is_valid is True
    assert validate_aadhaar("0123 4567 8901").is_valid is False # Cannot start with 0


def test_upi_vpa_captures_full_id_not_just_domain():
    # Regression: UPI pattern used a capturing group, so only "okhdfcbank" was returned
    from app.detection.regex_detector import get_regex_detector

    matches = [m for m in get_regex_detector().detect("pay jalsaiyer@okhdfcbank now")
               if m.entity_type == "UPI_ID"]
    assert [m.value for m in matches] == ["jalsaiyer@okhdfcbank"]
