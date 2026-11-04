"""
EBCP-Guard Entity Validator
=============================
Post-detection validation for structured identifiers.

After regex or GLiNER detection, entities must be validated
using domain-specific rules:
  - PAN format rules (not just regex — character position semantics).
  - IFSC structure verification.
  - Luhn checksum for card numbers.
  - Aadhaar structural rules.
  - UPI identifier format rules.

Validation promotes a raw detection to a "validated" entity with
a higher confidence score, improving precision and reducing false positives.

A failed validation DOES NOT discard the entity — it marks it as
unvalidated with reduced confidence. The policy engine can still
apply conservative handling to unvalidated entities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ValidationResult:
    is_valid: bool
    entity_type: str
    confidence_adjustment: float  # additive: +0.05 for valid, -0.15 for invalid
    failure_reason: str | None = None


# ------------------------------------------------------------------ #
# PAN Validation
# ------------------------------------------------------------------ #

_PAN_FOURTH_CHAR_MEANINGS = {
    "P": "Individual",
    "C": "Company",
    "H": "HUF",
    "F": "Firm",
    "A": "AOP",
    "T": "Trust",
    "B": "BOI",
    "L": "Local Authority",
    "J": "Artificial Juridical Person",
    "G": "Government",
}


def validate_pan(pan: str) -> ValidationResult:
    """
    Validate an Indian PAN card number.
    Rules:
      - Exactly 10 characters.
      - First 3: uppercase alpha (AAA–ZZZ).
      - 4th: uppercase alpha (one of the valid entity codes).
      - 5th: uppercase alpha (first letter of surname/company name).
      - 6–9: 4 digits.
      - 10th: uppercase alpha (check character).
    """
    pan = pan.upper().strip()
    if len(pan) != 10:
        return ValidationResult(False, "PAN", -0.15, "PAN must be exactly 10 characters.")
    if not re.match(r"^[A-Z]{3}[A-Z][A-Z][0-9]{4}[A-Z]$", pan):
        return ValidationResult(False, "PAN", -0.15, "PAN format mismatch.")
    if pan[3] not in _PAN_FOURTH_CHAR_MEANINGS:
        return ValidationResult(False, "PAN", -0.10, f"Invalid entity type code: {pan[3]}")
    return ValidationResult(True, "PAN", +0.05)


# ------------------------------------------------------------------ #
# IFSC Validation
# ------------------------------------------------------------------ #

def validate_ifsc(ifsc: str) -> ValidationResult:
    """
    Validate an IFSC code.
    Rules:
      - Exactly 11 characters.
      - First 4: bank code (uppercase alpha).
      - 5th: always '0'.
      - Remaining 6: branch code (alphanumeric).
    """
    ifsc = ifsc.upper().strip()
    if len(ifsc) != 11:
        return ValidationResult(False, "IFSC", -0.15, "IFSC must be exactly 11 characters.")
    if not re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", ifsc):
        return ValidationResult(False, "IFSC", -0.15, "IFSC format mismatch.")
    return ValidationResult(True, "IFSC", +0.05)


# ------------------------------------------------------------------ #
# Luhn Algorithm (Card Number)
# ------------------------------------------------------------------ #

def _luhn_check(number: str) -> bool:
    """Verify a credit/debit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0


def validate_card_number(card: str) -> ValidationResult:
    """
    Validate a payment card number using the Luhn checksum.
    Also checks that the card length falls within typical ranges (13–19 digits).
    """
    digits_only = re.sub(r"\D", "", card)
    if not (13 <= len(digits_only) <= 19):
        return ValidationResult(False, "CARD_NUMBER", -0.20,
                                f"Card number has {len(digits_only)} digits (expected 13–19).")
    if not _luhn_check(digits_only):
        return ValidationResult(False, "CARD_NUMBER", -0.20, "Luhn checksum failed.")
    return ValidationResult(True, "CARD_NUMBER", +0.08)


# ------------------------------------------------------------------ #
# Aadhaar Validation
# ------------------------------------------------------------------ #

def validate_aadhaar(aadhaar: str) -> ValidationResult:
    """
    Structural validation for Aadhaar-like numbers.
    Rules:
      - 12 digits (after removing spaces/hyphens).
      - First digit must be 2–9 (Aadhaar does not start with 0 or 1).
    Note: Full Aadhaar checksum (Verhoeff) is not implemented
          because we operate on synthetic data only.
    """
    digits = re.sub(r"[\s\-]", "", aadhaar)
    if len(digits) != 12:
        return ValidationResult(False, "AADHAAR", -0.15, "Aadhaar must have exactly 12 digits.")
    if digits[0] in ("0", "1"):
        return ValidationResult(False, "AADHAAR", -0.15, "Aadhaar cannot begin with 0 or 1.")
    if not digits.isdigit():
        return ValidationResult(False, "AADHAAR", -0.15, "Aadhaar must contain only digits.")
    return ValidationResult(True, "AADHAAR", +0.05)


# ------------------------------------------------------------------ #
# UPI ID Validation
# ------------------------------------------------------------------ #

_UPI_HANDLE_PATTERN = re.compile(
    r"^[a-zA-Z0-9._\-+]{3,50}@[a-zA-Z]{3,20}$"
)

def validate_upi_id(upi_id: str) -> ValidationResult:
    """
    Validate a UPI Virtual Payment Address (VPA).
    Format: identifier@handle
    Handle must be 3–20 alpha characters.
    """
    if not _UPI_HANDLE_PATTERN.match(upi_id.strip()):
        return ValidationResult(False, "UPI_ID", -0.10, "UPI ID format invalid.")
    return ValidationResult(True, "UPI_ID", +0.05)


# ------------------------------------------------------------------ #
# Account Number Validation
# ------------------------------------------------------------------ #

def validate_account_number(account: str) -> ValidationResult:
    """
    Structural validation for Indian bank account numbers.
    Rules:
      - 9 to 18 digits (varies by bank: SBI uses 11, HDFC uses 14, etc.).
      - Must contain only digits.
    No checksum algorithm is standardized across Indian banks.
    """
    digits = re.sub(r"\D", "", account)
    if not (9 <= len(digits) <= 18):
        return ValidationResult(False, "ACCOUNT_NUMBER", -0.10,
                                f"Account number has {len(digits)} digits (expected 9–18).")
    return ValidationResult(True, "ACCOUNT_NUMBER", +0.03)


# ------------------------------------------------------------------ #
# Email Validation
# ------------------------------------------------------------------ #

_EMAIL_STRICT_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

def validate_email(email: str) -> ValidationResult:
    """Basic RFC-conformant email validation."""
    if not _EMAIL_STRICT_PATTERN.match(email.strip()):
        return ValidationResult(False, "EMAIL", -0.10, "Email format invalid.")
    parts = email.split("@")
    if len(parts) != 2 or "." not in parts[1]:
        return ValidationResult(False, "EMAIL", -0.10, "Email domain invalid.")
    return ValidationResult(True, "EMAIL", +0.04)


# ------------------------------------------------------------------ #
# Dispatcher
# ------------------------------------------------------------------ #

def validate_entity(entity_type: str, value: str) -> ValidationResult:
    """
    Route an entity to the appropriate validator.

    Args:
        entity_type: Detected entity category label.
        value:       Extracted text value.

    Returns:
        ValidationResult with is_valid and confidence_adjustment.
    """
    entity_upper = entity_type.upper()
    validators = {
        "PAN": validate_pan,
        "IFSC": validate_ifsc,
        "CARD_NUMBER": validate_card_number,
        "CREDIT_CARD": validate_card_number,
        "DEBIT_CARD": validate_card_number,
        "AADHAAR": validate_aadhaar,
        "UPI_ID": validate_upi_id,
        "ACCOUNT_NUMBER": validate_account_number,
        "BANK_ACCOUNT": validate_account_number,
        "EMAIL": validate_email,
    }
    validator = validators.get(entity_upper)
    if validator is None:
        # No specific validator — return neutral result
        return ValidationResult(True, entity_type, 0.0)
    return validator(value)
