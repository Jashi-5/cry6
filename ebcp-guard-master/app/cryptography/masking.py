"""
EBCP-Guard Selective Masking Module
=====================================
Implements format-preserving masking strategies for sensitive values.

Masking is the least restrictive protection — it preserves structure
while obscuring sensitive characters. Used when:
  - The destination needs partial context (e.g., last 4 digits).
  - Full tokenization or encryption would break downstream processing.
  - Low-to-medium sensitivity with authorized partial disclosure.

Each masking function must:
  - Only retain explicitly approved characters.
  - Never expose more than what the configured policy allows.
  - Be deterministic (same input → same masked output — no side effects).
"""

from __future__ import annotations

import re


def mask_email(email: str, reveal_domain: bool = True) -> str:
    """
    Mask an email address.

    Strategy:
        - Reveal first character of local part.
        - Reveal last character of local part.
        - Mask middle characters with '*'.
        - Optionally reveal domain.

    Example:
        rahul.sharma@gmail.com → r*****a@gmail.com
        rahul.sharma@gmail.com → r*****a@*****.com  (reveal_domain=False)
    """
    if "@" not in email:
        return "***@***"
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + ("*" * (len(local) - 2)) + local[-1]

    if reveal_domain:
        masked_domain = domain
    else:
        parts = domain.split(".")
        masked_domain = ("*" * len(parts[0])) + "." + ".".join(parts[1:])

    return f"{masked_local}@{masked_domain}"


def mask_phone(phone: str, reveal_last_n: int = 4) -> str:
    """
    Mask a phone number, revealing only country prefix and last N digits.

    Example:
        +91-9876543210 → +91-XXXXXX3210  (reveal_last_n=4)
    """
    prefix = ""
    clean_phone = phone
    for p in ["+91-", "+91 ", "+91", "0091-", "+1-", "+44-"]:
        if phone.startswith(p):
            prefix = p
            clean_phone = phone[len(p):]
            break

    digits_only = re.sub(r"\D", "", clean_phone)
    if len(digits_only) <= reveal_last_n:
        return phone

    masked_digits = "X" * (len(digits_only) - reveal_last_n) + digits_only[-reveal_last_n:]

    result = []
    digit_idx = 0
    for char in clean_phone:
        if char.isdigit():
            result.append(masked_digits[digit_idx])
            digit_idx += 1
        else:
            result.append(char)
    return prefix + "".join(result)


def mask_account_number(account: str, reveal_last_n: int = 4) -> str:
    """
    Mask a bank account number.

    Example:
        123456789012 → ********9012
    """
    clean = re.sub(r"\D", "", account)
    if len(clean) <= reveal_last_n:
        return account
    return "*" * (len(clean) - reveal_last_n) + clean[-reveal_last_n:]


def mask_card_number(card: str, reveal_last_n: int = 4) -> str:
    """
    Mask a payment card number in standard format.

    Example:
        4111-1111-1111-1234 → XXXX-XXXX-XXXX-1234
    """
    digits = re.sub(r"\D", "", card)
    if len(digits) < 12:
        return "*" * len(card)

    masked_digits = "X" * (len(digits) - reveal_last_n) + digits[-reveal_last_n:]

    # Reformat with original separators
    result = []
    digit_idx = 0
    for char in card:
        if char.isdigit():
            result.append(masked_digits[digit_idx])
            digit_idx += 1
        else:
            result.append(char)
    return "".join(result)


def mask_pan(pan: str) -> str:
    """
    Mask an Indian PAN (Permanent Account Number).
    PAN format: AAAAA9999A (5 letters, 4 digits, 1 letter).

    Example:
        ABCDE1234F → ABCDE****F  (preserve structure, mask digits)
    """
    pan = pan.upper().strip()
    if len(pan) != 10:
        return "X" * len(pan)
    return pan[:5] + "****" + pan[-1]


def mask_aadhaar(aadhaar: str, reveal_last_n: int = 4) -> str:
    """
    Mask an Aadhaar-like 12-digit identifier.
    Compliant with UIDAI masking guidelines (reveal last 4 digits).

    Example:
        1234 5678 9012 → XXXX XXXX 9012
    """
    digits = re.sub(r"\D", "", aadhaar)
    if len(digits) < reveal_last_n:
        return "X" * len(aadhaar)

    masked_digits = "X" * (len(digits) - reveal_last_n) + digits[-reveal_last_n:]

    result = []
    digit_idx = 0
    for char in aadhaar:
        if char.isdigit():
            result.append(masked_digits[digit_idx])
            digit_idx += 1
        else:
            result.append(char)
    return "".join(result)


def mask_name(name: str, strategy: str = "initials") -> str:
    """
    Mask a person name.

    Strategies:
        'initials': Show only first character of each word.
            "Rahul Sharma" → "R. S."
        'first_only': Show first name, mask last name.
            "Rahul Sharma" → "Rahul *****"
        'full': Replace entire name.
            "Rahul Sharma" → "***"

    Args:
        name:     The name to mask.
        strategy: 'initials' | 'first_only' | 'full'
    """
    parts = name.strip().split()
    if not parts:
        return "***"

    if strategy == "initials":
        return " ".join(f"{p[0]}." for p in parts if p)
    elif strategy == "first_only":
        if len(parts) == 1:
            return parts[0]
        return parts[0] + " " + ("*" * len(" ".join(parts[1:])))
    else:
        return "***"


def mask_address(address: str) -> str:
    """
    Mask a street address — preserve city/state/country only.

    Example:
        "123 MG Road, Pune, Maharashtra, India"
        → "***, Pune, Maharashtra, India"
    """
    parts = [p.strip() for p in address.split(",")]
    if len(parts) <= 1:
        return "***"
    # Mask the street number/name (first part), keep city onward
    return "*** " + ", ".join(parts[1:])


def mask_upi_id(upi_id: str) -> str:
    """
    Mask a UPI ID.

    Example:
        rahulsharma@okaxis → r*****a@okaxis
    """
    return mask_email(upi_id, reveal_domain=True)


def mask_ifsc(ifsc: str) -> str:
    """
    Mask an IFSC code — keep bank identifier (first 4 chars), mask branch.

    Example:
        HDFC0001234 → HDFC*****
    """
    if len(ifsc) < 4:
        return "***"
    return ifsc[:4] + "*" * (len(ifsc) - 4)


def redact_field(value: str) -> str:
    """
    Fully redact a field — replace with [REDACTED].
    Used for the most sensitive fields where partial disclosure is not permitted.
    """
    return "[REDACTED]"


def mask_by_entity_type(
    value: str,
    entity_type: str,
    strategy: str = "default",
) -> str:
    """
    Route masking to the appropriate function based on entity type.

    Args:
        value:       Original sensitive value.
        entity_type: Entity category (EMAIL, PHONE, PAN, etc.).
        strategy:    Additional strategy hint for configurable masking.

    Returns:
        Masked string appropriate for the entity type.
    """
    entity_upper = entity_type.upper()

    if entity_upper in ("EMAIL", "UPI_ID", "UPI"):
        return mask_email(value)
    elif entity_upper in ("PHONE", "PHONE_NUMBER", "MOBILE", "MOBILE_NUMBER"):
        return mask_phone(value)
    elif entity_upper in ("ACCOUNT_NUMBER", "BANK_ACCOUNT"):
        return mask_account_number(value)
    elif entity_upper in ("CARD_NUMBER", "CREDIT_CARD", "DEBIT_CARD"):
        return mask_card_number(value)
    elif entity_upper == "PAN":
        return mask_pan(value)
    elif entity_upper in ("AADHAAR", "AADHAAR_NUMBER", "UID"):
        return mask_aadhaar(value)
    elif entity_upper in ("PERSON", "NAME", "CUSTOMER_NAME"):
        return mask_name(value, strategy=strategy if strategy != "default" else "initials")
    elif entity_upper in ("ADDRESS", "LOCATION"):
        return mask_address(value)
    elif entity_upper == "IFSC":
        return mask_ifsc(value)
    else:
        # Default: mask middle portion
        if len(value) <= 4:
            return "*" * len(value)
        return value[0] + "*" * (len(value) - 2) + value[-1]
