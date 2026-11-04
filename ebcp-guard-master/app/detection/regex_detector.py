"""
EBCP-Guard Regex Detector
===========================
Deterministic pattern-based detection for structured Indian banking
and standard PII identifiers.

Design:
  - Patterns are anchored and use non-capturing groups where possible.
  - Confidence is set based on pattern specificity (not dynamic).
  - Results feed into the hybrid detector alongside GLiNER.
  - Validation is handled by entity_validator.py AFTER detection.

Indian banking identifiers covered:
  PAN, Aadhaar-like, IFSC, UPI ID, bank account numbers,
  Indian mobile numbers, GST numbers.

Standard identifiers:
  Email, international phone, credit/debit card (partial — Luhn check in validator).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern


@dataclass
class RegexMatch:
    """A single pattern-matched entity span."""
    entity_type: str
    start: int
    end: int
    value: str
    confidence: float
    pattern_name: str


@dataclass
class _PatternSpec:
    entity_type: str
    pattern: Pattern[str]
    confidence: float
    pattern_name: str


def _compile(entity_type: str, pattern: str, confidence: float, name: str) -> _PatternSpec:
    return _PatternSpec(
        entity_type=entity_type,
        pattern=re.compile(pattern, re.IGNORECASE),
        confidence=confidence,
        pattern_name=name,
    )


# ------------------------------------------------------------------ #
# Pattern Library
# ------------------------------------------------------------------ #
_PATTERNS: list[_PatternSpec] = [

    # --- Email ---
    _compile("EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
             0.95, "email_rfc5322"),

    # Disguised email: user%40bank.com, user[at]bank[dot]com, user(at)bank.com
    _compile("EMAIL",
             r"\b[\w.%+\-]+(?:\[dot\][\w.%+\-]+)*(?:%40|\s?\[at\]\s?|\s?\(at\)\s?)[\w\-]+(?:(?:\.|\[dot\])[\w\-]+)+",
             0.80, "email_disguised"),

    # --- Indian PAN (Permanent Account Number)
    # Format: AAAAA9999A — 5 uppercase letters, 4 digits, 1 uppercase letter (optionally split)
    _compile("PAN", r"\b[A-Z]{5}[\s\-]?[0-9]{4}[\s\-]?[A-Z]\b",
             0.92, "pan_india"),

    # --- Aadhaar-like (12 digits, optionally spaced in groups of 4)
    _compile("AADHAAR", r"\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
             0.85, "aadhaar_india"),

    # --- IFSC Code (Indian Financial System Code)
    # Format: AAAA0XXXXXX — 4 alpha + 0 + 6 alphanumeric
    _compile("IFSC", r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
             0.93, "ifsc_india"),

    # --- UPI ID
    # Format: identifier@upi-handle
    _compile("UPI_ID", r"\b[a-zA-Z0-9._\-+]+@(?:upi|oksbi|okaxis|okhdfcbank|okicici|ybl|ibl|axl|paytm|apl|pingpay|waicici)\b",
             0.90, "upi_vpa"),

    # Generic UPI (less specific — lower confidence)
    _compile("UPI_ID", r"\b[a-zA-Z0-9._\-+]{3,50}@[a-zA-Z]{3,20}\b",
             0.70, "upi_generic"),

    # --- Indian Mobile Number
    # Starts with 6-9, 10 digits (optionally split 5-5), optional +91 or 0 prefix.
    # The separator belongs to the prefix only: a captured leading space makes the
    # value impossible to find in the original field, which leaks it.
    _compile("PHONE", r"(?<!\d)(?:(?:\+91|0091|0)[-\s]?)?[6-9]\d{4}[-\s]?\d{5}\b",
             0.88, "mobile_india"),

    # --- International Phone (E.164 style)
    _compile("PHONE", r"\+[1-9]\d{1,14}\b",
             0.80, "phone_e164"),

    # --- Bank Account Number (Indian — 9 to 18 digits)
    # This pattern is broad; validation uses checksum or length ranges
    _compile("ACCOUNT_NUMBER",
             r"\b(?:account(?:\s+(?:number|no\.?))?[\s:]*)?([0-9]{9,18})\b",
             0.65, "bank_account_india"),

    # --- Credit/Debit Card Number (Luhn validated in entity_validator)
    # Groups of 4 digits separated by spaces or hyphens
    _compile("CARD_NUMBER",
             r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b",
             0.87, "card_number_major"),

    # --- GST Number (India)
    # Format: 2-digit state code + 10-char PAN + 1Z + 1 alphanumeric + checksum
    _compile("GST_NUMBER",
             r"\b[0-3][0-9][A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
             0.91, "gst_india"),

    # --- Date of Birth (DD/MM/YYYY or YYYY-MM-DD)
    _compile("DATE_OF_BIRTH",
             r"\b(?:0[1-9]|[12][0-9]|3[01])[\/\-](?:0[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b",
             0.72, "dob_dmy"),
    _compile("DATE_OF_BIRTH",
             r"\b(?:19|20)\d{2}[\/\-](?:0[1-9]|1[0-2])[\/\-](?:0[1-9]|[12][0-9]|3[01])\b",
             0.72, "dob_iso"),

    # --- Transaction Amount (INR)
    _compile("TRANSACTION_AMOUNT",
             r"(?:INR|₹|Rs\.?)\s*[\d,]+(?:\.\d{2})?",
             0.80, "amount_inr"),

    # --- IPv4 Address (low sensitivity but trackable)
    _compile("IP_ADDRESS",
             r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{2}?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{2}?)\b",
             0.85, "ipv4"),
]


class RegexDetector:
    """
    Deterministic regex-based entity detector.
    Runs against the full text of an input string and returns all matches.

    Usage:
        detector = RegexDetector()
        matches = detector.detect("Email: rahul@example.com, PAN: ABCDE1234F")
    """

    def __init__(self) -> None:
        self._patterns = _PATTERNS

    def detect(self, text: str) -> list[RegexMatch]:
        """
        Run all patterns against the text and return non-overlapping matches.

        Overlapping matches are resolved by keeping the highest-confidence match.
        Longer matches take precedence over shorter ones at the same confidence.

        Args:
            text: Input text to scan.

        Returns:
            List of RegexMatch objects in ascending offset order.
        """
        raw_matches: list[RegexMatch] = []

        for spec in self._patterns:
            for m in spec.pattern.finditer(text):
                # Use group(1) if a capturing group is present (e.g., account number)
                if m.lastindex:
                    start = m.start(1)
                    end = m.end(1)
                    value = m.group(1)
                else:
                    start = m.start()
                    end = m.end()
                    value = m.group()

                raw_matches.append(RegexMatch(
                    entity_type=spec.entity_type,
                    start=start,
                    end=end,
                    value=value,
                    confidence=spec.confidence,
                    pattern_name=spec.pattern_name,
                ))

        return self._resolve_overlaps(raw_matches)

    @staticmethod
    def _resolve_overlaps(matches: list[RegexMatch]) -> list[RegexMatch]:
        """
        Remove overlapping matches, keeping the best candidate at each position.
        Priority: highest confidence, then longest span.
        """
        if not matches:
            return []

        # Sort by confidence desc, then span length desc
        sorted_matches = sorted(
            matches,
            key=lambda m: (m.confidence, m.end - m.start),
            reverse=True,
        )

        selected: list[RegexMatch] = []
        occupied: list[tuple[int, int]] = []

        for match in sorted_matches:
            overlaps = any(
                not (match.end <= occ_start or match.start >= occ_end)
                for occ_start, occ_end in occupied
            )
            if not overlaps:
                selected.append(match)
                occupied.append((match.start, match.end))

        return sorted(selected, key=lambda m: m.start)


# Module-level singleton
_regex_detector: RegexDetector | None = None


def get_regex_detector() -> RegexDetector:
    """Return the cached RegexDetector singleton."""
    global _regex_detector
    if _regex_detector is None:
        _regex_detector = RegexDetector()
    return _regex_detector
