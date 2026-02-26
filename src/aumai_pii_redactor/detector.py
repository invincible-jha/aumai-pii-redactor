"""PII detection using compiled regular expressions."""

from __future__ import annotations

import re
from typing import Iterator

from aumai_pii_redactor.models import PIIMatch, PIIType, RedactionConfig

# ---------------------------------------------------------------------------
# Built-in patterns
# ---------------------------------------------------------------------------

# Each pattern is (PIIType, compiled_regex, confidence_score).
# Patterns are ordered from most-specific to least-specific to reduce overlap.

_BUILTIN_PATTERNS: list[tuple[PIIType, re.Pattern[str], float]] = [
    # SSN — must come before generic numbers
    (
        PIIType.ssn,
        re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
        0.95,
    ),
    # Credit card (Luhn-candidate 13-19 digit sequences with optional separators)
    (
        PIIType.credit_card,
        re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"),
        0.90,
    ),
    # Email
    (
        PIIType.email,
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            re.IGNORECASE,
        ),
        0.99,
    ),
    # US phone (various formats) + international E.164
    (
        PIIType.phone,
        re.compile(
            r"(?:\+?1[\s\-.]?)?"
            r"(?:\(?\d{3}\)?[\s\-.]?)"
            r"\d{3}[\s\-.]?\d{4}\b"
        ),
        0.85,
    ),
    # IPv6 — before IPv4 to avoid partial matches
    (
        PIIType.ip_address,
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
            r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
            r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b",
            re.IGNORECASE,
        ),
        0.98,
    ),
    # IPv4
    (
        PIIType.ip_address,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        0.95,
    ),
    # Passport — US format (letter + 8 digits); generic 6-9 alphanum
    (
        PIIType.passport,
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        0.70,
    ),
    # Date of birth — common formats
    (
        PIIType.date_of_birth,
        re.compile(
            r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
        ),
        0.80,
    ),
]


# ---------------------------------------------------------------------------
# Luhn check (used to boost credit-card confidence)
# ---------------------------------------------------------------------------

def _luhn_valid(number_str: str) -> bool:
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class PIIDetector:
    """Detect PII spans in text using configurable regex patterns."""

    def __init__(self, config: RedactionConfig) -> None:
        self._config = config
        self._custom_patterns: list[tuple[PIIType, re.Pattern[str], float]] = []
        for label, raw_pattern in config.custom_patterns.items():
            compiled = re.compile(raw_pattern)
            self._custom_patterns.append((PIIType.custom, compiled, 0.80))

    def detect(self, text: str) -> list[PIIMatch]:
        """Return all PII matches found in *text*, deduplicated by span."""
        matches: list[PIIMatch] = []
        seen_spans: set[tuple[int, int]] = set()

        for pii_type, pattern, base_confidence in (
            _BUILTIN_PATTERNS + self._custom_patterns
        ):
            for match in pattern.finditer(text):
                span = (match.start(), match.end())
                if span in seen_spans:
                    continue

                original = match.group()
                confidence = base_confidence

                # Boost credit card confidence with Luhn check
                if pii_type == PIIType.credit_card:
                    if _luhn_valid(original):
                        confidence = min(1.0, confidence + 0.08)
                    else:
                        confidence = max(0.0, confidence - 0.30)

                seen_spans.add(span)
                matches.append(
                    PIIMatch(
                        pii_type=pii_type,
                        start=match.start(),
                        end=match.end(),
                        original_text=original,
                        confidence=confidence,
                    )
                )

        matches.sort(key=lambda m: m.start)
        return matches

    def detect_in_dict(self, data: dict[str, object]) -> dict[str, list[PIIMatch]]:
        """Recursively traverse *data* and detect PII in all string values.

        Returns:
            A mapping from dot-joined key path to the list of matches found in
            that value.  Only paths with at least one match are included.
        """
        results: dict[str, list[PIIMatch]] = {}
        for path, value in _flatten_dict(data):
            if isinstance(value, str):
                matches = self.detect(value)
                if matches:
                    results[path] = matches
        return results


# ---------------------------------------------------------------------------
# Dict flattening helper
# ---------------------------------------------------------------------------

def _flatten_dict(
    data: object,
    prefix: str = "",
) -> Iterator[tuple[str, object]]:
    """Yield (dotted_key, value) pairs for all leaf values in a nested dict."""
    if isinstance(data, dict):
        for key, val in data.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_dict(val, full_key)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            full_key = f"{prefix}[{idx}]"
            yield from _flatten_dict(item, full_key)
    else:
        yield prefix, data


__all__ = ["PIIDetector"]
