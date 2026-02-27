"""Shared pytest fixtures for aumai-pii-redactor tests."""

from __future__ import annotations

import pytest

from aumai_pii_redactor.detector import PIIDetector
from aumai_pii_redactor.models import (
    PIIType,
    RedactionConfig,
    RedactionRule,
    RedactionStrategy,
)
from aumai_pii_redactor.redactor import PIIRedactor

# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_config() -> RedactionConfig:
    """Bare config — no explicit rules, default strategy is mask."""
    return RedactionConfig()


@pytest.fixture()
def mask_config() -> RedactionConfig:
    """Config that masks every PII type explicitly."""
    rules = [
        RedactionRule(pii_type=pii_type, strategy=RedactionStrategy.mask)
        for pii_type in PIIType
    ]
    return RedactionConfig(rules=rules, default_strategy=RedactionStrategy.mask)


@pytest.fixture()
def hash_config() -> RedactionConfig:
    """Config that hashes every PII type."""
    rules = [
        RedactionRule(pii_type=pii_type, strategy=RedactionStrategy.hash)
        for pii_type in PIIType
    ]
    return RedactionConfig(rules=rules, default_strategy=RedactionStrategy.hash)


@pytest.fixture()
def remove_config() -> RedactionConfig:
    """Config that removes (deletes) every PII type."""
    rules = [
        RedactionRule(pii_type=pii_type, strategy=RedactionStrategy.remove)
        for pii_type in PIIType
    ]
    return RedactionConfig(rules=rules, default_strategy=RedactionStrategy.remove)


@pytest.fixture()
def replace_config() -> RedactionConfig:
    """Config that replaces every PII type with '[REDACTED]'."""
    rules = [
        RedactionRule(
            pii_type=pii_type,
            strategy=RedactionStrategy.replace,
            replacement="[REDACTED]",
        )
        for pii_type in PIIType
    ]
    return RedactionConfig(rules=rules, default_strategy=RedactionStrategy.replace)


@pytest.fixture()
def mixed_strategy_config() -> RedactionConfig:
    """Per-type strategy config for varied coverage."""
    return RedactionConfig(
        rules=[
            RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.mask),
            RedactionRule(pii_type=PIIType.ssn, strategy=RedactionStrategy.replace, replacement="[SSN]"),
            RedactionRule(pii_type=PIIType.credit_card, strategy=RedactionStrategy.hash),
            RedactionRule(pii_type=PIIType.phone, strategy=RedactionStrategy.remove),
            RedactionRule(pii_type=PIIType.ip_address, strategy=RedactionStrategy.hash),
        ],
        default_strategy=RedactionStrategy.mask,
    )


@pytest.fixture()
def custom_pattern_config() -> RedactionConfig:
    """Config with a custom regex pattern for employee IDs."""
    return RedactionConfig(
        custom_patterns={"employee_id": r"\bEMP-\d{6}\b"},
        default_strategy=RedactionStrategy.mask,
    )


# ---------------------------------------------------------------------------
# Detector / Redactor fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_detector(default_config: RedactionConfig) -> PIIDetector:
    return PIIDetector(default_config)


@pytest.fixture()
def default_redactor(default_config: RedactionConfig) -> PIIRedactor:
    return PIIRedactor(default_config)


@pytest.fixture()
def mixed_redactor(mixed_strategy_config: RedactionConfig) -> PIIRedactor:
    return PIIRedactor(mixed_strategy_config)


# ---------------------------------------------------------------------------
# Text samples
# ---------------------------------------------------------------------------


@pytest.fixture()
def email_text() -> str:
    return "Contact me at alice@example.com for details."


@pytest.fixture()
def phone_text() -> str:
    return "Call us at 555-867-5309 anytime."


@pytest.fixture()
def ssn_text() -> str:
    return "My SSN is 123-45-6789."


@pytest.fixture()
def credit_card_text() -> str:
    # Luhn-valid Visa test number
    return "Charge to card 4111 1111 1111 1111 please."


@pytest.fixture()
def ipv4_text() -> str:
    return "Server at 192.168.1.100 is down."


@pytest.fixture()
def ipv6_text() -> str:
    return "IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"


@pytest.fixture()
def dob_text() -> str:
    return "Date of birth: 01/15/1990"


@pytest.fixture()
def passport_text() -> str:
    return "Passport number AB1234567 issued."


@pytest.fixture()
def multi_pii_text() -> str:
    return (
        "Name: John Doe. Email: john.doe@example.com. "
        "Phone: 555-123-4567. SSN: 123-45-6789. "
        "IP: 10.0.0.1. DOB: 03/22/1985."
    )


@pytest.fixture()
def clean_text() -> str:
    return "This text contains absolutely no personally identifiable information."
