"""Pydantic models for aumai-pii-redactor."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class PIIType(str, Enum):
    """Categories of personally identifiable information."""

    email = "email"
    phone = "phone"
    ssn = "ssn"
    credit_card = "credit_card"
    ip_address = "ip_address"
    name = "name"
    address = "address"
    date_of_birth = "date_of_birth"
    passport = "passport"
    custom = "custom"


class PIIMatch(BaseModel):
    """A single detected PII span inside a text string."""

    pii_type: PIIType
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    original_text: str
    confidence: float = Field(ge=0.0, le=1.0)


class RedactionStrategy(str, Enum):
    """How a matched PII span should be handled."""

    mask = "mask"         # Replace with *** keeping first/last char
    hash = "hash"         # SHA-256 truncated hex
    remove = "remove"     # Replace with empty string
    replace = "replace"   # Replace with a configured literal string


class RedactionRule(BaseModel):
    """Maps a PII type to a specific redaction strategy."""

    pii_type: PIIType
    strategy: RedactionStrategy
    replacement: str | None = None  # Used only when strategy == replace


class RedactionConfig(BaseModel):
    """Top-level configuration for the redaction engine."""

    rules: list[RedactionRule] = Field(default_factory=list)
    default_strategy: RedactionStrategy = RedactionStrategy.mask
    custom_patterns: dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of custom PII label to raw regex pattern.",
    )


class RedactionResult(BaseModel):
    """Summary of a redaction operation."""

    original_length: int = Field(ge=0)
    redacted_text: str
    matches_found: list[PIIMatch] = Field(default_factory=list)
    redactions_applied: int = Field(ge=0)


__all__ = [
    "PIIMatch",
    "PIIType",
    "RedactionConfig",
    "RedactionResult",
    "RedactionRule",
    "RedactionStrategy",
]
