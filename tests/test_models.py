"""Tests for aumai_pii_redactor.models — Pydantic model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aumai_pii_redactor.models import (
    PIIMatch,
    PIIType,
    RedactionConfig,
    RedactionResult,
    RedactionRule,
    RedactionStrategy,
)

# ---------------------------------------------------------------------------
# PIIType
# ---------------------------------------------------------------------------


class TestPIIType:
    def test_all_expected_members_exist(self) -> None:
        expected = {
            "email", "phone", "ssn", "credit_card", "ip_address",
            "name", "address", "date_of_birth", "passport", "custom",
        }
        actual = {member.value for member in PIIType}
        assert actual == expected

    def test_is_string_enum(self) -> None:
        assert isinstance(PIIType.email, str)
        assert PIIType.email == "email"

    def test_construction_from_string(self) -> None:
        assert PIIType("ssn") is PIIType.ssn

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            PIIType("national_id")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# RedactionStrategy
# ---------------------------------------------------------------------------


class TestRedactionStrategy:
    def test_all_expected_members(self) -> None:
        expected = {"mask", "hash", "remove", "replace"}
        assert {s.value for s in RedactionStrategy} == expected

    def test_is_string_enum(self) -> None:
        assert isinstance(RedactionStrategy.mask, str)

    def test_construction_from_string(self) -> None:
        assert RedactionStrategy("hash") is RedactionStrategy.hash


# ---------------------------------------------------------------------------
# PIIMatch
# ---------------------------------------------------------------------------


class TestPIIMatch:
    def test_valid_construction(self) -> None:
        match = PIIMatch(
            pii_type=PIIType.email,
            start=0,
            end=20,
            original_text="user@example.com",
            confidence=0.99,
        )
        assert match.pii_type == PIIType.email
        assert match.start == 0
        assert match.end == 20
        assert match.confidence == 0.99

    def test_negative_start_raises(self) -> None:
        with pytest.raises(ValidationError):
            PIIMatch(
                pii_type=PIIType.email,
                start=-1,
                end=10,
                original_text="x",
                confidence=0.5,
            )

    def test_confidence_above_one_raises(self) -> None:
        with pytest.raises(ValidationError):
            PIIMatch(
                pii_type=PIIType.ssn,
                start=0,
                end=11,
                original_text="123-45-6789",
                confidence=1.1,
            )

    def test_confidence_below_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            PIIMatch(
                pii_type=PIIType.phone,
                start=0,
                end=12,
                original_text="555-867-5309",
                confidence=-0.01,
            )

    def test_confidence_boundary_zero(self) -> None:
        match = PIIMatch(
            pii_type=PIIType.name,
            start=0,
            end=4,
            original_text="John",
            confidence=0.0,
        )
        assert match.confidence == 0.0

    def test_confidence_boundary_one(self) -> None:
        match = PIIMatch(
            pii_type=PIIType.email,
            start=0,
            end=16,
            original_text="user@example.com",
            confidence=1.0,
        )
        assert match.confidence == 1.0

    def test_model_dump_round_trip(self) -> None:
        match = PIIMatch(
            pii_type=PIIType.credit_card,
            start=5,
            end=24,
            original_text="4111 1111 1111 1111",
            confidence=0.98,
        )
        dumped = match.model_dump(mode="json")
        restored = PIIMatch(**dumped)
        assert restored == match


# ---------------------------------------------------------------------------
# RedactionRule
# ---------------------------------------------------------------------------


class TestRedactionRule:
    def test_basic_rule(self) -> None:
        rule = RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.mask)
        assert rule.replacement is None

    def test_replace_rule_with_literal(self) -> None:
        rule = RedactionRule(
            pii_type=PIIType.ssn,
            strategy=RedactionStrategy.replace,
            replacement="[SSN REDACTED]",
        )
        assert rule.replacement == "[SSN REDACTED]"

    def test_missing_pii_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            RedactionRule(strategy=RedactionStrategy.mask)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# RedactionConfig
# ---------------------------------------------------------------------------


class TestRedactionConfig:
    def test_defaults(self) -> None:
        config = RedactionConfig()
        assert config.rules == []
        assert config.default_strategy == RedactionStrategy.mask
        assert config.custom_patterns == {}

    def test_custom_strategy_default(self) -> None:
        config = RedactionConfig(default_strategy=RedactionStrategy.remove)
        assert config.default_strategy == RedactionStrategy.remove

    def test_rules_populated(self) -> None:
        rules = [
            RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.hash),
            RedactionRule(pii_type=PIIType.phone, strategy=RedactionStrategy.remove),
        ]
        config = RedactionConfig(rules=rules)
        assert len(config.rules) == 2

    def test_custom_patterns(self) -> None:
        config = RedactionConfig(custom_patterns={"order_id": r"\bORD-\d{8}\b"})
        assert "order_id" in config.custom_patterns

    def test_invalid_default_strategy_raises(self) -> None:
        with pytest.raises(ValidationError):
            RedactionConfig(default_strategy="obliterate")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# RedactionResult
# ---------------------------------------------------------------------------


class TestRedactionResult:
    def test_basic_construction(self) -> None:
        result = RedactionResult(
            original_length=50,
            redacted_text="Hello ***.",
            matches_found=[],
            redactions_applied=0,
        )
        assert result.original_length == 50
        assert result.redactions_applied == 0

    def test_negative_original_length_raises(self) -> None:
        with pytest.raises(ValidationError):
            RedactionResult(
                original_length=-1,
                redacted_text="",
                matches_found=[],
                redactions_applied=0,
            )

    def test_negative_redactions_applied_raises(self) -> None:
        with pytest.raises(ValidationError):
            RedactionResult(
                original_length=10,
                redacted_text="text",
                matches_found=[],
                redactions_applied=-1,
            )
