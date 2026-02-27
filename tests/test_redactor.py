"""Tests for aumai_pii_redactor.redactor — redaction strategies and PIIRedactor."""

from __future__ import annotations

import hashlib
import re

from aumai_pii_redactor.models import (
    PIIType,
    RedactionConfig,
    RedactionResult,
    RedactionRule,
    RedactionStrategy,
)
from aumai_pii_redactor.redactor import (
    PIIRedactor,
    _apply_hash,
    _apply_mask,
    _apply_remove,
    _apply_replace,
    _apply_strategy,
)

# ---------------------------------------------------------------------------
# Strategy unit tests — private helpers
# ---------------------------------------------------------------------------


class TestApplyMask:
    def test_long_text(self) -> None:
        assert _apply_mask("alice@example.com") == "a***m"

    def test_two_char_text(self) -> None:
        assert _apply_mask("ab") == "**"

    def test_one_char_text(self) -> None:
        assert _apply_mask("x") == "*"

    def test_three_char_text(self) -> None:
        result = _apply_mask("abc")
        assert result == "a***c"

    def test_preserves_first_and_last(self) -> None:
        text = "hello"
        result = _apply_mask(text)
        assert result[0] == text[0]
        assert result[-1] == text[-1]

    def test_middle_is_three_stars(self) -> None:
        result = _apply_mask("password123")
        assert "***" in result
        # Exactly first + *** + last
        assert result == "p***3"


class TestApplyHash:
    def test_returns_12_hex_chars(self) -> None:
        result = _apply_hash("anything")
        assert len(result) == 12
        assert re.fullmatch(r"[0-9a-f]{12}", result)

    def test_deterministic(self) -> None:
        assert _apply_hash("test@example.com") == _apply_hash("test@example.com")

    def test_different_inputs_produce_different_hashes(self) -> None:
        assert _apply_hash("aaa") != _apply_hash("bbb")

    def test_matches_manual_sha256(self) -> None:
        text = "user@example.com"
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        assert _apply_hash(text) == expected

    def test_empty_string(self) -> None:
        result = _apply_hash("")
        assert len(result) == 12


class TestApplyRemove:
    def test_always_returns_empty(self) -> None:
        for text in ["hello", "123-45-6789", "a@b.c", ""]:
            assert _apply_remove(text) == ""


class TestApplyReplace:
    def test_uses_replacement_when_provided(self) -> None:
        assert _apply_replace("anything", "[SSN]") == "[SSN]"

    def test_falls_back_to_redacted_when_none(self) -> None:
        assert _apply_replace("anything", None) == "[REDACTED]"

    def test_empty_replacement_string(self) -> None:
        # An explicit empty string is a valid replacement
        assert _apply_replace("anything", "") == ""


class TestApplyStrategy:
    def test_dispatches_mask(self) -> None:
        result = _apply_strategy("hello@world.com", RedactionStrategy.mask, None)
        assert result == "h***m"

    def test_dispatches_hash(self) -> None:
        result = _apply_strategy("foo", RedactionStrategy.hash, None)
        assert len(result) == 12

    def test_dispatches_remove(self) -> None:
        assert _apply_strategy("foo", RedactionStrategy.remove, None) == ""

    def test_dispatches_replace_with_literal(self) -> None:
        assert _apply_strategy("foo", RedactionStrategy.replace, "[X]") == "[X]"

    def test_dispatches_replace_without_literal(self) -> None:
        assert _apply_strategy("foo", RedactionStrategy.replace, None) == "[REDACTED]"


# ---------------------------------------------------------------------------
# PIIRedactor.redact — result structure
# ---------------------------------------------------------------------------


class TestRedactResultStructure:
    def test_returns_redaction_result(self, default_redactor: PIIRedactor) -> None:
        result = default_redactor.redact("user@example.com")
        assert isinstance(result, RedactionResult)

    def test_original_length_correct(self, default_redactor: PIIRedactor) -> None:
        text = "user@example.com"
        result = default_redactor.redact(text)
        assert result.original_length == len(text)

    def test_matches_found_populated(self, default_redactor: PIIRedactor) -> None:
        result = default_redactor.redact("user@example.com")
        assert result.matches_found

    def test_redactions_applied_count(self, default_redactor: PIIRedactor) -> None:
        result = default_redactor.redact("user@example.com and 555-123-4567")
        assert result.redactions_applied == len(result.matches_found)

    def test_clean_text_no_matches(self, default_redactor: PIIRedactor, clean_text: str) -> None:
        result = default_redactor.redact(clean_text)
        assert result.matches_found == []
        assert result.redactions_applied == 0
        assert result.redacted_text == clean_text

    def test_empty_string(self, default_redactor: PIIRedactor) -> None:
        result = default_redactor.redact("")
        assert result.original_length == 0
        assert result.redacted_text == ""
        assert result.redactions_applied == 0


# ---------------------------------------------------------------------------
# PIIRedactor.redact — mask strategy
# ---------------------------------------------------------------------------


class TestRedactMaskStrategy:
    def test_email_masked(self, default_redactor: PIIRedactor) -> None:
        result = default_redactor.redact("Email: user@example.com")
        assert "user@example.com" not in result.redacted_text
        assert "***" in result.redacted_text

    def test_ssn_masked_default(self) -> None:
        config = RedactionConfig(default_strategy=RedactionStrategy.mask)
        redactor = PIIRedactor(config)
        result = redactor.redact("SSN: 123-45-6789")
        assert "123-45-6789" not in result.redacted_text

    def test_mask_preserves_surrounding_text(self, default_redactor: PIIRedactor) -> None:
        result = default_redactor.redact("Contact user@test.com today")
        assert result.redacted_text.startswith("Contact ")
        assert result.redacted_text.endswith(" today")


# ---------------------------------------------------------------------------
# PIIRedactor.redact — hash strategy
# ---------------------------------------------------------------------------


class TestRedactHashStrategy:
    def test_email_hashed(self, hash_config: RedactionConfig) -> None:
        redactor = PIIRedactor(hash_config)
        result = redactor.redact("user@example.com")
        assert "user@example.com" not in result.redacted_text
        # Should contain a 12-char hex token
        assert re.search(r"[0-9a-f]{12}", result.redacted_text)

    def test_hash_is_deterministic(self, hash_config: RedactionConfig) -> None:
        redactor = PIIRedactor(hash_config)
        r1 = redactor.redact("user@example.com")
        r2 = redactor.redact("user@example.com")
        assert r1.redacted_text == r2.redacted_text

    def test_different_values_hash_differently(self, hash_config: RedactionConfig) -> None:
        redactor = PIIRedactor(hash_config)
        r1 = redactor.redact("alice@corp.com")
        r2 = redactor.redact("bob@corp.com")
        assert r1.redacted_text != r2.redacted_text


# ---------------------------------------------------------------------------
# PIIRedactor.redact — remove strategy
# ---------------------------------------------------------------------------


class TestRedactRemoveStrategy:
    def test_email_removed(self, remove_config: RedactionConfig) -> None:
        redactor = PIIRedactor(remove_config)
        result = redactor.redact("Contact user@example.com now")
        assert "user@example.com" not in result.redacted_text
        # Removed — the gap is empty
        assert "Contact " in result.redacted_text

    def test_phone_removed(self, remove_config: RedactionConfig) -> None:
        redactor = PIIRedactor(remove_config)
        result = redactor.redact("Call 555-867-5309")
        assert "555-867-5309" not in result.redacted_text

    def test_remove_leaves_empty_where_pii_was(self, remove_config: RedactionConfig) -> None:
        redactor = PIIRedactor(remove_config)
        result = redactor.redact("AB")
        # "AB" has no PII; text unchanged
        assert result.redacted_text == "AB"


# ---------------------------------------------------------------------------
# PIIRedactor.redact — replace strategy
# ---------------------------------------------------------------------------


class TestRedactReplaceStrategy:
    def test_email_replaced_with_literal(self, replace_config: RedactionConfig) -> None:
        redactor = PIIRedactor(replace_config)
        result = redactor.redact("Email: user@example.com")
        assert "[REDACTED]" in result.redacted_text
        assert "user@example.com" not in result.redacted_text

    def test_custom_replacement_string(self) -> None:
        config = RedactionConfig(
            rules=[
                RedactionRule(
                    pii_type=PIIType.ssn,
                    strategy=RedactionStrategy.replace,
                    replacement="[SSN REDACTED]",
                )
            ],
            default_strategy=RedactionStrategy.mask,
        )
        redactor = PIIRedactor(config)
        result = redactor.redact("SSN: 123-45-6789")
        assert "[SSN REDACTED]" in result.redacted_text

    def test_replace_without_replacement_uses_default(self) -> None:
        config = RedactionConfig(
            rules=[
                RedactionRule(
                    pii_type=PIIType.email,
                    strategy=RedactionStrategy.replace,
                    replacement=None,
                )
            ]
        )
        redactor = PIIRedactor(config)
        result = redactor.redact("user@example.com")
        assert "[REDACTED]" in result.redacted_text


# ---------------------------------------------------------------------------
# PIIRedactor.redact — per-type rule overrides (mixed strategy)
# ---------------------------------------------------------------------------


class TestRedactMixedStrategies:
    def test_email_rule_overrides_default(self, mixed_redactor: PIIRedactor) -> None:
        result = mixed_redactor.redact("Email: user@example.com")
        # Email rule = mask
        assert "***" in result.redacted_text

    def test_phone_rule_is_remove(self, mixed_redactor: PIIRedactor) -> None:
        result = mixed_redactor.redact("Call 555-123-4567 now")
        assert "555-123-4567" not in result.redacted_text

    def test_ssn_rule_is_replace(self, mixed_redactor: PIIRedactor) -> None:
        result = mixed_redactor.redact("SSN: 123-45-6789")
        assert "[SSN]" in result.redacted_text

    def test_unknown_type_uses_default_strategy(self) -> None:
        """PIIType without an explicit rule falls back to default_strategy."""
        config = RedactionConfig(
            rules=[
                RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.hash)
            ],
            default_strategy=RedactionStrategy.remove,
        )
        redactor = PIIRedactor(config)
        # SSN has no rule — should use default (remove)
        result = redactor.redact("SSN: 123-45-6789")
        assert "123-45-6789" not in result.redacted_text


# ---------------------------------------------------------------------------
# PIIRedactor.redact — multiple PII in one string
# ---------------------------------------------------------------------------


class TestRedactMultiplePII:
    def test_all_instances_redacted(self, default_redactor: PIIRedactor, multi_pii_text: str) -> None:
        result = default_redactor.redact(multi_pii_text)
        assert "john.doe@example.com" not in result.redacted_text
        assert "555-123-4567" not in result.redacted_text
        assert "123-45-6789" not in result.redacted_text
        assert "10.0.0.1" not in result.redacted_text

    def test_redaction_count_matches_found(self, default_redactor: PIIRedactor, multi_pii_text: str) -> None:
        result = default_redactor.redact(multi_pii_text)
        assert result.redactions_applied == len(result.matches_found)

    def test_two_emails_both_redacted(self, default_redactor: PIIRedactor) -> None:
        text = "From: alice@corp.com, CC: bob@corp.com"
        result = default_redactor.redact(text)
        assert "alice@corp.com" not in result.redacted_text
        assert "bob@corp.com" not in result.redacted_text


# ---------------------------------------------------------------------------
# PIIRedactor.redact_dict
# ---------------------------------------------------------------------------


class TestRedactDict:
    def test_flat_dict_string_redacted(self, default_redactor: PIIRedactor) -> None:
        data = {"email": "user@example.com", "age": 30}
        result = default_redactor.redact_dict(data)
        assert isinstance(result, dict)
        assert "user@example.com" not in result["email"]
        assert result["age"] == 30  # non-string preserved

    def test_nested_dict_redacted(self, default_redactor: PIIRedactor) -> None:
        data = {
            "profile": {
                "contact": "alice@example.com",
                "score": 99,
            }
        }
        result = default_redactor.redact_dict(data)
        profile = result["profile"]
        assert isinstance(profile, dict)
        assert "alice@example.com" not in profile["contact"]
        assert profile["score"] == 99

    def test_list_values_redacted(self, default_redactor: PIIRedactor) -> None:
        data = {"notes": ["plain", "SSN: 123-45-6789", "also plain"]}
        result = default_redactor.redact_dict(data)
        notes = result["notes"]
        assert isinstance(notes, list)
        assert "123-45-6789" not in notes[1]
        assert notes[0] == "plain"
        assert notes[2] == "also plain"

    def test_original_dict_not_mutated(self, default_redactor: PIIRedactor) -> None:
        original = {"email": "user@example.com"}
        _ = default_redactor.redact_dict(original)
        assert original["email"] == "user@example.com"

    def test_empty_dict(self, default_redactor: PIIRedactor) -> None:
        assert default_redactor.redact_dict({}) == {}

    def test_non_string_scalar_passthrough(self, default_redactor: PIIRedactor) -> None:
        data = {"count": 42, "ratio": 3.14, "active": True, "nothing": None}
        result = default_redactor.redact_dict(data)
        assert result["count"] == 42
        assert result["ratio"] == 3.14
        assert result["active"] is True
        assert result["nothing"] is None

    def test_deeply_nested(self, default_redactor: PIIRedactor) -> None:
        data = {"a": {"b": {"c": {"d": "ip: 10.0.0.1"}}}}
        result = default_redactor.redact_dict(data)
        leaf = result["a"]["b"]["c"]["d"]  # type: ignore[index]
        assert "10.0.0.1" not in leaf


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestRedactEdgeCases:
    def test_only_whitespace(self, default_redactor: PIIRedactor) -> None:
        result = default_redactor.redact("   \t\n  ")
        assert result.redacted_text == "   \t\n  "
        assert result.redactions_applied == 0

    def test_pii_at_start_of_string(self, default_redactor: PIIRedactor) -> None:
        text = "user@example.com is our contact"
        result = default_redactor.redact(text)
        assert "user@example.com" not in result.redacted_text

    def test_pii_at_end_of_string(self, default_redactor: PIIRedactor) -> None:
        text = "Contact: user@example.com"
        result = default_redactor.redact(text)
        assert "user@example.com" not in result.redacted_text

    def test_pii_entire_string(self, default_redactor: PIIRedactor) -> None:
        text = "user@example.com"
        result = default_redactor.redact(text)
        assert result.redacted_text != text
        assert result.redactions_applied == 1

    def test_unicode_surroundings_preserved(self, default_redactor: PIIRedactor) -> None:
        text = "Kontakt: user@example.com — Danke"
        result = default_redactor.redact(text)
        assert "Kontakt:" in result.redacted_text
        assert "Danke" in result.redacted_text
        assert "user@example.com" not in result.redacted_text

    def test_newlines_in_text(self, default_redactor: PIIRedactor) -> None:
        text = "Line 1\nEmail: user@example.com\nLine 3"
        result = default_redactor.redact(text)
        assert "user@example.com" not in result.redacted_text
        assert "Line 1" in result.redacted_text
        assert "Line 3" in result.redacted_text
