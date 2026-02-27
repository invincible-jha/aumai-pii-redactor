"""Tests for aumai_pii_redactor.detector — PII pattern matching."""

from __future__ import annotations

import re

import pytest

from aumai_pii_redactor.detector import PIIDetector, _flatten_dict, _luhn_valid
from aumai_pii_redactor.models import PIIMatch, PIIType, RedactionConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _types_detected(matches: list[PIIMatch]) -> set[PIIType]:
    return {m.pii_type for m in matches}


def _texts_detected(matches: list[PIIMatch]) -> list[str]:
    return [m.original_text for m in matches]


# ---------------------------------------------------------------------------
# _luhn_valid
# ---------------------------------------------------------------------------


class TestLuhnValid:
    def test_known_valid_visa(self) -> None:
        assert _luhn_valid("4111111111111111") is True

    def test_known_valid_mastercard(self) -> None:
        assert _luhn_valid("5500005555555559") is True

    def test_known_invalid(self) -> None:
        assert _luhn_valid("1234567890123456") is False

    def test_with_spaces(self) -> None:
        # Spaces are stripped, check passes
        assert _luhn_valid("4111 1111 1111 1111") is True

    def test_with_dashes(self) -> None:
        assert _luhn_valid("4111-1111-1111-1111") is True

    def test_too_short_returns_false(self) -> None:
        assert _luhn_valid("411111111111") is False  # 12 digits

    def test_single_digit_returns_false(self) -> None:
        assert _luhn_valid("5") is False

    def test_empty_string_returns_false(self) -> None:
        assert _luhn_valid("") is False


# ---------------------------------------------------------------------------
# _flatten_dict
# ---------------------------------------------------------------------------


class TestFlattenDict:
    def test_flat_dict(self) -> None:
        data = {"a": "hello", "b": 42}
        result = dict(_flatten_dict(data))
        assert result["a"] == "hello"
        assert result["b"] == 42

    def test_nested_dict(self) -> None:
        data = {"user": {"email": "x@y.com", "age": 30}}
        result = dict(_flatten_dict(data))
        assert result["user.email"] == "x@y.com"
        assert result["user.age"] == 30

    def test_list_values(self) -> None:
        data = {"tags": ["foo", "bar"]}
        result = dict(_flatten_dict(data))
        assert result["tags[0]"] == "foo"
        assert result["tags[1]"] == "bar"

    def test_deeply_nested(self) -> None:
        data = {"a": {"b": {"c": "deep"}}}
        result = dict(_flatten_dict(data))
        assert result["a.b.c"] == "deep"

    def test_mixed_list_and_dict(self) -> None:
        data = {"items": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}
        result = dict(_flatten_dict(data))
        assert result["items[0].name"] == "Alice"
        assert result["items[1].name"] == "Bob"

    def test_scalar_passthrough(self) -> None:
        result = list(_flatten_dict("just a string"))
        assert result == [("", "just a string")]

    def test_empty_dict(self) -> None:
        result = list(_flatten_dict({}))
        assert result == []

    def test_none_value(self) -> None:
        data = {"key": None}
        result = dict(_flatten_dict(data))
        assert result["key"] is None


# ---------------------------------------------------------------------------
# PIIDetector.detect — individual PII types
# ---------------------------------------------------------------------------


class TestDetectEmail:
    def test_simple_email(self, default_detector: PIIDetector, email_text: str) -> None:
        matches = default_detector.detect(email_text)
        assert any(m.pii_type == PIIType.email for m in matches)

    def test_email_original_text(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("Send to user@domain.org now")
        emails = [m for m in matches if m.pii_type == PIIType.email]
        assert emails
        assert emails[0].original_text == "user@domain.org"

    def test_email_high_confidence(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("x@y.io")
        emails = [m for m in matches if m.pii_type == PIIType.email]
        assert emails
        assert emails[0].confidence >= 0.95

    def test_email_case_insensitive(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("EMAIL: USER@EXAMPLE.COM")
        assert any(m.pii_type == PIIType.email for m in matches)

    def test_email_with_plus_addressing(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("alice+tag@sub.domain.co.uk")
        assert any(m.pii_type == PIIType.email for m in matches)

    def test_no_email_in_clean_text(self, default_detector: PIIDetector, clean_text: str) -> None:
        matches = default_detector.detect(clean_text)
        assert not any(m.pii_type == PIIType.email for m in matches)

    def test_span_indices_correct(self, default_detector: PIIDetector) -> None:
        text = "Contact: user@test.com today"
        matches = default_detector.detect(text)
        emails = [m for m in matches if m.pii_type == PIIType.email]
        assert emails
        m = emails[0]
        assert text[m.start : m.end] == m.original_text


class TestDetectPhone:
    def test_dashed_phone(self, default_detector: PIIDetector, phone_text: str) -> None:
        matches = default_detector.detect(phone_text)
        assert any(m.pii_type == PIIType.phone for m in matches)

    def test_dotted_phone(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("Call 555.867.5309 now")
        assert any(m.pii_type == PIIType.phone for m in matches)

    def test_parenthesised_area_code(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("Reach me at (800) 555-0100")
        assert any(m.pii_type == PIIType.phone for m in matches)

    def test_phone_with_country_code(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("+1-800-555-0100")
        assert any(m.pii_type == PIIType.phone for m in matches)

    def test_span_correct_for_phone(self, default_detector: PIIDetector) -> None:
        text = "Phone: 555-123-4567 end"
        matches = default_detector.detect(text)
        phones = [m for m in matches if m.pii_type == PIIType.phone]
        assert phones
        m = phones[0]
        assert text[m.start : m.end] == m.original_text


class TestDetectSSN:
    def test_standard_ssn(self, default_detector: PIIDetector, ssn_text: str) -> None:
        matches = default_detector.detect(ssn_text)
        assert any(m.pii_type == PIIType.ssn for m in matches)

    def test_ssn_without_dashes(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("SSN 123456789")
        assert any(m.pii_type == PIIType.ssn for m in matches)

    def test_ssn_with_spaces(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("SSN: 123 45 6789")
        assert any(m.pii_type == PIIType.ssn for m in matches)

    def test_ssn_high_confidence(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("123-45-6789")
        ssns = [m for m in matches if m.pii_type == PIIType.ssn]
        assert ssns
        assert ssns[0].confidence >= 0.90

    def test_ssn_span_correct(self, default_detector: PIIDetector) -> None:
        text = "Filed for 123-45-6789 today"
        matches = default_detector.detect(text)
        ssns = [m for m in matches if m.pii_type == PIIType.ssn]
        assert ssns
        m = ssns[0]
        assert text[m.start : m.end] == m.original_text


class TestDetectCreditCard:
    def test_luhn_valid_card_detected(self, default_detector: PIIDetector, credit_card_text: str) -> None:
        matches = default_detector.detect(credit_card_text)
        cards = [m for m in matches if m.pii_type == PIIType.credit_card]
        assert cards

    def test_valid_card_boosts_confidence(self, default_detector: PIIDetector) -> None:
        # 4111 1111 1111 1111 is Luhn-valid
        matches = default_detector.detect("4111 1111 1111 1111")
        cards = [m for m in matches if m.pii_type == PIIType.credit_card]
        assert cards
        assert cards[0].confidence >= 0.95  # 0.90 + 0.08 = 0.98

    def test_invalid_card_lowers_confidence(self, default_detector: PIIDetector) -> None:
        # 4111 1111 1111 1112 is Luhn-invalid
        matches = default_detector.detect("4111 1111 1111 1112")
        cards = [m for m in matches if m.pii_type == PIIType.credit_card]
        assert cards
        assert cards[0].confidence < 0.90

    def test_card_with_dashes(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("4111-1111-1111-1111")
        cards = [m for m in matches if m.pii_type == PIIType.credit_card]
        assert cards


class TestDetectIPAddress:
    def test_ipv4_detected(self, default_detector: PIIDetector, ipv4_text: str) -> None:
        matches = default_detector.detect(ipv4_text)
        assert any(m.pii_type == PIIType.ip_address for m in matches)

    def test_ipv6_detected(self, default_detector: PIIDetector, ipv6_text: str) -> None:
        matches = default_detector.detect(ipv6_text)
        assert any(m.pii_type == PIIType.ip_address for m in matches)

    def test_ipv4_original_text(self, default_detector: PIIDetector) -> None:
        text = "Origin: 10.20.30.40"
        matches = default_detector.detect(text)
        ips = [m for m in matches if m.pii_type == PIIType.ip_address]
        assert ips
        assert ips[0].original_text == "10.20.30.40"

    def test_invalid_ipv4_not_detected(self, default_detector: PIIDetector) -> None:
        # 999.x.x.x is outside valid octet range
        matches = default_detector.detect("address 999.0.0.1 listed")
        ips = [m for m in matches if m.pii_type == PIIType.ip_address]
        assert not ips


class TestDetectDateOfBirth:
    def test_slash_format(self, default_detector: PIIDetector, dob_text: str) -> None:
        matches = default_detector.detect(dob_text)
        assert any(m.pii_type == PIIType.date_of_birth for m in matches)

    def test_dash_format(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("Born on 06-30-2000.")
        assert any(m.pii_type == PIIType.date_of_birth for m in matches)

    def test_century_boundary_20xx(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("DOB: 12/31/2020")
        assert any(m.pii_type == PIIType.date_of_birth for m in matches)

    def test_century_boundary_19xx(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("DOB: 12/31/1985")
        assert any(m.pii_type == PIIType.date_of_birth for m in matches)


class TestDetectPassport:
    def test_us_format(self, default_detector: PIIDetector, passport_text: str) -> None:
        matches = default_detector.detect(passport_text)
        assert any(m.pii_type == PIIType.passport for m in matches)

    def test_single_letter_prefix(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("Passport: A12345678")
        assert any(m.pii_type == PIIType.passport for m in matches)

    def test_two_letter_prefix(self, default_detector: PIIDetector) -> None:
        matches = default_detector.detect("Travel doc XY123456789")
        assert any(m.pii_type == PIIType.passport for m in matches)


# ---------------------------------------------------------------------------
# PIIDetector.detect — ordering, deduplication, multi-PII
# ---------------------------------------------------------------------------


class TestDetectOrdering:
    def test_matches_sorted_by_start(self, default_detector: PIIDetector, multi_pii_text: str) -> None:
        matches = default_detector.detect(multi_pii_text)
        starts = [m.start for m in matches]
        assert starts == sorted(starts)

    def test_no_duplicate_spans(self, default_detector: PIIDetector) -> None:
        text = "user@example.com user@example.com"
        matches = default_detector.detect(text)
        spans = [(m.start, m.end) for m in matches]
        assert len(spans) == len(set(spans))


class TestDetectMultiPII:
    def test_multiple_types_in_single_string(
        self, default_detector: PIIDetector, multi_pii_text: str
    ) -> None:
        matches = default_detector.detect(multi_pii_text)
        detected_types = _types_detected(matches)
        # Email, phone, SSN, ip_address, and DOB should all appear
        assert PIIType.email in detected_types
        assert PIIType.phone in detected_types
        assert PIIType.ssn in detected_types
        assert PIIType.ip_address in detected_types

    def test_clean_text_returns_empty(
        self, default_detector: PIIDetector, clean_text: str
    ) -> None:
        matches = default_detector.detect(clean_text)
        assert matches == []

    def test_empty_string_returns_empty(self, default_detector: PIIDetector) -> None:
        assert default_detector.detect("") == []


# ---------------------------------------------------------------------------
# PIIDetector.detect_in_dict
# ---------------------------------------------------------------------------


class TestDetectInDict:
    def test_flat_dict_with_pii(self, default_detector: PIIDetector) -> None:
        data = {
            "user_email": "alice@corp.com",
            "age": 30,
            "note": "No PII here",
        }
        result = default_detector.detect_in_dict(data)
        assert "user_email" in result
        assert "age" not in result  # integer — no PII
        assert "note" not in result

    def test_nested_dict_pii(self, default_detector: PIIDetector) -> None:
        data = {
            "profile": {
                "contact": {"email": "bob@example.com", "phone": "555-000-1111"},
            }
        }
        result = default_detector.detect_in_dict(data)
        assert "profile.contact.email" in result
        assert "profile.contact.phone" in result

    def test_list_of_strings(self, default_detector: PIIDetector) -> None:
        data = {"notes": ["plain text", "call 800-555-0199 now"]}
        result = default_detector.detect_in_dict(data)
        assert "notes[1]" in result
        assert "notes[0]" not in result

    def test_empty_dict(self, default_detector: PIIDetector) -> None:
        assert default_detector.detect_in_dict({}) == {}

    def test_non_string_values_ignored(self, default_detector: PIIDetector) -> None:
        data = {"count": 42, "ratio": 3.14, "active": True}
        result = default_detector.detect_in_dict(data)
        assert result == {}

    def test_returns_correct_match_objects(self, default_detector: PIIDetector) -> None:
        data = {"field": "ip is 192.168.0.1"}
        result = default_detector.detect_in_dict(data)
        assert "field" in result
        matches = result["field"]
        assert all(isinstance(m, PIIMatch) for m in matches)
        assert any(m.pii_type == PIIType.ip_address for m in matches)


# ---------------------------------------------------------------------------
# Custom patterns
# ---------------------------------------------------------------------------


class TestCustomPatterns:
    def test_custom_pattern_detected(self, custom_pattern_config: RedactionConfig) -> None:
        detector = PIIDetector(custom_pattern_config)
        matches = detector.detect("Employee EMP-123456 submitted form.")
        assert any(m.pii_type == PIIType.custom for m in matches)

    def test_custom_pattern_original_text(self, custom_pattern_config: RedactionConfig) -> None:
        detector = PIIDetector(custom_pattern_config)
        matches = detector.detect("ID: EMP-654321")
        customs = [m for m in matches if m.pii_type == PIIType.custom]
        assert customs
        assert customs[0].original_text == "EMP-654321"

    def test_custom_pattern_confidence(self, custom_pattern_config: RedactionConfig) -> None:
        detector = PIIDetector(custom_pattern_config)
        matches = detector.detect("EMP-999999")
        customs = [m for m in matches if m.pii_type == PIIType.custom]
        assert customs
        assert customs[0].confidence == 0.80

    def test_invalid_regex_raises_on_init(self) -> None:
        config = RedactionConfig(custom_patterns={"bad": r"[unclosed"})
        with pytest.raises(re.error):
            PIIDetector(config)

    def test_multiple_custom_patterns(self) -> None:
        config = RedactionConfig(
            custom_patterns={
                "order": r"\bORD-\d{6}\b",
                "invoice": r"\bINV-\d{5}\b",
            }
        )
        detector = PIIDetector(config)
        matches = detector.detect("Order ORD-100200 Invoice INV-55555")
        custom_texts = {m.original_text for m in matches if m.pii_type == PIIType.custom}
        assert "ORD-100200" in custom_texts
        assert "INV-55555" in custom_texts

    def test_duplicate_span_deduplicated(self) -> None:
        """A custom pattern matching the same span as a built-in produces only one match.

        This exercises the seen_spans deduplication (continue branch) in detect().
        The built-in email pattern uses a word-boundary (\b) prefix; a custom
        pattern without boundaries matches the identical span.  The first match
        (email, from the built-in list which runs first) wins and the duplicate
        from the custom pattern is silently dropped.
        """
        config = RedactionConfig(
            # Pattern deliberately matches the same text span as the built-in email pattern
            custom_patterns={
                "email_alias": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
            }
        )
        detector = PIIDetector(config)
        matches = detector.detect("user@example.com")
        # Only one match even though two patterns fired on the same span
        assert len(matches) == 1
        # The built-in email match wins (it runs first)
        assert matches[0].pii_type == PIIType.email
