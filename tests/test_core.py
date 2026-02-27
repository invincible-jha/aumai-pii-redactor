"""Tests for aumai_pii_redactor.core — re-export convenience module."""

from __future__ import annotations

from aumai_pii_redactor.core import PIIDetector, PIIRedactor
from aumai_pii_redactor.detector import PIIDetector as _DetectorDirect
from aumai_pii_redactor.redactor import PIIRedactor as _RedactorDirect


class TestCoreReExports:
    def test_pii_detector_is_same_class(self) -> None:
        assert PIIDetector is _DetectorDirect

    def test_pii_redactor_is_same_class(self) -> None:
        assert PIIRedactor is _RedactorDirect

    def test_detector_instantiable_from_core(self) -> None:
        from aumai_pii_redactor.models import RedactionConfig

        detector = PIIDetector(RedactionConfig())
        matches = detector.detect("user@example.com")
        assert matches

    def test_redactor_instantiable_from_core(self) -> None:
        from aumai_pii_redactor.models import RedactionConfig

        redactor = PIIRedactor(RedactionConfig())
        result = redactor.redact("user@example.com")
        assert result.redactions_applied >= 1
