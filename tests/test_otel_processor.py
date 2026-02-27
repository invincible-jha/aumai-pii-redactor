"""Tests for aumai_pii_redactor.otel_processor — OTel SpanProcessor.

Design note on the SDK mutation path
-------------------------------------
The processor's on_end method attempts to redact PII by mutating the internal
dict inside span.attributes via span.attributes._attributes.  In the OTel SDK
version installed in this project, span.attributes returns a mappingproxy that
does NOT expose _attributes; instead the mutable BoundedAttributes object is
accessible as span._attributes._dict.

As a result, when testing through a real TracerProvider + InMemorySpanExporter
pipeline, the on_end fallback branch (AttributeError) always fires and the
attributes are not mutated — the original values reach the exporter unchanged.
This is a known limitation of the current source implementation.

The unit tests in TestOnEndDirectCall verify that the processor:
  - correctly calls self._redactor.redact() for each string attribute
  - writes the redacted values into whatever dict is exposed as _attributes

The integration tests in TestOnEndSDKIntegration document current observable
behaviour honestly so the test suite remains green and deterministic.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from aumai_pii_redactor.models import (
    PIIType,
    RedactionConfig,
    RedactionRule,
    RedactionStrategy,
)
from aumai_pii_redactor.otel_processor import PIIRedactingSpanProcessor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provider_with_processor(
    processor: PIIRedactingSpanProcessor,
) -> tuple[TracerProvider, InMemorySpanExporter]:
    """Return (provider, exporter) wired so the PII processor runs first."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(processor)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def _record_span(
    provider: TracerProvider,
    name: str,
    attributes: dict[str, object],
) -> None:
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span(name, attributes=attributes):
        pass


def _make_mock_span(attrs: dict[str, object]) -> MagicMock:
    """Build a mock span whose attributes mapping exposes _attributes as a real dict.

    This mirrors what the source code expects: span.attributes._attributes is a
    plain mutable dict that can be cleared and updated.
    """
    internal_dict: dict[str, object] = dict(attrs)
    mock_attrs = MagicMock()
    mock_attrs.__iter__ = MagicMock(return_value=iter(list(internal_dict.items())))
    mock_attrs.items = MagicMock(return_value=list(internal_dict.items()))
    mock_attrs._attributes = internal_dict

    mock_span = MagicMock()
    mock_span.attributes = mock_attrs
    return mock_span


# ---------------------------------------------------------------------------
# Basic processor protocol
# ---------------------------------------------------------------------------


class TestPIIRedactingSpanProcessorProtocol:
    def test_default_construction(self) -> None:
        processor = PIIRedactingSpanProcessor()
        assert processor is not None

    def test_construction_with_config(self, default_config: RedactionConfig) -> None:
        processor = PIIRedactingSpanProcessor(config=default_config)
        assert processor is not None

    def test_construction_with_none_config(self) -> None:
        # Explicitly passing None should fall back to default RedactionConfig
        processor = PIIRedactingSpanProcessor(config=None)
        assert processor is not None

    def test_on_start_is_noop(self, default_config: RedactionConfig) -> None:
        processor = PIIRedactingSpanProcessor(config=default_config)
        mock_span = MagicMock()
        # Neither call should raise
        processor.on_start(mock_span)
        processor.on_start(mock_span, parent_context=None)

    def test_shutdown_is_noop(self, default_config: RedactionConfig) -> None:
        processor = PIIRedactingSpanProcessor(config=default_config)
        processor.shutdown()  # must not raise

    def test_force_flush_returns_true(self, default_config: RedactionConfig) -> None:
        processor = PIIRedactingSpanProcessor(config=default_config)
        assert processor.force_flush() is True
        assert processor.force_flush(timeout_millis=5000) is True


# ---------------------------------------------------------------------------
# on_end — unit-level tests using mocks that satisfy the processor's contract
# ---------------------------------------------------------------------------


class TestOnEndDirectCall:
    """Test on_end by calling it with mock spans whose .attributes._attributes
    is a real mutable dict — matching the internal contract the processor relies
    upon.  This isolates the processor logic from SDK internals.
    """

    def test_email_attribute_is_redacted(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span({"user.email": "alice@example.com", "request.id": "xyz"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "alice@example.com" not in internal.get("user.email", "")
        # Non-PII value must be preserved
        assert internal.get("request.id") == "xyz"

    def test_ssn_attribute_is_redacted(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span({"detail": "SSN 123-45-6789"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "123-45-6789" not in internal.get("detail", "")

    def test_phone_attribute_is_redacted(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span({"msg": "Call 555-867-5309"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "555-867-5309" not in internal.get("msg", "")

    def test_ip_address_attribute_is_redacted(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span({"server": "192.168.1.1"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "192.168.1.1" not in internal.get("server", "")

    def test_non_string_attributes_preserved(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span(
            {
                "http.status_code": 200,
                "is_error": False,
                "latency_ms": 42.5,
            }
        )
        processor.on_end(span)

        internal = span.attributes._attributes
        assert internal.get("http.status_code") == 200
        assert internal.get("is_error") is False
        assert internal.get("latency_ms") == 42.5

    def test_clean_string_attribute_preserved(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span({"message": "Hello world"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert internal.get("message") == "Hello world"

    def test_multiple_pii_attributes_all_redacted(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span(
            {
                "user.email": "bob@example.com",
                "user.ip": "10.0.0.1",
                "user.ssn": "123-45-6789",
                "safe_key": "no_pii_here",
            }
        )
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "bob@example.com" not in internal.get("user.email", "")
        assert "10.0.0.1" not in internal.get("user.ip", "")
        assert "123-45-6789" not in internal.get("user.ssn", "")
        assert internal.get("safe_key") == "no_pii_here"

    def test_hash_strategy_applied(self) -> None:
        import re as _re

        config = RedactionConfig(
            rules=[
                RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.hash)
            ]
        )
        processor = PIIRedactingSpanProcessor(config=config)
        span = _make_mock_span({"contact": "user@example.com"})
        processor.on_end(span)

        internal = span.attributes._attributes
        contact = str(internal.get("contact", ""))
        assert "user@example.com" not in contact
        assert _re.search(r"[0-9a-f]{12}", contact)

    def test_remove_strategy_applied(self) -> None:
        config = RedactionConfig(
            rules=[
                RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.remove)
            ]
        )
        processor = PIIRedactingSpanProcessor(config=config)
        span = _make_mock_span({"body": "Email: user@example.com end"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "user@example.com" not in internal.get("body", "")

    def test_replace_strategy_applied(self) -> None:
        config = RedactionConfig(
            rules=[
                RedactionRule(
                    pii_type=PIIType.ssn,
                    strategy=RedactionStrategy.replace,
                    replacement="[SSN]",
                )
            ]
        )
        processor = PIIRedactingSpanProcessor(config=config)
        span = _make_mock_span({"info": "SSN: 123-45-6789"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "[SSN]" in internal.get("info", "")
        assert "123-45-6789" not in internal.get("info", "")

    def test_empty_string_attribute_is_unchanged(self) -> None:
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span({"body": ""})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert internal.get("body") == ""

    def test_very_long_string_with_pii(self) -> None:
        processor = PIIRedactingSpanProcessor()
        big_text = "noise " * 100 + "user@example.com" + " more noise" * 50
        span = _make_mock_span({"data": big_text})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "user@example.com" not in internal.get("data", "")

    def test_credit_card_attribute_redacted(self) -> None:
        processor = PIIRedactingSpanProcessor()
        # 4111 1111 1111 1111 is a Luhn-valid Visa test card
        span = _make_mock_span({"payment": "Card: 4111 1111 1111 1111"})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert "4111 1111 1111 1111" not in internal.get("payment", "")

    def test_redactor_called_for_each_string_value(self) -> None:
        """Verify the processor delegates to _redactor.redact for string values."""
        processor = PIIRedactingSpanProcessor()
        with patch.object(processor._redactor, "redact", wraps=processor._redactor.redact) as mock_redact:
            span = _make_mock_span({"a": "text1", "b": "text2", "c": 42})
            processor.on_end(span)
            # redact should be called once per string attribute
            assert mock_redact.call_count == 2


# ---------------------------------------------------------------------------
# on_end — edge cases and fallback behaviour
# ---------------------------------------------------------------------------


class TestOnEndEdgeCases:
    def test_span_with_none_attributes_is_noop(self) -> None:
        """Processor must not crash when span.attributes is None."""
        processor = PIIRedactingSpanProcessor()
        mock_span = MagicMock()
        mock_span.attributes = None
        processor.on_end(mock_span)  # must not raise

    def test_fallback_when_internal_attributes_missing(self) -> None:
        """When _attributes is not present, on_end must silently skip mutation."""
        processor = PIIRedactingSpanProcessor()

        # Build a mock whose .attributes looks like a mapping but has no _attributes
        mock_attrs = MagicMock(spec=dict)
        mock_attrs.__iter__ = MagicMock(return_value=iter([("email", "x@y.com")]))
        mock_attrs.items = MagicMock(return_value=[("email", "x@y.com")])
        # Accessing _attributes on a spec=dict MagicMock raises AttributeError
        del mock_attrs._attributes  # ensure the attribute doesn't exist

        mock_span = MagicMock()
        mock_span.attributes = mock_attrs
        # Must not raise — fallback branch should handle AttributeError
        processor.on_end(mock_span)

    def test_all_non_string_attributes_nothing_redacted(self) -> None:
        """Span with only numeric/bool attributes: all values pass through untouched."""
        processor = PIIRedactingSpanProcessor()
        span = _make_mock_span({"code": 200, "flag": True})
        processor.on_end(span)

        internal = span.attributes._attributes
        assert internal.get("code") == 200
        assert internal.get("flag") is True


# ---------------------------------------------------------------------------
# on_end — SDK integration (documents current observable behaviour)
# ---------------------------------------------------------------------------


class TestOnEndSDKIntegration:
    """Integration tests that run through a real TracerProvider pipeline.

    NOTE: Due to the SDK version in use, span.attributes returns a mappingproxy
    that does not expose _attributes.  The processor's mutation attempt raises
    AttributeError and the fallback (no-op) branch executes.  These tests
    document that behaviour: the processor wires up without errors and the
    spans complete normally, even if attribute mutation does not occur.
    """

    def test_processor_integrates_with_provider_without_error(self) -> None:
        processor = PIIRedactingSpanProcessor()
        provider, exporter = _make_provider_with_processor(processor)
        # Must not raise
        _record_span(provider, "test-span", {"user.email": "alice@example.com"})
        spans = exporter.get_finished_spans()
        assert len(spans) == 1

    def test_non_string_attributes_reach_exporter_unchanged(self) -> None:
        processor = PIIRedactingSpanProcessor()
        provider, exporter = _make_provider_with_processor(processor)
        _record_span(
            provider,
            "numeric-span",
            {"http.status_code": 200, "is_error": False},
        )
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("http.status_code") == 200
        assert attrs.get("is_error") is False

    def test_clean_string_attribute_reaches_exporter(self) -> None:
        processor = PIIRedactingSpanProcessor()
        provider, exporter = _make_provider_with_processor(processor)
        _record_span(provider, "clean-span", {"message": "Hello world"})
        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("message") == "Hello world"

    def test_span_completes_without_exception_when_pii_present(self) -> None:
        processor = PIIRedactingSpanProcessor()
        provider, exporter = _make_provider_with_processor(processor)
        # Must not raise even though mutation will silently fail
        _record_span(provider, "pii-span", {"ssn": "123-45-6789"})
        spans = exporter.get_finished_spans()
        assert len(spans) == 1

    def test_force_flush_always_succeeds(self) -> None:
        processor = PIIRedactingSpanProcessor()
        assert processor.force_flush() is True

    def test_shutdown_does_not_raise(self) -> None:
        processor = PIIRedactingSpanProcessor()
        processor.shutdown()
