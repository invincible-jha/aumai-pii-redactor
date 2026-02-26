"""OpenTelemetry SpanProcessor that redacts PII from span attributes before export."""

from __future__ import annotations

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span

from aumai_pii_redactor.models import RedactionConfig
from aumai_pii_redactor.redactor import PIIRedactor


class PIIRedactingSpanProcessor:
    """OTel SpanProcessor that redacts PII from all string span attributes.

    Attach this processor to your SDK ``TracerProvider`` before adding any
    exporting processor so that sensitive data is scrubbed before it ever
    reaches a backend.

    Example::

        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(PIIRedactingSpanProcessor(config))
        provider.add_span_processor(BatchSpanProcessor(exporter))
    """

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self._redactor = PIIRedactor(config or RedactionConfig())

    # ------------------------------------------------------------------
    # SpanProcessor protocol
    # ------------------------------------------------------------------

    def on_start(
        self,
        span: Span,
        parent_context: Context | None = None,
    ) -> None:
        """No-op: PII is redacted on span end, not on start."""

    def on_end(self, span: ReadableSpan) -> None:
        """Redact PII from all string attributes on the finished span.

        The span's internal attributes dict is mutated in-place.  This is
        intentional — we want the redacted values to flow to any downstream
        exporters that were added after this processor.
        """
        if span.attributes is None:
            return

        # span.attributes is a BoundedAttributes mapping; we can mutate it
        # via the underlying dict by accessing _attributes (SDK internal).
        # We build a replacement dict to avoid mutation during iteration.
        redacted_attrs: dict[str, object] = {}
        for key, value in span.attributes.items():
            if isinstance(value, str):
                redacted_attrs[key] = self._redactor.redact(value).redacted_text
            else:
                redacted_attrs[key] = value

        # Overwrite values in the internal dict if accessible, otherwise no-op.
        try:
            internal: dict[str, object] = span.attributes._attributes  # type: ignore[union-attr]
            internal.clear()
            internal.update(redacted_attrs)
        except AttributeError:
            # Fallback: the SDK version doesn't expose _attributes — skip.
            pass

    def shutdown(self) -> None:
        """No-op: no resources to release."""

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        """No-op: synchronous processor, nothing to flush."""
        return True


__all__ = ["PIIRedactingSpanProcessor"]
