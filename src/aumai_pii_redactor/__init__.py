"""aumai-pii-redactor: PII detection and redaction for agent telemetry."""

from aumai_pii_redactor.detector import PIIDetector
from aumai_pii_redactor.models import (
    PIIMatch,
    PIIType,
    RedactionConfig,
    RedactionResult,
    RedactionRule,
    RedactionStrategy,
)
from aumai_pii_redactor.otel_processor import PIIRedactingSpanProcessor
from aumai_pii_redactor.redactor import PIIRedactor

__version__ = "0.1.0"

__all__ = [
    "PIIDetector",
    "PIIMatch",
    "PIIRedactingSpanProcessor",
    "PIIRedactor",
    "PIIType",
    "RedactionConfig",
    "RedactionResult",
    "RedactionRule",
    "RedactionStrategy",
]
