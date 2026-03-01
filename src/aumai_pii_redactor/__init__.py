"""aumai-pii-redactor: PII detection and redaction for agent telemetry."""

from aumai_pii_redactor.async_core import AsyncPIIRedactor
from aumai_pii_redactor.detector import PIIDetector
from aumai_pii_redactor.integration import PIIRedactorIntegration, setup_pii_redactor
from aumai_pii_redactor.llm_detector import (
    LLMPIIDetectionResult,
    LLMPIIDetector,
    LLMPIIEntity,
    build_mock_detector,
)
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
from aumai_pii_redactor.store import RedactionRecord, RedactionStore

__version__ = "0.1.0"

__all__ = [
    # Async service
    "AsyncPIIRedactor",
    # Core
    "PIIDetector",
    "PIIMatch",
    "PIIRedactingSpanProcessor",
    "PIIRedactor",
    "PIIType",
    "RedactionConfig",
    "RedactionResult",
    "RedactionRule",
    "RedactionStrategy",
    # Store
    "RedactionRecord",
    "RedactionStore",
    # LLM detector
    "LLMPIIDetectionResult",
    "LLMPIIDetector",
    "LLMPIIEntity",
    "build_mock_detector",
    # Integration
    "PIIRedactorIntegration",
    "setup_pii_redactor",
]
