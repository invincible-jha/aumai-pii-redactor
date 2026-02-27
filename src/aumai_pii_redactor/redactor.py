"""PII redaction engine — applies configured strategies to detected PII spans."""

from __future__ import annotations

import hashlib

from aumai_pii_redactor.detector import PIIDetector
from aumai_pii_redactor.models import (
    PIIType,
    RedactionConfig,
    RedactionResult,
    RedactionRule,
    RedactionStrategy,
)

# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------

def _apply_mask(text: str) -> str:
    """Keep the first and last characters; fill the middle with ***."""
    if len(text) <= 2:  # noqa: PLR2004
        return "*" * len(text)
    return text[0] + "***" + text[-1]


def _apply_hash(text: str) -> str:
    """Return the first 12 hex chars of the SHA-256 digest of *text*."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest[:12]


def _apply_remove(_text: str) -> str:
    return ""


def _apply_replace(text: str, replacement: str | None) -> str:  # noqa: ARG001
    return replacement if replacement is not None else "[REDACTED]"


def _apply_strategy(
    original: str,
    strategy: RedactionStrategy,
    replacement: str | None,
) -> str:
    if strategy == RedactionStrategy.mask:
        return _apply_mask(original)
    if strategy == RedactionStrategy.hash:
        return _apply_hash(original)
    if strategy == RedactionStrategy.remove:
        return _apply_remove(original)
    # replace
    return _apply_replace(original, replacement)


# ---------------------------------------------------------------------------
# PIIRedactor
# ---------------------------------------------------------------------------

class PIIRedactor:
    """Detect and redact PII from text or nested dicts using configured rules."""

    def __init__(self, config: RedactionConfig) -> None:
        self._config = config
        self._detector = PIIDetector(config)
        # Build a quick lookup from PIIType -> RedactionRule
        self._rule_map: dict[PIIType, RedactionRule] = {
            rule.pii_type: rule for rule in config.rules
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact(self, text: str) -> RedactionResult:
        """Detect and redact all PII in *text*.

        Overlapping spans are handled by processing matches in reverse order so
        character positions remain valid throughout the replacement loop.
        """
        matches = self._detector.detect(text)
        if not matches:
            return RedactionResult(
                original_length=len(text),
                redacted_text=text,
                matches_found=[],
                redactions_applied=0,
            )

        # Process in reverse to preserve forward indices
        redacted = text
        applied = 0
        for match in reversed(matches):
            strategy, replacement = self._resolve_strategy(match.pii_type)
            substitution = _apply_strategy(match.original_text, strategy, replacement)
            redacted = redacted[: match.start] + substitution + redacted[match.end :]
            applied += 1

        return RedactionResult(
            original_length=len(text),
            redacted_text=redacted,
            matches_found=matches,
            redactions_applied=applied,
        )

    def redact_dict(self, data: dict[str, object]) -> dict[str, object]:
        """Recursively redact all string values in *data*.

        Non-string leaf values are left unchanged.  The input dict is not
        mutated; a deep copy with redacted strings is returned.
        """
        return self._redact_value(data)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_strategy(
        self, pii_type: PIIType
    ) -> tuple[RedactionStrategy, str | None]:
        rule = self._rule_map.get(pii_type)
        if rule:
            return rule.strategy, rule.replacement
        return self._config.default_strategy, None

    def _redact_value(self, value: object) -> object:
        if isinstance(value, str):
            return self.redact(value).redacted_text
        if isinstance(value, dict):
            return {k: self._redact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        return value


__all__ = ["PIIRedactor"]
