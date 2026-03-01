"""Async API for aumai-pii-redactor using aumai-async-core foundation library.

Provides AsyncPIIRedactor — a lifecycle-managed async service that wraps the
synchronous PIIRedactor and PIIDetector with event emission, concurrency
control, and health checks.
"""

from __future__ import annotations

import asyncio
from typing import Any

from aumai_async_core import AsyncEventEmitter, AsyncService, AsyncServiceConfig

from aumai_pii_redactor.detector import PIIDetector
from aumai_pii_redactor.models import (
    PIIMatch,
    RedactionConfig,
    RedactionResult,
)
from aumai_pii_redactor.redactor import PIIRedactor


class AsyncPIIRedactor(AsyncService):
    """Lifecycle-managed async service for PII detection and redaction.

    Wraps the synchronous :class:`~aumai_pii_redactor.redactor.PIIRedactor`
    and :class:`~aumai_pii_redactor.detector.PIIDetector` with async-first
    ergonomics, event emission on PII operations, and the full
    :class:`~aumai_async_core.core.AsyncService` lifecycle (start/stop,
    health checks, concurrency limits).

    Events emitted:
        - ``pii.detected``: fired after detection completes.  Payload keys:
          ``match_count``, ``pii_types``, ``text_length``.
        - ``pii.redacted``: fired after redaction completes.  Payload keys:
          ``redactions_applied``, ``original_length``, ``redacted_length``.
        - ``scan.completed``: fired after a full redact pass.  Payload keys:
          ``redactions_applied``, ``safe`` (True when no PII found).

    Example::

        config = AsyncServiceConfig(name="pii-redactor")
        service = AsyncPIIRedactor(config)
        await service.start()

        result = await service.redact("Email me at alice@example.com")

        @service.emitter.on_event("pii.detected")
        async def handle_detected(match_count: int, **kw: Any) -> None:
            print(f"Detected {match_count} PII span(s)")

        await service.stop()
    """

    def __init__(
        self,
        config: AsyncServiceConfig | None = None,
        *,
        redaction_config: RedactionConfig | None = None,
        run_in_executor: bool = True,
    ) -> None:
        """Initialise the async PII redactor service.

        Args:
            config: Service configuration.  Defaults to a sensible config
                with ``name="pii-redactor"``.
            redaction_config: PII redaction configuration controlling which
                types are detected and how they are redacted.  Defaults to
                :class:`~aumai_pii_redactor.models.RedactionConfig` with
                built-in patterns and mask strategy.
            run_in_executor: When ``True`` (the default), CPU-bound regex
                work runs in the default thread executor to avoid blocking the
                event loop.  Set to ``False`` in tests to keep execution
                synchronous.
        """
        effective_config = config or AsyncServiceConfig(
            name="pii-redactor",
            health_check_interval_seconds=0.0,
        )
        super().__init__(effective_config)
        self._redaction_config: RedactionConfig = redaction_config or RedactionConfig()
        self._redactor: PIIRedactor = PIIRedactor(self._redaction_config)
        self._detector: PIIDetector = PIIDetector(self._redaction_config)
        self._emitter: AsyncEventEmitter = AsyncEventEmitter()
        self._run_in_executor = run_in_executor

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def emitter(self) -> AsyncEventEmitter:
        """The :class:`~aumai_async_core.events.AsyncEventEmitter` for this service.

        Register handlers here to receive ``pii.detected``, ``pii.redacted``,
        and ``scan.completed`` events.
        """
        return self._emitter

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    async def on_start(self) -> None:
        """Re-initialise the underlying redactor/detector on service start."""
        self._redactor = PIIRedactor(self._redaction_config)
        self._detector = PIIDetector(self._redaction_config)

    async def on_stop(self) -> None:
        """Remove all event listeners on service shutdown."""
        self._emitter.remove_all_listeners()

    async def health_check(self) -> bool:
        """Return ``True`` when the underlying redactor is operational.

        A trivial probe — redact a known-clean string and assert no error.
        """
        probe = "health check probe text"
        try:
            result = self._redactor.redact(probe)
            return result.redacted_text == probe
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Core async API
    # ------------------------------------------------------------------

    async def detect(self, text: str) -> list[PIIMatch]:
        """Detect PII in *text* asynchronously.

        Dispatches the CPU-bound regex work to a thread executor.  Emits a
        ``pii.detected`` event with match metadata after completion.

        Args:
            text: The string to scan for PII.

        Returns:
            List of :class:`~aumai_pii_redactor.models.PIIMatch` instances,
            ordered by position within *text*.
        """
        await self.increment_request_count()

        try:
            if self._run_in_executor:
                loop = asyncio.get_running_loop()
                matches: list[PIIMatch] = await loop.run_in_executor(
                    None, self._detector.detect, text
                )
            else:
                matches = self._detector.detect(text)
        except Exception:
            await self.increment_error_count()
            raise

        pii_types = list({m.pii_type.value for m in matches})
        await self._emitter.emit(
            "pii.detected",
            match_count=len(matches),
            pii_types=pii_types,
            text_length=len(text),
        )

        return matches

    async def redact(
        self,
        text: str,
        *,
        context: str = "unknown",
    ) -> RedactionResult:
        """Detect and redact all PII in *text* asynchronously.

        The CPU-bound scanning and redaction work is dispatched to a thread
        executor so the event loop remains unblocked.  Events are emitted for
        detection and redaction after the pass completes.

        Args:
            text: The string to redact.
            context: Optional human-readable label for the source of this
                text (e.g. ``"span.attribute"``).  Used for logging/events.

        Returns:
            A :class:`~aumai_pii_redactor.models.RedactionResult` with the
            redacted text and metadata about matches and replacements.
        """
        await self.increment_request_count()

        try:
            if self._run_in_executor:
                loop = asyncio.get_running_loop()
                result: RedactionResult = await loop.run_in_executor(
                    None, self._redactor.redact, text
                )
            else:
                result = self._redactor.redact(text)
        except Exception:
            await self.increment_error_count()
            raise

        pii_types = list({m.pii_type.value for m in result.matches_found})

        await self._emitter.emit(
            "pii.detected",
            match_count=len(result.matches_found),
            pii_types=pii_types,
            text_length=result.original_length,
        )

        await self._emitter.emit(
            "pii.redacted",
            redactions_applied=result.redactions_applied,
            original_length=result.original_length,
            redacted_length=len(result.redacted_text),
        )

        await self._emitter.emit(
            "scan.completed",
            redactions_applied=result.redactions_applied,
            safe=result.redactions_applied == 0,
            context=context,
        )

        return result

    async def redact_dict(
        self,
        data: dict[str, object],
    ) -> dict[str, object]:
        """Recursively redact all string values in *data* asynchronously.

        Dispatches to a thread executor and emits ``scan.completed`` when done.

        Args:
            data: Nested dictionary whose string leaf values will be redacted.

        Returns:
            A deep copy of *data* with all string values redacted.
        """
        await self.increment_request_count()

        try:
            if self._run_in_executor:
                loop = asyncio.get_running_loop()
                redacted: dict[str, object] = await loop.run_in_executor(
                    None, self._redactor.redact_dict, data
                )
            else:
                redacted = self._redactor.redact_dict(data)
        except Exception:
            await self.increment_error_count()
            raise

        await self._emitter.emit(
            "scan.completed",
            redactions_applied=-1,  # unknown total for dict ops
            safe=True,
            context="dict",
        )

        return redacted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _emit_pii_match(self, match: PIIMatch) -> None:
        """Emit a ``pii.detected`` event for a single match."""
        await self._emitter.emit(
            "pii.detected",
            match_count=1,
            pii_types=[match.pii_type.value],
            text_length=len(match.original_text),
        )


__all__ = ["AsyncPIIRedactor"]
