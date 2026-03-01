"""Persistence layer for aumai-pii-redactor using aumai-store foundation library.

Provides RedactionStore — a repository-backed persistence service for redaction
audit records — and RedactionRecord, the Pydantic model persisted to SQLite
(or an in-memory backend during tests).
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime
from typing import Any

from aumai_store import Repository, Store, StoreConfig
from pydantic import BaseModel, Field, model_validator

from aumai_pii_redactor.models import PIIType, RedactionResult


class RedactionRecord(BaseModel):
    """Persisted representation of a single redaction operation.

    Attributes:
        id: Unique identifier for this audit record (UUID v4 string).
        context: Human-readable label for the source of the redacted text
            (e.g. ``"span.attribute"``, ``"user-message"``).
        operator: Identifier of the caller who triggered this redaction
            (e.g. user ID, service name).  Defaults to ``"system"``.
        timestamp: UTC datetime string (ISO-8601) when the redaction was
            performed.
        redactions_applied: Number of PII spans that were redacted.
        pii_types_found: JSON-serialised list of PII type strings detected.
            When read back from the store the backend may deserialise the JSON
            string into a Python list; the validator re-serialises it to ensure
            this field is always a string.
        result_json: Full JSON-serialised
            :class:`~aumai_pii_redactor.models.RedactionResult`.
            Same re-serialisation guard applies.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    context: str = Field(default="unknown")
    operator: str = Field(default="system")
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    redactions_applied: int = Field(default=0, ge=0)
    pii_types_found: str = Field(default="[]")
    result_json: str = Field(default="{}")

    @model_validator(mode="before")
    @classmethod
    def _coerce_json_fields(cls, values: Any) -> Any:
        """Re-serialise JSON fields when the store returns them as Python objects.

        The aumai-store memory backend parses any JSON-string value that starts
        with ``{`` or ``[`` back into a Python object before handing it to
        Pydantic.  This validator ensures ``pii_types_found`` and
        ``result_json`` are always ``str`` regardless of the round-trip.
        """
        if isinstance(values, dict):
            for field_name in ("pii_types_found", "result_json"):
                raw = values.get(field_name)
                if raw is not None and not isinstance(raw, str):
                    values[field_name] = json.dumps(raw)
        return values


class RedactionStore:
    """Repository-backed store for redaction audit records.

    Wraps a :class:`~aumai_store.core.Store` and exposes domain-specific
    query methods for redaction history and PII type breakdown metrics.

    Use :meth:`memory` to create an in-memory instance suitable for unit
    tests.  For production, pass a :class:`~aumai_store.models.StoreConfig`
    pointing at a SQLite (or Postgres) database.

    Example::

        async with RedactionStore.memory() as store:
            record = await store.save_result(
                "user-message", result, operator="alice"
            )
            history = await store.get_by_context("user-message")
            metrics = await store.get_metrics()
    """

    def __init__(self, store: Store) -> None:
        """Initialise using an existing :class:`~aumai_store.core.Store`.

        Args:
            store: A configured (but not yet necessarily initialised) store.
        """
        self._store: Store = store
        self._repo: Repository[RedactionRecord] | None = None

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def memory(cls) -> "RedactionStore":
        """Create an in-memory RedactionStore for testing.

        Returns:
            A :class:`RedactionStore` backed by
            :class:`~aumai_store.backends.MemoryBackend`.
        """
        return cls(Store.memory())

    @classmethod
    def sqlite(
        cls,
        database_url: str = "sqlite:///aumai_pii_redactor.db",
    ) -> "RedactionStore":
        """Create a SQLite-backed RedactionStore.

        Args:
            database_url: SQLite connection URL, e.g.
                ``"sqlite:///redactions.db"``.

        Returns:
            A :class:`RedactionStore` backed by
            :class:`~aumai_store.backends.SQLiteBackend`.
        """
        config = StoreConfig(backend="sqlite", database_url=database_url)
        return cls(Store(config))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Open the backend connection and ensure the redaction table exists.

        Must be called before any data operations.  Idempotent — safe to call
        multiple times.
        """
        await self._store.initialize()
        repo: Repository[RedactionRecord] = self._store.repository(
            RedactionRecord
        )
        await repo.ensure_table()
        self._repo = repo

    async def close(self) -> None:
        """Close the underlying store connection."""
        if hasattr(self._store, "close"):
            await self._store.close()  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "RedactionStore":
        await self.initialize()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    async def save_result(
        self,
        context: str,
        result: RedactionResult,
        *,
        operator: str = "system",
    ) -> RedactionRecord:
        """Persist a redaction result and return the saved audit record.

        Args:
            context: Human-readable label for the source of the redacted text.
            result: The completed :class:`~aumai_pii_redactor.models.RedactionResult`.
            operator: Identifier of the caller who triggered this redaction.

        Returns:
            The persisted :class:`RedactionRecord` (with assigned ``id``).

        Raises:
            RuntimeError: If the store has not been initialised.
        """
        self._assert_initialized()
        pii_types = [m.pii_type.value for m in result.matches_found]
        record = RedactionRecord(
            context=context,
            operator=operator,
            redactions_applied=result.redactions_applied,
            pii_types_found=json.dumps(pii_types),
            result_json=result.model_dump_json(),
        )
        assigned_id = await self._repo.save(record)  # type: ignore[union-attr]
        record = record.model_copy(update={"id": assigned_id})
        return record

    # ------------------------------------------------------------------
    # Query operations
    # ------------------------------------------------------------------

    async def get_by_context(self, context: str) -> list[RedactionRecord]:
        """Return all audit records for a given context label.

        Args:
            context: The context label to filter by.

        Returns:
            List of :class:`RedactionRecord` instances, newest first.
        """
        self._assert_initialized()
        records = await self._repo.find(context=context)  # type: ignore[union-attr]
        return sorted(records, key=lambda r: r.timestamp, reverse=True)

    async def get_by_operator(self, operator: str) -> list[RedactionRecord]:
        """Return all audit records for a given operator.

        Args:
            operator: The operator identifier to filter by.

        Returns:
            List of :class:`RedactionRecord` instances.
        """
        self._assert_initialized()
        return await self._repo.find(operator=operator)  # type: ignore[union-attr]

    async def get_by_id(self, record_id: str) -> RedactionRecord | None:
        """Fetch a single audit record by its primary key.

        Args:
            record_id: UUID string assigned during :meth:`save_result`.

        Returns:
            The :class:`RedactionRecord`, or ``None`` if not found.
        """
        self._assert_initialized()
        return await self._repo.get(record_id)  # type: ignore[union-attr]

    async def get_all(self) -> list[RedactionRecord]:
        """Return every audit record stored in the backend.

        Returns:
            All :class:`RedactionRecord` instances.
        """
        self._assert_initialized()
        return await self._repo.find()  # type: ignore[union-attr]

    async def get_metrics(self) -> dict[str, Any]:
        """Compute aggregate metrics across all stored audit records.

        Returns a dictionary with:
            - ``total_records``: Total number of audit records.
            - ``total_redactions``: Sum of ``redactions_applied`` across all
              records.
            - ``pii_type_counts``: A dict mapping PII type label to the count
              of times that type was encountered across all records.

        Returns:
            A ``dict`` containing the aggregate metrics.
        """
        self._assert_initialized()
        all_records = await self.get_all()

        total_redactions = sum(r.redactions_applied for r in all_records)
        pii_type_counter: Counter[str] = Counter()

        for record in all_records:
            try:
                types: list[str] = json.loads(record.pii_types_found)
                pii_type_counter.update(types)
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "total_records": len(all_records),
            "total_redactions": total_redactions,
            "pii_type_counts": dict(pii_type_counter),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_initialized(self) -> None:
        """Raise if :meth:`initialize` has not been called."""
        if self._repo is None:
            raise RuntimeError(
                "RedactionStore has not been initialised. "
                "Call await store.initialize() or use it as an async context manager."
            )


__all__ = ["RedactionRecord", "RedactionStore"]
