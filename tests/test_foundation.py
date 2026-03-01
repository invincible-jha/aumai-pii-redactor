"""Comprehensive tests for the four foundation modules added to aumai-pii-redactor.

Covers:
    - async_core.AsyncPIIRedactor
    - store.RedactionStore / RedactionRecord
    - llm_detector.LLMPIIDetector / LLMPIIDetectionResult / LLMPIIEntity
    - integration.PIIRedactorIntegration / setup_pii_redactor
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from aumai_async_core import AsyncServiceConfig
from aumai_integration import AumOS, Event

from aumai_pii_redactor.async_core import AsyncPIIRedactor
from aumai_pii_redactor.integration import (
    PIIRedactorIntegration,
    setup_pii_redactor,
    _SERVICE_CAPABILITIES,
    _SERVICE_NAME,
    _SERVICE_VERSION,
)
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
from aumai_pii_redactor.store import RedactionRecord, RedactionStore


# ===========================================================================
# Shared helpers / fixtures
# ===========================================================================


def _make_redaction_result(
    text: str = "Contact alice@example.com",
    matches: list[PIIMatch] | None = None,
) -> RedactionResult:
    """Build a RedactionResult with optional match list."""
    if matches is None:
        matches = [
            PIIMatch(
                pii_type=PIIType.email,
                start=8,
                end=25,
                original_text="alice@example.com",
                confidence=0.99,
            )
        ]
    return RedactionResult(
        original_length=len(text),
        redacted_text=text.replace("alice@example.com", "a***m"),
        matches_found=matches,
        redactions_applied=len(matches),
    )


def _make_clean_result() -> RedactionResult:
    """Build a RedactionResult with no matches."""
    text = "Hello, how are you today?"
    return RedactionResult(
        original_length=len(text),
        redacted_text=text,
        matches_found=[],
        redactions_applied=0,
    )


def _make_async_service(
    name: str = "test-pii-redactor",
    *,
    redaction_config: RedactionConfig | None = None,
) -> AsyncPIIRedactor:
    """Return an AsyncPIIRedactor in non-executor mode for synchronous testing."""
    config = AsyncServiceConfig(
        name=name,
        health_check_interval_seconds=0.0,
    )
    return AsyncPIIRedactor(
        config,
        redaction_config=redaction_config,
        run_in_executor=False,
    )


@pytest.fixture
def async_service() -> AsyncPIIRedactor:
    return _make_async_service()


@pytest.fixture
def aumos() -> AumOS:
    return AumOS()


@pytest.fixture
def integration(aumos: AumOS) -> PIIRedactorIntegration:
    return PIIRedactorIntegration.from_aumos(aumos)


@pytest.fixture
def pii_text() -> str:
    return "Call me at 555-867-5309 or email alice@example.com"


@pytest.fixture
def clean_text() -> str:
    return "Hello, how are you today?"


# ===========================================================================
# Section 1: RedactionRecord model
# ===========================================================================


class TestRedactionRecord:
    def test_default_id_is_uuid(self) -> None:
        record = RedactionRecord()
        parsed = uuid.UUID(record.id)
        assert str(parsed) == record.id

    def test_default_context_is_unknown(self) -> None:
        record = RedactionRecord()
        assert record.context == "unknown"

    def test_default_operator_is_system(self) -> None:
        record = RedactionRecord()
        assert record.operator == "system"

    def test_default_timestamp_is_iso(self) -> None:
        from datetime import datetime
        record = RedactionRecord()
        dt = datetime.fromisoformat(record.timestamp)
        assert dt is not None

    def test_default_redactions_applied_zero(self) -> None:
        record = RedactionRecord()
        assert record.redactions_applied == 0

    def test_default_pii_types_found_empty_list(self) -> None:
        record = RedactionRecord()
        parsed = json.loads(record.pii_types_found)
        assert parsed == []

    def test_default_result_json_empty_object(self) -> None:
        record = RedactionRecord()
        assert record.result_json == "{}"

    def test_custom_fields_set_correctly(self) -> None:
        record = RedactionRecord(
            context="user-message",
            operator="alice",
            redactions_applied=3,
            pii_types_found='["email", "phone"]',
            result_json='{"original_length": 50}',
        )
        assert record.context == "user-message"
        assert record.operator == "alice"
        assert record.redactions_applied == 3

    def test_model_dump_has_all_fields(self) -> None:
        record = RedactionRecord()
        dumped = record.model_dump()
        assert "id" in dumped
        assert "context" in dumped
        assert "operator" in dumped
        assert "timestamp" in dumped
        assert "redactions_applied" in dumped
        assert "pii_types_found" in dumped
        assert "result_json" in dumped

    def test_model_validator_coerces_pii_types_found_dict_to_str(self) -> None:
        """Simulate what aumai-store does when parsing stored JSON back to a dict."""
        record = RedactionRecord.model_validate(
            {
                "context": "test",
                "pii_types_found": ["email", "phone"],  # list, not str
                "result_json": "{}",
            }
        )
        assert isinstance(record.pii_types_found, str)
        parsed = json.loads(record.pii_types_found)
        assert parsed == ["email", "phone"]

    def test_model_validator_coerces_result_json_dict_to_str(self) -> None:
        record = RedactionRecord.model_validate(
            {
                "context": "test",
                "pii_types_found": "[]",
                "result_json": {"original_length": 10},  # dict, not str
            }
        )
        assert isinstance(record.result_json, str)
        parsed = json.loads(record.result_json)
        assert parsed["original_length"] == 10

    def test_pii_types_found_is_always_str(self) -> None:
        record = RedactionRecord(pii_types_found='["email"]')
        assert isinstance(record.pii_types_found, str)


# ===========================================================================
# Section 2: RedactionStore lifecycle
# ===========================================================================


class TestRedactionStoreLifecycle:
    async def test_memory_factory_creates_store(self) -> None:
        store = RedactionStore.memory()
        assert isinstance(store, RedactionStore)

    async def test_initialize_sets_up_repo(self) -> None:
        store = RedactionStore.memory()
        await store.initialize()
        records = await store.get_all()
        assert isinstance(records, list)
        await store.close()

    async def test_context_manager_initializes_and_closes(self) -> None:
        async with RedactionStore.memory() as store:
            records = await store.get_all()
            assert records == []

    async def test_uninitialized_store_raises_on_get_all(self) -> None:
        store = RedactionStore.memory()
        with pytest.raises(RuntimeError, match="not been initialised"):
            await store.get_all()

    async def test_initialize_is_idempotent(self) -> None:
        async with RedactionStore.memory() as store:
            await store.initialize()  # second call
            records = await store.get_all()
            assert records == []

    async def test_close_is_safe_on_uninitialized(self) -> None:
        store = RedactionStore.memory()
        # Should not raise even if never initialized.
        await store.close()


# ===========================================================================
# Section 3: RedactionStore save_result
# ===========================================================================


class TestRedactionStoreSaveResult:
    async def test_save_result_returns_redaction_record(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("user-message", result)
            assert isinstance(record, RedactionRecord)

    async def test_save_result_sets_context(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("span-attribute", result)
            assert record.context == "span-attribute"

    async def test_save_result_sets_operator(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("ctx", result, operator="bob")
            assert record.operator == "bob"

    async def test_save_result_default_operator_system(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("ctx", result)
            assert record.operator == "system"

    async def test_save_result_sets_redactions_applied(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("ctx", result)
            assert record.redactions_applied == result.redactions_applied

    async def test_save_result_zero_redactions_when_clean(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_clean_result()
            record = await store.save_result("ctx", result)
            assert record.redactions_applied == 0

    async def test_save_result_pii_types_found_is_valid_json(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("ctx", result)
            parsed = json.loads(record.pii_types_found)
            assert isinstance(parsed, list)

    async def test_save_result_pii_types_found_contains_email(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("ctx", result)
            types = json.loads(record.pii_types_found)
            assert "email" in types

    async def test_save_result_result_json_is_valid_json(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("ctx", result)
            parsed = json.loads(record.result_json)
            assert isinstance(parsed, dict)

    async def test_save_result_assigns_id(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            record = await store.save_result("ctx", result)
            assert len(record.id) > 0


# ===========================================================================
# Section 4: RedactionStore queries
# ===========================================================================


class TestRedactionStoreQueries:
    async def test_get_by_context_empty_when_none_saved(self) -> None:
        async with RedactionStore.memory() as store:
            records = await store.get_by_context("no-such-context")
            assert records == []

    async def test_get_by_context_filters_correctly(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            await store.save_result("ctx-a", result)
            await store.save_result("ctx-b", result)
            records = await store.get_by_context("ctx-a")
            assert len(records) == 1
            assert records[0].context == "ctx-a"

    async def test_get_by_context_returns_newest_first(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            await store.save_result("ctx", result)
            await store.save_result("ctx", result)
            records = await store.get_by_context("ctx")
            timestamps = [r.timestamp for r in records]
            assert timestamps == sorted(timestamps, reverse=True)

    async def test_get_by_operator_filters_correctly(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            await store.save_result("ctx", result, operator="alice")
            await store.save_result("ctx", result, operator="bob")
            records = await store.get_by_operator("alice")
            assert len(records) == 1
            assert records[0].operator == "alice"

    async def test_get_by_id_returns_record(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            saved = await store.save_result("ctx", result)
            retrieved = await store.get_by_id(saved.id)
            assert retrieved is not None
            assert retrieved.context == "ctx"

    async def test_get_by_id_returns_none_for_unknown(self) -> None:
        async with RedactionStore.memory() as store:
            retrieved = await store.get_by_id("non-existent-id")
            assert retrieved is None

    async def test_get_all_returns_all_records(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            await store.save_result("ctx-x", result)
            await store.save_result("ctx-y", result)
            all_records = await store.get_all()
            assert len(all_records) == 2

    async def test_get_all_empty_store(self) -> None:
        async with RedactionStore.memory() as store:
            records = await store.get_all()
            assert records == []


# ===========================================================================
# Section 5: RedactionStore metrics
# ===========================================================================


class TestRedactionStoreMetrics:
    async def test_metrics_empty_store(self) -> None:
        async with RedactionStore.memory() as store:
            metrics = await store.get_metrics()
            assert metrics["total_records"] == 0
            assert metrics["total_redactions"] == 0
            assert metrics["pii_type_counts"] == {}

    async def test_metrics_total_records(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()
            await store.save_result("ctx", result)
            await store.save_result("ctx", result)
            metrics = await store.get_metrics()
            assert metrics["total_records"] == 2

    async def test_metrics_total_redactions(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()  # 1 redaction
            await store.save_result("ctx", result)
            await store.save_result("ctx", result)
            metrics = await store.get_metrics()
            assert metrics["total_redactions"] == 2

    async def test_metrics_pii_type_counts(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_redaction_result()  # email match
            await store.save_result("ctx", result)
            metrics = await store.get_metrics()
            assert "email" in metrics["pii_type_counts"]
            assert metrics["pii_type_counts"]["email"] == 1

    async def test_metrics_clean_result_no_pii_types(self) -> None:
        async with RedactionStore.memory() as store:
            result = _make_clean_result()
            await store.save_result("ctx", result)
            metrics = await store.get_metrics()
            assert metrics["total_redactions"] == 0
            assert metrics["pii_type_counts"] == {}


# ===========================================================================
# Section 6: AsyncPIIRedactor lifecycle
# ===========================================================================


class TestAsyncPIIRedactorLifecycle:
    async def test_default_config_has_name_pii_redactor(self) -> None:
        service = AsyncPIIRedactor()
        assert service.config.name == "pii-redactor"

    async def test_custom_config_respected(self) -> None:
        config = AsyncServiceConfig(
            name="custom-redactor",
            health_check_interval_seconds=0.0,
        )
        service = AsyncPIIRedactor(config, run_in_executor=False)
        assert service.config.name == "custom-redactor"

    async def test_service_starts_and_stops(self) -> None:
        service = _make_async_service()
        await service.start()
        assert service.status.state == "running"
        await service.stop()
        assert service.status.state == "stopped"

    async def test_start_increments_state_to_running(self) -> None:
        service = _make_async_service()
        assert service.status.state == "created"
        await service.start()
        assert service.status.state == "running"
        await service.stop()

    async def test_stop_removes_all_event_listeners(self) -> None:
        service = _make_async_service()
        await service.start()

        async def noop(**kw: Any) -> None:
            pass

        service.emitter.on("scan.completed", noop)
        assert service.emitter.listener_count("scan.completed") == 1
        await service.stop()
        assert service.emitter.listener_count("scan.completed") == 0

    async def test_health_check_returns_true_on_healthy_service(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        await async_service.start()
        result = await async_service.health_check()
        assert result is True
        await async_service.stop()

    async def test_emitter_property_returns_emitter_instance(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        from aumai_async_core import AsyncEventEmitter
        assert isinstance(async_service.emitter, AsyncEventEmitter)


# ===========================================================================
# Section 7: AsyncPIIRedactor.detect()
# ===========================================================================


class TestAsyncPIIRedactorDetect:
    async def test_detect_clean_text_returns_empty_list(
        self, async_service: AsyncPIIRedactor, clean_text: str
    ) -> None:
        await async_service.start()
        matches = await async_service.detect(clean_text)
        assert matches == []
        await async_service.stop()

    async def test_detect_email_returns_match(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        await async_service.start()
        matches = await async_service.detect("Email: alice@example.com")
        assert len(matches) >= 1
        assert any(m.pii_type == PIIType.email for m in matches)
        await async_service.stop()

    async def test_detect_emits_pii_detected_event(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("pii.detected", capture)
        await async_service.detect(pii_text)
        assert len(events) == 1
        await async_service.stop()

    async def test_detect_event_has_match_count(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("pii.detected", capture)
        matches = await async_service.detect(pii_text)
        assert events[0]["match_count"] == len(matches)
        await async_service.stop()

    async def test_detect_event_has_text_length(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("pii.detected", capture)
        await async_service.detect(pii_text)
        assert events[0]["text_length"] == len(pii_text)
        await async_service.stop()

    async def test_detect_increments_request_count(
        self, async_service: AsyncPIIRedactor, clean_text: str
    ) -> None:
        await async_service.start()
        await async_service.detect(clean_text)
        assert async_service.status.request_count == 1
        await async_service.detect(clean_text)
        assert async_service.status.request_count == 2
        await async_service.stop()


# ===========================================================================
# Section 8: AsyncPIIRedactor.redact()
# ===========================================================================


class TestAsyncPIIRedactorRedact:
    async def test_redact_clean_text_unchanged(
        self, async_service: AsyncPIIRedactor, clean_text: str
    ) -> None:
        await async_service.start()
        result = await async_service.redact(clean_text)
        assert result.redacted_text == clean_text
        assert result.redactions_applied == 0
        await async_service.stop()

    async def test_redact_email_is_replaced(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        await async_service.start()
        result = await async_service.redact("Contact alice@example.com now")
        assert "alice@example.com" not in result.redacted_text
        assert result.redactions_applied >= 1
        await async_service.stop()

    async def test_redact_emits_pii_detected_event(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("pii.detected", capture)
        await async_service.redact(pii_text)
        assert len(events) == 1
        await async_service.stop()

    async def test_redact_emits_pii_redacted_event(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("pii.redacted", capture)
        await async_service.redact(pii_text)
        assert len(events) == 1
        await async_service.stop()

    async def test_redact_emits_scan_completed_event(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("scan.completed", capture)
        await async_service.redact(pii_text)
        assert len(events) == 1
        await async_service.stop()

    async def test_redact_scan_completed_safe_true_on_clean(
        self, async_service: AsyncPIIRedactor, clean_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("scan.completed", capture)
        await async_service.redact(clean_text)
        assert events[0]["safe"] is True
        await async_service.stop()

    async def test_redact_scan_completed_safe_false_on_pii(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("scan.completed", capture)
        await async_service.redact(pii_text)
        assert events[0]["safe"] is False
        await async_service.stop()

    async def test_redact_returns_redaction_result(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        result = await async_service.redact(pii_text)
        assert isinstance(result, RedactionResult)
        await async_service.stop()

    async def test_redact_increments_request_count(
        self, async_service: AsyncPIIRedactor, clean_text: str
    ) -> None:
        await async_service.start()
        await async_service.redact(clean_text)
        assert async_service.status.request_count == 1
        await async_service.stop()

    async def test_redact_pii_redacted_event_has_redactions_applied(
        self, async_service: AsyncPIIRedactor, pii_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("pii.redacted", capture)
        result = await async_service.redact(pii_text)
        assert events[0]["redactions_applied"] == result.redactions_applied
        await async_service.stop()

    async def test_redact_with_context_label(
        self, async_service: AsyncPIIRedactor, clean_text: str
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("scan.completed", capture)
        await async_service.redact(clean_text, context="my-context")
        assert events[0]["context"] == "my-context"
        await async_service.stop()


# ===========================================================================
# Section 9: AsyncPIIRedactor.redact_dict()
# ===========================================================================


class TestAsyncPIIRedactorRedactDict:
    async def test_redact_dict_returns_dict(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        await async_service.start()
        data = {"greeting": "Hello world"}
        result = await async_service.redact_dict(data)
        assert isinstance(result, dict)
        await async_service.stop()

    async def test_redact_dict_preserves_non_string_values(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        await async_service.start()
        data = {"count": 42, "active": True, "ratio": 3.14}
        result = await async_service.redact_dict(data)
        assert result["count"] == 42
        assert result["active"] is True
        await async_service.stop()

    async def test_redact_dict_redacts_email_in_value(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        await async_service.start()
        data = {"user": "alice@example.com"}
        result = await async_service.redact_dict(data)
        assert "alice@example.com" not in str(result["user"])
        await async_service.stop()

    async def test_redact_dict_emits_scan_completed(
        self, async_service: AsyncPIIRedactor
    ) -> None:
        await async_service.start()
        events: list[dict[str, Any]] = []

        async def capture(**kw: Any) -> None:
            events.append(kw)

        async_service.emitter.on("scan.completed", capture)
        await async_service.redact_dict({"key": "value"})
        assert len(events) == 1
        await async_service.stop()


# ===========================================================================
# Section 10: LLMPIIEntity model
# ===========================================================================


class TestLLMPIIEntity:
    def test_default_category_unknown(self) -> None:
        entity = LLMPIIEntity(text="test@example.com")
        assert entity.category == "unknown"

    def test_default_confidence_medium(self) -> None:
        entity = LLMPIIEntity(text="test@example.com")
        assert entity.confidence == "medium"

    def test_default_start_hint_minus_one(self) -> None:
        entity = LLMPIIEntity(text="555-1234")
        assert entity.start_hint == -1

    def test_custom_fields_set_correctly(self) -> None:
        entity = LLMPIIEntity(
            text="alice@example.com",
            category="email",
            confidence="very_high",
            context="Email: alice@example.com now",
            start_hint=7,
        )
        assert entity.text == "alice@example.com"
        assert entity.category == "email"
        assert entity.confidence == "very_high"
        assert entity.start_hint == 7


# ===========================================================================
# Section 11: LLMPIIDetectionResult
# ===========================================================================


class TestLLMPIIDetectionResult:
    def test_default_overall_risk_none(self) -> None:
        result = LLMPIIDetectionResult()
        assert result.overall_risk == "none"

    def test_default_entities_empty(self) -> None:
        result = LLMPIIDetectionResult()
        assert result.entities == []

    def test_llm_powered_true_by_default(self) -> None:
        result = LLMPIIDetectionResult()
        assert result.llm_powered is True

    def test_to_pii_matches_empty_entities(self) -> None:
        result = LLMPIIDetectionResult()
        matches = result.to_pii_matches()
        assert matches == []

    def test_to_pii_matches_email_entity(self) -> None:
        entity = LLMPIIEntity(
            text="alice@example.com",
            category="email",
            confidence="high",
            start_hint=0,
        )
        result = LLMPIIDetectionResult(entities=[entity], overall_risk="high")
        matches = result.to_pii_matches()
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.email
        assert matches[0].original_text == "alice@example.com"

    def test_to_pii_matches_unknown_category_falls_back_to_custom(self) -> None:
        entity = LLMPIIEntity(
            text="secret-api-key-12345",
            category="credential",
            confidence="high",
        )
        result = LLMPIIDetectionResult(entities=[entity])
        matches = result.to_pii_matches()
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.custom

    def test_to_pii_matches_confidence_very_high_maps_to_high_score(self) -> None:
        entity = LLMPIIEntity(
            text="alice@example.com",
            category="email",
            confidence="very_high",
        )
        result = LLMPIIDetectionResult(entities=[entity])
        matches = result.to_pii_matches()
        assert matches[0].confidence >= 0.90

    def test_to_pii_matches_start_hint_zero_uses_zero(self) -> None:
        entity = LLMPIIEntity(
            text="123-45-6789",
            category="ssn",
            confidence="high",
            start_hint=0,
        )
        result = LLMPIIDetectionResult(entities=[entity])
        matches = result.to_pii_matches()
        assert matches[0].start == 0

    def test_to_pii_matches_negative_start_hint_defaults_to_zero(self) -> None:
        entity = LLMPIIEntity(
            text="john",
            category="name",
            confidence="medium",
            start_hint=-1,
        )
        result = LLMPIIDetectionResult(entities=[entity])
        matches = result.to_pii_matches()
        assert matches[0].start == 0


# ===========================================================================
# Section 12: LLMPIIDetector with MockProvider
# ===========================================================================


class TestLLMPIIDetector:
    async def test_analyze_returns_detection_result(self) -> None:
        detector = build_mock_detector()
        result = await detector.analyze("No PII here")
        assert isinstance(result, LLMPIIDetectionResult)

    async def test_analyze_default_mock_returns_none_risk(self) -> None:
        detector = build_mock_detector()
        result = await detector.analyze("No PII here")
        assert result.overall_risk == "none"

    async def test_analyze_llm_powered_true_when_client_configured(self) -> None:
        detector = build_mock_detector()
        result = await detector.analyze("test text")
        assert result.llm_powered is True

    async def test_analyze_with_entities_in_response(self) -> None:
        response = json.dumps(
            {
                "entities": [
                    {
                        "text": "alice@example.com",
                        "category": "email",
                        "confidence": "very_high",
                        "context": "alice@example.com",
                        "start_hint": 0,
                    }
                ],
                "overall_risk": "high",
                "explanation": "Email address found.",
            }
        )
        detector = build_mock_detector([response])
        result = await detector.analyze("alice@example.com")
        assert len(result.entities) == 1
        assert result.entities[0].text == "alice@example.com"
        assert result.overall_risk == "high"

    async def test_analyze_fallback_when_no_client(self) -> None:
        detector = LLMPIIDetector(client=None)
        result = await detector.analyze("alice@example.com")
        assert result.llm_powered is False

    async def test_analyze_fallback_finds_email(self) -> None:
        detector = LLMPIIDetector(client=None)
        result = await detector.analyze("Email: alice@example.com today")
        assert len(result.entities) >= 1
        categories = [e.category for e in result.entities]
        assert "email" in categories

    async def test_analyze_fallback_clean_text_no_entities(self) -> None:
        detector = LLMPIIDetector(client=None)
        result = await detector.analyze("Hello, how are you?")
        assert result.overall_risk == "none"
        assert result.entities == []

    async def test_analyze_parse_error_returns_medium_risk(self) -> None:
        detector = build_mock_detector(["not valid json {{{"])
        result = await detector.analyze("test text")
        assert result.overall_risk == "medium"

    async def test_build_mock_detector_returns_llm_pii_detector(self) -> None:
        detector = build_mock_detector()
        assert isinstance(detector, LLMPIIDetector)

    async def test_build_mock_detector_custom_response(self) -> None:
        response = json.dumps(
            {
                "entities": [],
                "overall_risk": "low",
                "explanation": "minor data found",
            }
        )
        detector = build_mock_detector([response])
        result = await detector.analyze("some text")
        assert result.overall_risk == "low"

    async def test_analyze_entities_multiple(self) -> None:
        response = json.dumps(
            {
                "entities": [
                    {
                        "text": "alice@example.com",
                        "category": "email",
                        "confidence": "very_high",
                        "context": "",
                        "start_hint": 0,
                    },
                    {
                        "text": "555-867-5309",
                        "category": "phone",
                        "confidence": "high",
                        "context": "",
                        "start_hint": 20,
                    },
                ],
                "overall_risk": "very_high",
                "explanation": "Multiple PII types found.",
            }
        )
        detector = build_mock_detector([response])
        result = await detector.analyze("alice@example.com and 555-867-5309")
        assert len(result.entities) == 2

    async def test_to_pii_matches_from_mock_result(self) -> None:
        response = json.dumps(
            {
                "entities": [
                    {
                        "text": "alice@example.com",
                        "category": "email",
                        "confidence": "high",
                        "context": "",
                        "start_hint": 0,
                    }
                ],
                "overall_risk": "high",
                "explanation": "",
            }
        )
        detector = build_mock_detector([response])
        result = await detector.analyze("alice@example.com")
        matches = result.to_pii_matches()
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.email


# ===========================================================================
# Section 13: PIIRedactorIntegration registration
# ===========================================================================


class TestPIIRedactorIntegrationRegistration:
    async def test_register_sets_is_registered_true(
        self, integration: PIIRedactorIntegration
    ) -> None:
        assert integration.is_registered is False
        await integration.register()
        assert integration.is_registered is True

    async def test_register_is_idempotent(
        self, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        await integration.register()  # second call — should not raise
        assert integration.is_registered is True

    async def test_register_adds_service_to_discovery(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        service = aumos.get_service(_SERVICE_NAME)
        assert service is not None

    async def test_registered_service_has_correct_name(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        service = aumos.get_service(_SERVICE_NAME)
        assert service is not None
        assert service.name == _SERVICE_NAME

    async def test_registered_service_has_correct_version(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        service = aumos.get_service(_SERVICE_NAME)
        assert service is not None
        assert service.version == _SERVICE_VERSION

    async def test_registered_service_has_capabilities(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        service = aumos.get_service(_SERVICE_NAME)
        assert service is not None
        for cap in _SERVICE_CAPABILITIES:
            assert cap in service.capabilities

    async def test_registered_service_status_healthy(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        service = aumos.get_service(_SERVICE_NAME)
        assert service is not None
        assert service.status == "healthy"

    async def test_unregister_sets_is_registered_false(
        self, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        await integration.unregister()
        assert integration.is_registered is False

    async def test_unregister_stops_auto_redact(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        await integration.unregister()
        redact_events: list[Event] = []

        async def capture(event: Event) -> None:
            redact_events.append(event)

        aumos.events.subscribe("pii.redacted", capture)
        await aumos.events.publish_simple(
            "agent.text_submitted",
            source="test-agent",
            text="alice@example.com",
            context="msg",
        )
        assert len(redact_events) == 0


# ===========================================================================
# Section 14: PIIRedactorIntegration factory
# ===========================================================================


class TestPIIRedactorIntegrationFactory:
    def test_from_aumos_returns_integration(self, aumos: AumOS) -> None:
        result = PIIRedactorIntegration.from_aumos(aumos)
        assert isinstance(result, PIIRedactorIntegration)

    def test_from_aumos_binds_to_hub(self, aumos: AumOS) -> None:
        result = PIIRedactorIntegration.from_aumos(aumos)
        assert result.aumos is aumos

    def test_from_aumos_with_custom_redaction_config(
        self, aumos: AumOS
    ) -> None:
        config = RedactionConfig(
            rules=[
                RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.remove)
            ]
        )
        integration = PIIRedactorIntegration.from_aumos(aumos, redaction_config=config)
        assert isinstance(integration, PIIRedactorIntegration)


# ===========================================================================
# Section 15: setup_pii_redactor convenience function
# ===========================================================================


class TestSetupPIIRedactor:
    async def test_setup_returns_registered_integration(
        self, aumos: AumOS
    ) -> None:
        integration = await setup_pii_redactor(aumos)
        assert isinstance(integration, PIIRedactorIntegration)
        assert integration.is_registered is True

    async def test_setup_registers_service(self, aumos: AumOS) -> None:
        await setup_pii_redactor(aumos)
        service = aumos.get_service(_SERVICE_NAME)
        assert service is not None


# ===========================================================================
# Section 16: PIIRedactorIntegration.redact_and_publish()
# ===========================================================================


class TestRedactAndPublish:
    async def test_clean_text_publishes_scan_completed(
        self, aumos: AumOS, integration: PIIRedactorIntegration, clean_text: str
    ) -> None:
        await integration.register()
        events: list[Event] = []

        async def capture(event: Event) -> None:
            events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        await integration.redact_and_publish(clean_text, context="ctx")
        assert len(events) == 1

    async def test_clean_text_scan_completed_safe_true(
        self, aumos: AumOS, integration: PIIRedactorIntegration, clean_text: str
    ) -> None:
        await integration.register()
        events: list[Event] = []

        async def capture(event: Event) -> None:
            events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        await integration.redact_and_publish(clean_text, context="ctx")
        assert events[0].data["safe"] is True

    async def test_pii_text_publishes_pii_detected(
        self, aumos: AumOS, integration: PIIRedactorIntegration, pii_text: str
    ) -> None:
        await integration.register()
        events: list[Event] = []

        async def capture(event: Event) -> None:
            events.append(event)

        aumos.events.subscribe("pii.detected", capture)
        await integration.redact_and_publish(pii_text, context="ctx")
        assert len(events) >= 1

    async def test_pii_text_publishes_pii_redacted(
        self, aumos: AumOS, integration: PIIRedactorIntegration, pii_text: str
    ) -> None:
        await integration.register()
        events: list[Event] = []

        async def capture(event: Event) -> None:
            events.append(event)

        aumos.events.subscribe("pii.redacted", capture)
        await integration.redact_and_publish(pii_text, context="ctx")
        assert len(events) == 1

    async def test_pii_detected_event_has_match_count(
        self, aumos: AumOS, integration: PIIRedactorIntegration, pii_text: str
    ) -> None:
        await integration.register()
        events: list[Event] = []

        async def capture(event: Event) -> None:
            events.append(event)

        aumos.events.subscribe("pii.detected", capture)
        result = await integration.redact_and_publish(pii_text, context="ctx")
        assert events[0].data["match_count"] == len(result.matches_found)

    async def test_scan_completed_event_has_context(
        self, aumos: AumOS, integration: PIIRedactorIntegration, clean_text: str
    ) -> None:
        await integration.register()
        events: list[Event] = []

        async def capture(event: Event) -> None:
            events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        await integration.redact_and_publish(clean_text, context="my-context")
        assert events[0].data["context"] == "my-context"

    async def test_redact_and_publish_returns_redaction_result(
        self, aumos: AumOS, integration: PIIRedactorIntegration, clean_text: str
    ) -> None:
        await integration.register()
        result = await integration.redact_and_publish(clean_text)
        assert isinstance(result, RedactionResult)

    async def test_pii_redacted_event_source_is_service_name(
        self, aumos: AumOS, integration: PIIRedactorIntegration, pii_text: str
    ) -> None:
        await integration.register()
        events: list[Event] = []

        async def capture(event: Event) -> None:
            events.append(event)

        aumos.events.subscribe("pii.redacted", capture)
        await integration.redact_and_publish(pii_text)
        assert events[0].source == _SERVICE_NAME


# ===========================================================================
# Section 17: PIIRedactorIntegration auto-redaction on agent.text_submitted
# ===========================================================================


class TestAutoRedact:
    async def test_text_submitted_triggers_auto_redact(
        self, aumos: AumOS, integration: PIIRedactorIntegration, pii_text: str
    ) -> None:
        await integration.register()
        scan_events: list[Event] = []

        async def capture(event: Event) -> None:
            scan_events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        await aumos.events.publish_simple(
            "agent.text_submitted",
            source="my-agent",
            text=pii_text,
            context="chat",
        )
        assert len(scan_events) == 1

    async def test_text_submitted_with_clean_text_no_pii_detected(
        self, aumos: AumOS, integration: PIIRedactorIntegration, clean_text: str
    ) -> None:
        await integration.register()
        pii_events: list[Event] = []

        async def capture(event: Event) -> None:
            pii_events.append(event)

        aumos.events.subscribe("pii.detected", capture)
        await aumos.events.publish_simple(
            "agent.text_submitted",
            source="my-agent",
            text=clean_text,
            context="chat",
        )
        assert len(pii_events) == 0

    async def test_text_submitted_missing_text_skipped_gracefully(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        scan_events: list[Event] = []

        async def capture(event: Event) -> None:
            scan_events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        await aumos.events.publish_simple(
            "agent.text_submitted",
            source="agent",
            context="chat",
            # no "text" key
        )
        assert len(scan_events) == 0

    async def test_text_submitted_non_string_text_skipped(
        self, aumos: AumOS, integration: PIIRedactorIntegration
    ) -> None:
        await integration.register()
        scan_events: list[Event] = []

        async def capture(event: Event) -> None:
            scan_events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        await aumos.events.publish_simple(
            "agent.text_submitted",
            source="agent",
            text=12345,  # not a string
            context="chat",
        )
        assert len(scan_events) == 0

    async def test_multiple_text_submitted_all_processed(
        self, aumos: AumOS, integration: PIIRedactorIntegration, clean_text: str
    ) -> None:
        await integration.register()
        scan_events: list[Event] = []

        async def capture(event: Event) -> None:
            scan_events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        for _ in range(3):
            await aumos.events.publish_simple(
                "agent.text_submitted",
                source="agent",
                text=clean_text,
                context="chat",
            )
        assert len(scan_events) == 3

    async def test_text_submitted_context_propagated_to_event(
        self, aumos: AumOS, integration: PIIRedactorIntegration, clean_text: str
    ) -> None:
        await integration.register()
        scan_events: list[Event] = []

        async def capture(event: Event) -> None:
            scan_events.append(event)

        aumos.events.subscribe("scan.completed", capture)
        await aumos.events.publish_simple(
            "agent.text_submitted",
            source="agent",
            text=clean_text,
            context="special-context",
        )
        assert scan_events[0].data["context"] == "special-context"
