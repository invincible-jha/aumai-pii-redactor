"""LLM-powered PII detector using aumai-llm-core foundation library.

Provides LLMPIIDetector, which uses a language model to perform semantic
analysis of text for PII that goes beyond what static regex patterns can catch.
Falls back to the synchronous regex-based detector when the LLM is unavailable.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from aumai_llm_core import (
    CompletionRequest,
    LLMClient,
    Message,
    MockProvider,
    ModelConfig,
)
from pydantic import BaseModel, Field

from aumai_pii_redactor.detector import PIIDetector
from aumai_pii_redactor.models import PIIMatch, PIIType, RedactionConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Structured output model
# ---------------------------------------------------------------------------

_CONFIDENCE_LEVELS = ("none", "low", "medium", "high", "very_high")

_CATEGORY_VALUES = (
    "email",
    "phone",
    "ssn",
    "credit_card",
    "ip_address",
    "name",
    "address",
    "date_of_birth",
    "passport",
    "financial",
    "medical",
    "credential",
    "custom",
    "unknown",
)


class LLMPIIEntity(BaseModel):
    """A single PII entity detected by the LLM.

    Attributes:
        text: The raw PII text that was found.
        category: The PII category label (e.g. ``"email"``, ``"name"``).
        confidence: Confidence level — one of ``"low"``, ``"medium"``,
            ``"high"``, ``"very_high"``.
        context: Short snippet of surrounding context showing where the entity
            appeared.
        start_hint: Best-effort character offset estimate within the source
            text (may be ``-1`` when the model cannot determine it).
    """

    text: str = Field(description="The detected PII text.")
    category: str = Field(
        default="unknown",
        description="PII category label.",
    )
    confidence: str = Field(
        default="medium",
        description="Confidence level: low | medium | high | very_high",
    )
    context: str = Field(
        default="",
        description="Short surrounding context snippet.",
    )
    start_hint: int = Field(
        default=-1,
        description="Best-effort character offset within the source text.",
    )


class LLMPIIDetectionResult(BaseModel):
    """Structured output returned by the LLM-powered PII analysis.

    Attributes:
        entities: List of PII entities detected by the LLM.
        overall_risk: Overall PII risk level — one of ``"none"``, ``"low"``,
            ``"medium"``, ``"high"``, ``"very_high"``.
        explanation: Natural-language explanation of the findings.
        llm_powered: ``True`` when the result came from an LLM call, ``False``
            when it came from the regex fallback.
    """

    entities: list[LLMPIIEntity] = Field(
        default_factory=list,
        description="Detected PII entities.",
    )
    overall_risk: str = Field(
        default="none",
        description="Overall PII risk level.",
    )
    explanation: str = Field(
        default="",
        description="Human-readable explanation of findings.",
    )
    llm_powered: bool = Field(
        default=True,
        description="True when the result was produced by an LLM call.",
    )

    def to_pii_matches(self) -> list[PIIMatch]:
        """Convert LLM entities into :class:`~aumai_pii_redactor.models.PIIMatch` objects.

        Maps LLM category labels to known :class:`~aumai_pii_redactor.models.PIIType`
        values, falling back to ``PIIType.custom`` for unrecognised categories.

        Returns:
            List of :class:`~aumai_pii_redactor.models.PIIMatch` instances
            with ``start`` and ``end`` set from ``start_hint`` when available,
            otherwise ``0``.
        """
        _category_map: dict[str, PIIType] = {
            "email": PIIType.email,
            "phone": PIIType.phone,
            "ssn": PIIType.ssn,
            "credit_card": PIIType.credit_card,
            "ip_address": PIIType.ip_address,
            "name": PIIType.name,
            "address": PIIType.address,
            "date_of_birth": PIIType.date_of_birth,
            "passport": PIIType.passport,
        }
        _confidence_score: dict[str, float] = {
            "very_high": 0.97,
            "high": 0.85,
            "medium": 0.65,
            "low": 0.40,
            "none": 0.10,
        }

        matches: list[PIIMatch] = []
        for entity in self.entities:
            pii_type = _category_map.get(entity.category, PIIType.custom)
            start = max(entity.start_hint, 0)
            end = start + len(entity.text)
            confidence = _confidence_score.get(entity.confidence, 0.65)
            matches.append(
                PIIMatch(
                    pii_type=pii_type,
                    start=start,
                    end=end,
                    original_text=entity.text,
                    confidence=confidence,
                )
            )
        return matches


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a privacy and compliance assistant specialising in PII (Personally
Identifiable Information) detection within unstructured text.

Analyse the provided text and identify all PII entities including but not
limited to:
  - Names (full, first, last)
  - Email addresses
  - Phone numbers
  - Social Security Numbers (SSNs) or national ID numbers
  - Credit card numbers
  - IP addresses
  - Physical addresses
  - Dates of birth
  - Passport or government ID numbers
  - Financial account numbers
  - Medical record identifiers
  - Usernames, passwords, API keys, or credentials

Respond ONLY with a valid JSON object matching this exact schema — no markdown,
no prose outside the JSON:
{
  "entities": [
    {
      "text": "<the PII text as it appears in the input>",
      "category": "<email|phone|ssn|credit_card|ip_address|name|address|date_of_birth|passport|financial|medical|credential|custom|unknown>",
      "confidence": "<low|medium|high|very_high>",
      "context": "<short surrounding context snippet>",
      "start_hint": <integer character offset, or -1 if unknown>
    }
  ],
  "overall_risk": "<none|low|medium|high|very_high>",
  "explanation": "<string>"
}

If no PII is found, return an empty entities list, set overall_risk to "none",
and leave explanation as an empty string.
"""


class LLMPIIDetector:
    """LLM-powered detector that performs semantic PII analysis.

    Sends the text to an LLM for deep analysis and returns a structured
    :class:`LLMPIIDetectionResult`.  Automatically falls back to the
    regex-based :class:`~aumai_pii_redactor.detector.PIIDetector` when the
    LLM call fails or the response cannot be parsed.

    Args:
        client: An :class:`~aumai_llm_core.core.LLMClient` instance.  When
            ``None`` the detector operates in **fallback-only mode** (regex
            detection only).
        fallback_config: A :class:`~aumai_pii_redactor.models.RedactionConfig`
            passed to the regex fallback detector.  Defaults to the built-in
            configuration.

    Example (production)::

        config = ModelConfig(provider="anthropic", model_id="claude-sonnet-4-6")
        client = LLMClient(config)
        detector = LLMPIIDetector(client=client)
        result = await detector.analyze("Call me at 555-867-5309")

    Example (testing with MockProvider)::

        detector = build_mock_detector()
        result = await detector.analyze("My SSN is 123-45-6789")
        assert result.llm_powered is True
    """

    def __init__(
        self,
        client: LLMClient | None = None,
        fallback_config: RedactionConfig | None = None,
    ) -> None:
        self._client = client
        self._fallback_config = fallback_config or RedactionConfig()
        self._fallback = PIIDetector(self._fallback_config)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(self, text: str) -> LLMPIIDetectionResult:
        """Analyse *text* for PII using an LLM with regex fallback.

        The method first attempts an LLM call.  If the client is not
        configured, or if the LLM call fails, it falls back to regex-based
        detection automatically.

        Args:
            text: The string to analyse for PII.

        Returns:
            A :class:`LLMPIIDetectionResult` with detected entities and
            overall risk level.
        """
        if self._client is None:
            logger.debug(
                "LLMPIIDetector: no LLM client configured, using regex fallback."
            )
            return self._regex_fallback(text)

        try:
            return await self._llm_analyze(text)
        except Exception as exc:
            logger.warning(
                "LLMPIIDetector: LLM call failed (%s), falling back to regex.",
                exc,
            )
            return self._regex_fallback(text)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _llm_analyze(self, text: str) -> LLMPIIDetectionResult:
        """Perform the actual LLM call and parse the structured response.

        Args:
            text: The string to analyse.

        Returns:
            Parsed :class:`LLMPIIDetectionResult`.

        Raises:
            Exception: Propagates any provider or JSON-parse errors so the
                caller can decide whether to fall back to regex.
        """
        user_message = (
            f"Analyse the following text for PII:\n\n"
            f"---\n{text}\n---"
        )

        request = CompletionRequest(
            messages=[
                Message(role="system", content=_SYSTEM_PROMPT),
                Message(role="user", content=user_message),
            ],
            temperature=0.0,
        )

        assert self._client is not None  # guarded by caller
        response = await self._client.complete(request)
        return self._parse_llm_response(response.content)

    def _parse_llm_response(self, raw_content: str) -> LLMPIIDetectionResult:
        """Parse the LLM's JSON response into a :class:`LLMPIIDetectionResult`.

        Strips markdown code fences if present before attempting JSON parsing.
        If parsing fails, returns a conservative ``"medium"`` risk result with
        a note that the response was unparseable.

        Args:
            raw_content: Raw text content from the LLM response.

        Returns:
            A :class:`LLMPIIDetectionResult`.
        """
        content = raw_content.strip()
        # Strip optional markdown code fences.
        if content.startswith("```"):
            lines = content.splitlines()
            content = "\n".join(
                line
                for line in lines
                if not line.startswith("```")
            ).strip()

        try:
            data: dict[str, Any] = json.loads(content)
            raw_entities = data.get("entities", [])
            entities: list[LLMPIIEntity] = []
            for raw_entity in raw_entities:
                if isinstance(raw_entity, dict):
                    category = str(raw_entity.get("category", "unknown"))
                    confidence = str(raw_entity.get("confidence", "medium"))
                    if confidence not in _CONFIDENCE_LEVELS:
                        confidence = "medium"
                    entities.append(
                        LLMPIIEntity(
                            text=str(raw_entity.get("text", "")),
                            category=category,
                            confidence=confidence,
                            context=str(raw_entity.get("context", "")),
                            start_hint=int(raw_entity.get("start_hint", -1)),
                        )
                    )

            overall_risk = str(data.get("overall_risk", "none"))
            if overall_risk not in _CONFIDENCE_LEVELS:
                overall_risk = "medium"

            return LLMPIIDetectionResult(
                entities=entities,
                overall_risk=overall_risk,
                explanation=str(data.get("explanation", "")),
                llm_powered=True,
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "LLMPIIDetector: could not parse LLM JSON response: %s", exc
            )
            return LLMPIIDetectionResult(
                entities=[],
                overall_risk="medium",
                explanation=(
                    "LLM response could not be parsed — treating conservatively. "
                    f"Parse error: {exc}"
                ),
                llm_powered=True,
            )

    def _regex_fallback(self, text: str) -> LLMPIIDetectionResult:
        """Run regex-based PII detection on *text*.

        Converts :class:`~aumai_pii_redactor.models.PIIMatch` results into
        :class:`LLMPIIEntity` objects and computes an overall risk level.

        Args:
            text: The string to scan.

        Returns:
            A :class:`LLMPIIDetectionResult` marked with ``llm_powered=False``.
        """
        matches = self._fallback.detect(text)

        if not matches:
            return LLMPIIDetectionResult(
                entities=[],
                overall_risk="none",
                explanation="",
                llm_powered=False,
            )

        _confidence_map: dict[float, str] = {}

        def _score_to_level(score: float) -> str:
            if score >= 0.95:
                return "very_high"
            if score >= 0.80:
                return "high"
            if score >= 0.60:
                return "medium"
            return "low"

        entities = [
            LLMPIIEntity(
                text=match.original_text,
                category=match.pii_type.value,
                confidence=_score_to_level(match.confidence),
                context=text[max(0, match.start - 20) : match.end + 20],
                start_hint=match.start,
            )
            for match in matches
        ]

        # Derive overall risk from the highest confidence score.
        max_confidence = max(m.confidence for m in matches)
        overall_risk = _score_to_level(max_confidence)

        return LLMPIIDetectionResult(
            entities=entities,
            overall_risk=overall_risk,
            explanation=(
                f"Regex-based detection found {len(matches)} PII span(s). "
                "LLM analysis was unavailable."
            ),
            llm_powered=False,
        )


def build_mock_detector(
    responses: list[str] | None = None,
) -> LLMPIIDetector:
    """Create an :class:`LLMPIIDetector` backed by a :class:`~aumai_llm_core.MockProvider`.

    This is the canonical way to build a fully testable LLM PII detector
    without making real API calls.

    Args:
        responses: Canned JSON response strings to return in round-robin order.
            Defaults to a single ``"none"``-risk response.

    Returns:
        A configured :class:`LLMPIIDetector` using the mock provider.

    Example::

        detector = build_mock_detector([
            '{"entities":[{"text":"alice@example.com","category":"email",'
            '"confidence":"very_high","context":"","start_hint":0}],'
            '"overall_risk":"high","explanation":"Email found"}'
        ])
        result = await detector.analyze("Email me at alice@example.com")
        assert result.overall_risk == "high"
    """
    default_response = json.dumps(
        {
            "entities": [],
            "overall_risk": "none",
            "explanation": "",
        }
    )
    effective_responses = responses if responses is not None else [default_response]

    mock_provider = MockProvider(responses=effective_responses)
    config = ModelConfig(provider="mock", model_id="mock-pii-detector")
    client = LLMClient(config)
    client._provider = mock_provider  # type: ignore[attr-defined]
    return LLMPIIDetector(client=client)


__all__ = [
    "LLMPIIDetectionResult",
    "LLMPIIDetector",
    "LLMPIIEntity",
    "build_mock_detector",
]
