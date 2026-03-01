"""AumOS integration module for aumai-pii-redactor.

Registers the PII redactor as a named service in the AumOS discovery layer,
publishes ``pii.detected`` and ``pii.redacted`` events when redactions occur,
and subscribes to ``agent.text_submitted`` events to automatically scan
incoming text payloads.
"""

from __future__ import annotations

import logging
from typing import Any

from aumai_integration import AumOS, Event, EventBus, ServiceInfo

from aumai_pii_redactor.models import RedactionConfig, RedactionResult
from aumai_pii_redactor.redactor import PIIRedactor

logger = logging.getLogger(__name__)

# Service metadata constants.
_SERVICE_NAME = "pii-redactor"
_SERVICE_VERSION = "0.1.0"
_SERVICE_DESCRIPTION = (
    "AumAI PII Redactor — detect and redact personally identifiable information "
    "from agent telemetry and LLM pipeline text."
)
_SERVICE_CAPABILITIES = ["pii-detection", "pii-redaction", "text-sanitization"]


class PIIRedactorIntegration:
    """AumOS integration facade for the PII redactor service.

    Handles service registration, event subscriptions, and event publishing.
    One instance per application is expected; obtain via :meth:`from_aumos`.

    Attributes:
        SERVICE_NAME: Constant string ``"pii-redactor"`` used as the service key.

    Example::

        hub = AumOS()
        integration = PIIRedactorIntegration.from_aumos(hub)
        await integration.register()

        # Now any agent.text_submitted event triggers automatic redaction:
        await hub.events.publish_simple(
            "agent.text_submitted",
            source="my-agent",
            text="My email is alice@example.com",
            context="user-message",
        )
    """

    SERVICE_NAME: str = _SERVICE_NAME

    def __init__(
        self,
        aumos: AumOS,
        *,
        redaction_config: RedactionConfig | None = None,
    ) -> None:
        """Initialise the integration against an AumOS hub.

        Args:
            aumos: The AumOS hub to register with and subscribe events on.
            redaction_config: Optional redaction configuration.  Defaults to
                built-in patterns with mask strategy.
        """
        self._aumos = aumos
        self._redaction_config = redaction_config or RedactionConfig()
        self._redactor: PIIRedactor = PIIRedactor(self._redaction_config)
        self._subscription_id: str | None = None
        self._registered: bool = False
        # Cache of detected capability names from subscribed events.
        self._capability_cache: list[str] = []

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_aumos(
        cls,
        aumos: AumOS,
        *,
        redaction_config: RedactionConfig | None = None,
    ) -> "PIIRedactorIntegration":
        """Create a :class:`PIIRedactorIntegration` bound to *aumos*.

        Args:
            aumos: The AumOS hub instance.
            redaction_config: Optional redaction configuration.

        Returns:
            A new :class:`PIIRedactorIntegration`.
        """
        return cls(aumos, redaction_config=redaction_config)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(self) -> None:
        """Register the PII redactor with AumOS and start listening for text events.

        Idempotent — calling this method more than once is safe.

        Steps:
            1. Register the service descriptor with the discovery layer.
            2. Subscribe to ``agent.text_submitted`` events for auto-redaction.
        """
        if self._registered:
            logger.debug("PIIRedactorIntegration: already registered, skipping.")
            return

        service_info = ServiceInfo(
            name=_SERVICE_NAME,
            version=_SERVICE_VERSION,
            description=_SERVICE_DESCRIPTION,
            capabilities=list(_SERVICE_CAPABILITIES),
            endpoints={},
            metadata={
                "pii_types_supported": [
                    "email",
                    "phone",
                    "ssn",
                    "credit_card",
                    "ip_address",
                    "name",
                    "address",
                    "date_of_birth",
                    "passport",
                    "custom",
                ],
                "default_strategy": "mask",
            },
            status="healthy",
        )
        self._aumos.register(service_info)
        logger.info(
            "PIIRedactorIntegration: registered service '%s' v%s with capabilities %s",
            _SERVICE_NAME,
            _SERVICE_VERSION,
            _SERVICE_CAPABILITIES,
        )

        # Subscribe to agent.text_submitted events for automatic redaction.
        self._subscription_id = self._aumos.events.subscribe(
            pattern="agent.text_submitted",
            handler=self._handle_text_submitted,
            subscriber=_SERVICE_NAME,
        )
        logger.info(
            "PIIRedactorIntegration: subscribed to 'agent.text_submitted' events "
            "(subscription_id=%s)",
            self._subscription_id,
        )

        self._registered = True

    async def unregister(self) -> None:
        """Unsubscribe from events and mark the service as not registered.

        Does not remove the service from the discovery layer (that is managed
        by the AumOS hub lifecycle).
        """
        if self._subscription_id is not None:
            self._aumos.events.unsubscribe(self._subscription_id)
            self._subscription_id = None
        self._registered = False
        logger.info("PIIRedactorIntegration: unregistered.")

    # ------------------------------------------------------------------
    # Redaction with event publishing
    # ------------------------------------------------------------------

    async def redact_and_publish(
        self,
        text: str,
        *,
        context: str = "unknown",
        source: str = _SERVICE_NAME,
    ) -> RedactionResult:
        """Redact PII from *text* and publish domain events.

        Publishes:
            - ``pii.detected`` — if any PII matches were found.
            - ``pii.redacted`` — always, after redaction completes.
            - ``scan.completed`` — with safe flag and match count.

        Args:
            text: The text to redact.
            context: Human-readable label for the source of the text.
            source: Event source name (defaults to ``"pii-redactor"``).

        Returns:
            The :class:`~aumai_pii_redactor.models.RedactionResult`.
        """
        result = self._redactor.redact(text)

        if result.matches_found:
            pii_types = [m.pii_type.value for m in result.matches_found]
            await self._aumos.events.publish_simple(
                "pii.detected",
                source=source,
                context=context,
                match_count=len(result.matches_found),
                pii_types=pii_types,
            )
            logger.info(
                "PIIRedactorIntegration: detected %d PII span(s) in context '%s': %s",
                len(result.matches_found),
                context,
                pii_types,
            )

        await self._aumos.events.publish_simple(
            "pii.redacted",
            source=source,
            context=context,
            redactions_applied=result.redactions_applied,
            original_length=result.original_length,
            redacted_length=len(result.redacted_text),
        )

        await self._aumos.events.publish_simple(
            "scan.completed",
            source=source,
            context=context,
            safe=result.redactions_applied == 0,
            redactions_applied=result.redactions_applied,
        )

        return result

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _handle_text_submitted(self, event: Event) -> None:
        """Automatically redact PII when text is submitted by an agent.

        Expected event payload keys:
            - ``text`` (str): The text to redact.
            - ``context`` (str, optional): Source context label.

        Missing or invalid payloads are logged as warnings and skipped.

        Args:
            event: The ``agent.text_submitted`` event received from the bus.
        """
        text = event.data.get("text")
        context = str(event.data.get("context", "agent.text_submitted"))

        if not isinstance(text, str):
            logger.warning(
                "PIIRedactorIntegration: received 'agent.text_submitted' event "
                "without a valid 'text' string payload — skipping auto-redaction."
            )
            return

        logger.info(
            "PIIRedactorIntegration: auto-redacting text from event source '%s' "
            "in context '%s'",
            event.source,
            context,
        )
        await self.redact_and_publish(
            text=text,
            context=context,
            source=_SERVICE_NAME,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_registered(self) -> bool:
        """``True`` when the service has been registered with AumOS."""
        return self._registered

    @property
    def aumos(self) -> AumOS:
        """The AumOS hub this integration is bound to."""
        return self._aumos

    @property
    def capability_cache(self) -> list[str]:
        """Cache of capability names from received events."""
        return list(self._capability_cache)


async def setup_pii_redactor(
    aumos: AumOS,
    *,
    redaction_config: RedactionConfig | None = None,
) -> PIIRedactorIntegration:
    """Convenience function: create and register a :class:`PIIRedactorIntegration`.

    Args:
        aumos: The AumOS hub to register with.
        redaction_config: Optional redaction configuration.

    Returns:
        The registered :class:`PIIRedactorIntegration` instance.

    Example::

        hub = AumOS()
        integration = await setup_pii_redactor(hub)
    """
    integration = PIIRedactorIntegration.from_aumos(
        aumos, redaction_config=redaction_config
    )
    await integration.register()
    return integration


__all__ = [
    "PIIRedactorIntegration",
    "setup_pii_redactor",
    "_SERVICE_CAPABILITIES",
    "_SERVICE_NAME",
    "_SERVICE_VERSION",
]
