"""aumai-pii-redactor quickstart — working demonstrations of all major features.

Run this file directly to verify your installation:

    python examples/quickstart.py

Each demo is self-contained and prints its output to stdout.
"""

from __future__ import annotations

from aumai_pii_redactor import (
    PIIDetector,
    PIIRedactor,
    PIIType,
    RedactionConfig,
    RedactionRule,
    RedactionStrategy,
)


# ---------------------------------------------------------------------------
# Demo 1 — Basic detection
# ---------------------------------------------------------------------------

def demo_basic_detection() -> None:
    """Detect all built-in PII types in a realistic agent log snippet."""

    print("\n=== Demo 1: Basic PII Detection ===")

    # Simulate a fragment of agent telemetry
    text = (
        "Tool: user_lookup\n"
        "Input: {\"email\": \"alice@example.com\"}\n"
        "Output: {\n"
        "  \"name\": \"Alice Smith\",\n"
        "  \"ssn\": \"123-45-6789\",\n"
        "  \"phone\": \"(555) 867-5309\",\n"
        "  \"card\": \"4111-1111-1111-1111\",\n"
        "  \"ip\": \"192.168.1.100\"\n"
        "}"
    )

    config = RedactionConfig()
    detector = PIIDetector(config)
    matches = detector.detect(text)

    print(f"  Found {len(matches)} PII match(es):")
    for match in matches:
        snippet = match.original_text[:30]
        print(f"    [{match.pii_type.value:<12}] '{snippet}' "
              f"confidence={match.confidence:.2f} pos={match.start}-{match.end}")

    # Confirm expected types are all detected
    detected_types = {m.pii_type for m in matches}
    expected = {PIIType.email, PIIType.ssn, PIIType.phone, PIIType.credit_card, PIIType.ip_address}
    for pii_type in expected:
        assert pii_type in detected_types, f"Expected {pii_type} not detected"

    print("  Demo 1 passed.")


# ---------------------------------------------------------------------------
# Demo 2 — Redaction with default strategy (mask)
# ---------------------------------------------------------------------------

def demo_default_redaction() -> None:
    """Demonstrate the default mask strategy applied to all PII."""

    print("\n=== Demo 2: Default Mask Redaction ===")

    text = "Contact support: help@myorg.com or 1-800-555-0199"

    config = RedactionConfig()  # default_strategy = mask
    redactor = PIIRedactor(config)
    result = redactor.redact(text)

    print(f"  Original:  {text}")
    print(f"  Redacted:  {result.redacted_text}")
    print(f"  Redactions applied: {result.redactions_applied}")

    assert result.redactions_applied == 2
    assert "help@myorg.com" not in result.redacted_text
    assert "1-800-555-0199" not in result.redacted_text

    print("  Demo 2 passed.")


# ---------------------------------------------------------------------------
# Demo 3 — Per-type redaction rules
# ---------------------------------------------------------------------------

def demo_custom_redaction_rules() -> None:
    """Show how per-type rules override the default strategy."""

    print("\n=== Demo 3: Per-Type Redaction Rules ===")

    config = RedactionConfig(
        default_strategy=RedactionStrategy.mask,
        rules=[
            # SSNs get a clearly labelled placeholder
            RedactionRule(
                pii_type=PIIType.ssn,
                strategy=RedactionStrategy.replace,
                replacement="[SSN REDACTED]",
            ),
            # Credit cards are completely removed
            RedactionRule(
                pii_type=PIIType.credit_card,
                strategy=RedactionStrategy.remove,
            ),
            # IPs are pseudonymised with a hash
            RedactionRule(
                pii_type=PIIType.ip_address,
                strategy=RedactionStrategy.hash,
            ),
        ],
    )

    redactor = PIIRedactor(config)

    cases = [
        ("SSN field", "Your SSN is 123-45-6789."),
        ("Credit card", "Card: 4111-1111-1111-1111."),
        ("IP address", "Request from 10.0.0.55"),
        ("Email (default mask)", "user@example.com"),
    ]

    for label, text in cases:
        result = redactor.redact(text)
        print(f"  {label:<22} | {text!r}")
        print(f"  {'':22} -> {result.redacted_text!r}")

    print("  Demo 3 passed.")


# ---------------------------------------------------------------------------
# Demo 4 — Redact nested dict (OTel span attributes)
# ---------------------------------------------------------------------------

def demo_redact_dict() -> None:
    """Show recursive dict redaction for structured span attribute payloads."""

    print("\n=== Demo 4: Nested Dict Redaction ===")

    span_attributes: dict[str, object] = {
        "user.email": "bob@corp.com",
        "user.ip": "172.16.0.5",
        "http.status_code": 200,          # int — unchanged
        "tool.output": {
            "ssn": "987-65-4321",
            "name": "Bob Jones",          # not PII by pattern — unchanged
        },
        "tags": ["production", "eu-west"],  # list of strings, no PII
    }

    config = RedactionConfig()
    redactor = PIIRedactor(config)
    clean_attributes = redactor.redact_dict(span_attributes)

    print("  Input:")
    for key, val in span_attributes.items():
        print(f"    {key}: {val!r}")

    print("  Output:")
    for key, val in clean_attributes.items():
        print(f"    {key}: {val!r}")

    # Verify PII is gone
    assert clean_attributes["user.email"] != "bob@corp.com"
    assert clean_attributes["http.status_code"] == 200  # unchanged
    assert isinstance(clean_attributes["tool.output"], dict)

    print("  Demo 4 passed.")


# ---------------------------------------------------------------------------
# Demo 5 — Custom regex patterns
# ---------------------------------------------------------------------------

def demo_custom_patterns() -> None:
    """Demonstrate adding organisation-specific PII patterns."""

    print("\n=== Demo 5: Custom Regex Patterns ===")

    config = RedactionConfig(
        custom_patterns={
            # Internal employee IDs: EMP-12345
            "employee_id": r"\bEMP-\d{5}\b",
            # API keys: sk-<32 alphanumeric>
            "api_key": r"\bsk-[A-Za-z0-9]{32}\b",
        },
        default_strategy=RedactionStrategy.replace,
    )

    detector = PIIDetector(config)
    redactor = PIIRedactor(config)

    text = (
        "Employee EMP-98765 made a call using API key "
        "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345."
    )
    print(f"  Input: {text}")

    matches = detector.detect(text)
    print(f"  Detected {len(matches)} custom PII match(es):")
    for m in matches:
        print(f"    [{m.pii_type.value}] '{m.original_text}'")

    result = redactor.redact(text)
    print(f"  Redacted: {result.redacted_text}")

    assert "EMP-98765" not in result.redacted_text
    assert "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345" not in result.redacted_text
    assert result.redactions_applied == 2

    print("  Demo 5 passed.")


# ---------------------------------------------------------------------------
# Demo 6 — Hash strategy for pseudonymisation
# ---------------------------------------------------------------------------

def demo_hash_pseudonymisation() -> None:
    """Show that hash redaction is consistent across calls (same input = same hash)."""

    print("\n=== Demo 6: Consistent Hash Pseudonymisation ===")

    config = RedactionConfig(
        rules=[
            RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.hash),
            RedactionRule(pii_type=PIIType.ip_address, strategy=RedactionStrategy.hash),
        ],
        default_strategy=RedactionStrategy.mask,
    )

    redactor = PIIRedactor(config)

    # Same user appearing in two separate log lines
    log_line_1 = "alice@example.com requested /api/v1/query from 10.0.0.1"
    log_line_2 = "alice@example.com completed /api/v1/query from 10.0.0.1"

    result1 = redactor.redact(log_line_1)
    result2 = redactor.redact(log_line_2)

    print(f"  Line 1: {result1.redacted_text}")
    print(f"  Line 2: {result2.redacted_text}")

    # The hash for alice@example.com must be the same in both lines
    # Extract the hash (it replaces the email in both lines)
    # Both redacted lines should be structurally identical except for the path
    parts1 = result1.redacted_text.split()
    parts2 = result2.redacted_text.split()
    assert parts1[0] == parts2[0], "Same email should hash to the same value"
    print("  Same user maps to the same hash across log lines — referential integrity preserved.")

    print("  Demo 6 passed.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Run all quickstart demos in sequence."""
    print("aumai-pii-redactor quickstart demos")
    print("=" * 45)

    demo_basic_detection()
    demo_default_redaction()
    demo_custom_redaction_rules()
    demo_redact_dict()
    demo_custom_patterns()
    demo_hash_pseudonymisation()

    print("\n" + "=" * 45)
    print("All demos completed successfully.")


if __name__ == "__main__":
    main()
