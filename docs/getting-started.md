# Getting Started with aumai-pii-redactor

This guide walks you from install through your first redaction, the OTel integration,
and the most common real-world patterns.

---

## Prerequisites

- **Python 3.11 or later**
- For YAML config files: `pip install pyyaml`
- For the OTel span processor: `pip install opentelemetry-sdk`

---

## Installation

### From PyPI (recommended)

```bash
pip install aumai-pii-redactor
```

Verify:

```bash
aumai-pii-redactor --version
# aumai-pii-redactor, version 0.1.0
```

### With optional dependencies

```bash
# YAML config support
pip install aumai-pii-redactor pyyaml

# OTel integration
pip install aumai-pii-redactor opentelemetry-sdk
```

### From source

```bash
git clone https://github.com/aumai/aumai-pii-redactor.git
cd aumai-pii-redactor
pip install -e .
```

### Development mode

```bash
git clone https://github.com/aumai/aumai-pii-redactor.git
cd aumai-pii-redactor
pip install -e ".[dev]"
make lint test
```

---

## Your First Redaction

This tutorial takes five minutes and demonstrates detection, redaction, and the OTel
processor.

### Step 1 — Create a sample file with PII

```bash
cat > /tmp/agent-log.txt << 'EOF'
[2024-01-15 10:23:41] Tool call: lookup_user
  Input: {"query": "alice@example.com"}
  Output: {"name": "Alice Smith", "ssn": "123-45-6789", "phone": "555-867-5309"}
  Source IP: 192.168.1.42
[2024-01-15 10:23:42] Tool call complete. Credit card on file: 4111-1111-1111-1111
EOF
```

### Step 2 — Scan the file for PII

```bash
aumai-pii-redactor scan --input /tmp/agent-log.txt
```

Output:

```
Found 5 PII match(es):

  [email]       pos=41-57    confidence=0.99  "alice@example.com"
  [ssn]         pos=106-117  confidence=0.90  "123-45-6789"
  [phone]       pos=131-143  confidence=0.85  "555-867-5309"
  [ip_address]  pos=164-177  confidence=0.95  "192.168.1.42"
  [credit_card] pos=219-238  confidence=0.98  "4111-1111-1111-1111"
```

### Step 3 — Generate a config file

```bash
aumai-pii-redactor configure --output /tmp/rules.yaml
```

This produces a YAML file with sensible defaults. Edit it to add custom rules.

### Step 4 — Redact the file

```bash
aumai-pii-redactor redact \
  --input /tmp/agent-log.txt \
  --output /tmp/clean-log.txt \
  --config /tmp/rules.yaml
```

Output:

```
Redacted 5 PII instance(s).
Output written to: /tmp/clean-log.txt
```

Inspect the result:

```bash
cat /tmp/clean-log.txt
```

```
[2024-01-15 10:23:41] Tool call: lookup_user
  Input: {"query": "a***m"}
  Output: {"name": "Alice Smith", "ssn": [SSN REDACTED], "phone": "5***9"}
  Source IP: 4a3b2c1d9e8f
[2024-01-15 10:23:42] Tool call complete. Credit card on file: [CARD REDACTED]
```

---

## Common Patterns

### Pattern 1 — In-process redaction before logging

Redact before any log statement is written.

```python
import logging
from aumai_pii_redactor import PIIRedactor, RedactionConfig

config = RedactionConfig()
redactor = PIIRedactor(config)
logger = logging.getLogger("my-agent")


def safe_log(message: str) -> None:
    """Log a message after redacting PII."""
    result = redactor.redact(message)
    if result.redactions_applied:
        logger.info(result.redacted_text)
    else:
        logger.info(message)


# Usage
safe_log("Processing request from alice@example.com (192.168.1.1)")
# Logs: "Processing request from a***m (4a3b2c1d9e8f)"
```

### Pattern 2 — Redact OTel span attributes

Attach `PIIRedactingSpanProcessor` to your tracer provider so that PII is scrubbed
before any exporter sees it.

```python
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from aumai_pii_redactor import PIIRedactingSpanProcessor, RedactionConfig

config = RedactionConfig()

# IMPORTANT: Add PIIRedactingSpanProcessor BEFORE the exporting processor
provider = TracerProvider()
provider.add_span_processor(PIIRedactingSpanProcessor(config))
provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

tracer = provider.get_tracer("agent")
with tracer.start_as_current_span("user-lookup") as span:
    span.set_attribute("user.email", "alice@example.com")
    span.set_attribute("user.ip", "10.0.0.55")
    span.set_attribute("request.id", "req-abc-123")

# Console output will show redacted values for email and IP,
# but request.id is unchanged (not PII).
```

### Pattern 3 — Redact nested dicts from tool outputs

Many agent frameworks pass tool call inputs and outputs as dicts. Use
`PIIRedactor.redact_dict` to sanitise them in one call.

```python
from aumai_pii_redactor import PIIRedactor, PIIType, RedactionConfig, RedactionRule, RedactionStrategy

config = RedactionConfig(
    rules=[
        RedactionRule(pii_type=PIIType.ssn, strategy=RedactionStrategy.replace, replacement="[SSN]"),
        RedactionRule(pii_type=PIIType.credit_card, strategy=RedactionStrategy.remove),
    ],
    default_strategy=RedactionStrategy.mask,
)
redactor = PIIRedactor(config)

tool_output = {
    "user": {
        "id": 42,
        "email": "bob@corp.com",
        "ssn": "987-65-4321",
        "payment": {
            "card": "4111-1111-1111-1111",
            "expires": "12/28",
        },
    },
    "status": "found",
}

clean_output = redactor.redact_dict(tool_output)
print(clean_output)
# {
#   "user": {
#     "id": 42,                            <- int, unchanged
#     "email": "b***m",                    <- masked
#     "ssn": "[SSN]",                      <- replaced
#     "payment": {
#       "card": "",                         <- removed
#       "expires": "12/28",               <- not PII, unchanged
#     },
#   },
#   "status": "found",                    <- not PII, unchanged
# }
```

### Pattern 4 — Custom patterns for domain-specific identifiers

Add organisation-specific patterns to `RedactionConfig.custom_patterns`.

```python
from aumai_pii_redactor import PIIDetector, PIIRedactor, RedactionConfig

config = RedactionConfig(
    custom_patterns={
        # Match internal ticket IDs like TKT-2024-001234
        "ticket_id": r"\bTKT-\d{4}-\d{6}\b",
        # Match API keys in the form sk-<32 alphanumeric chars>
        "api_key": r"\bsk-[A-Za-z0-9]{32}\b",
    },
    default_strategy="replace",
)

detector = PIIDetector(config)
redactor = PIIRedactor(config)

text = "Ticket TKT-2024-001234 was opened with API key sk-abcdefghijklmnopqrstuvwxyz012345"
matches = detector.detect(text)
for m in matches:
    print(f"{m.pii_type.value}: '{m.original_text}'")

result = redactor.redact(text)
print(result.redacted_text)
# Ticket [REDACTED] was opened with API key [REDACTED]
```

### Pattern 5 — Pseudonymisation with hashing

Replace PII with consistent, non-reversible hashes. The same input always produces
the same hash output, which preserves referential integrity across log lines while
preventing reconstruction of the original value.

```python
from aumai_pii_redactor import (
    PIIRedactor, PIIType, RedactionConfig, RedactionRule, RedactionStrategy,
)

config = RedactionConfig(
    rules=[
        RedactionRule(pii_type=PIIType.email, strategy=RedactionStrategy.hash),
        RedactionRule(pii_type=PIIType.ip_address, strategy=RedactionStrategy.hash),
        RedactionRule(pii_type=PIIType.phone, strategy=RedactionStrategy.hash),
    ],
    default_strategy=RedactionStrategy.mask,
)
redactor = PIIRedactor(config)

log_lines = [
    "Request from alice@example.com, IP 10.0.0.1",
    "Follow-up from alice@example.com, IP 10.0.0.1",  # same user, same hash
]
for line in log_lines:
    print(redactor.redact(line).redacted_text)
# Request from 3d4e5f6a7b8c, IP 9f8e7d6c5b4a
# Follow-up from 3d4e5f6a7b8c, IP 9f8e7d6c5b4a  <- same hashes, traceable across lines
```

---

## Troubleshooting FAQ

**Q: `aumai-pii-redactor scan` reports no PII but I know the file contains PII**

A: The built-in patterns cover common formats. Check the specific format:
- Phone numbers must match North American or E.164 format.
- SSNs must not have an area number of `000`, `666`, or `900-999`.
- Credit cards without valid separators between groups may not match.

Use `--json-output` to get raw match data and compare with the built-in patterns
in `detector.py`. If your format is not covered, add a custom pattern via
`custom_patterns` in the config.

**Q: Credit card numbers are not being detected at high confidence**

A: Credit cards receive a `-0.30` confidence penalty if they fail the Luhn checksum.
Test card numbers (e.g. `4111-1111-1111-1111`) are Luhn-valid and receive the
+0.08 boost. Non-Luhn-valid sequences that happen to match the pattern will have
a final confidence of ~0.60.

**Q: `ImportError: cannot import name 'PIIRedactingSpanProcessor'`**

A: The OTel processor requires `opentelemetry-sdk`. Install it:

```bash
pip install opentelemetry-sdk
```

**Q: `PIIRedactingSpanProcessor` is not redacting attributes on the span**

A: Ensure the processor is added **before** any exporting processor. Span processors
run in registration order. If the exporter is added first, it will export the span
before the PII processor sees it.

**Q: `redact_dict` is not redacting values nested inside lists**

A: `redact_dict` does traverse lists. Items within lists are processed recursively.
Only non-string leaf values (integers, booleans, etc.) are left unchanged. If a list
item is itself a dict, it will be fully traversed.

**Q: The `hash` strategy produces a 12-character output. Is that enough entropy?**

A: The hash is the first 12 hex characters (48 bits) of a SHA-256 digest. This is
sufficient for pseudonymisation (preventing casual reconstruction) but not for
cryptographic security. If you need collision resistance or security guarantees,
consider a keyed HMAC or a longer truncation. For log pseudonymisation, 12 hex
characters is a pragmatic choice that keeps logs readable.

**Q: Can two different email addresses produce the same hash?**

A: In theory yes (hash collision), but SHA-256 has a collision resistance of
approximately 2^128, making practical collisions impossible. For 12-character hex
output the birthday-bound collision probability becomes significant around 2^24
(~16 million) distinct values — sufficient for typical log cardinalities.

**Q: `PyYAML required for YAML config` error when using `--config rules.yaml`**

A: Install PyYAML:

```bash
pip install pyyaml
```

Alternatively, convert your config to JSON format.
