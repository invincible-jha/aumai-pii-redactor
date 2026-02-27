# API Reference — aumai-pii-redactor

Complete reference for every public class, function, and Pydantic model.
All symbols are importable from the top-level package:

```python
from aumai_pii_redactor import (
    PIIDetector, PIIRedactor, PIIRedactingSpanProcessor,
    PIIMatch, PIIType, RedactionConfig, RedactionResult,
    RedactionRule, RedactionStrategy,
)
```

---

## Enumerations

### `PIIType`

```python
class PIIType(str, Enum):
    email        = "email"
    phone        = "phone"
    ssn          = "ssn"
    credit_card  = "credit_card"
    ip_address   = "ip_address"
    name         = "name"
    address      = "address"
    date_of_birth = "date_of_birth"
    passport     = "passport"
    custom       = "custom"
```

Categories of personally identifiable information. Built-in detection patterns
exist for: `email`, `phone`, `ssn`, `credit_card`, `ip_address`, `date_of_birth`,
`passport`. Custom regex patterns registered via `RedactionConfig.custom_patterns`
use the `custom` type. `name` and `address` are defined for future use.

---

### `RedactionStrategy`

```python
class RedactionStrategy(str, Enum):
    mask    = "mask"
    hash    = "hash"
    remove  = "remove"
    replace = "replace"
```

Determines how a detected PII span is replaced.

| Strategy | Behaviour | Example input | Example output |
|---|---|---|---|
| `mask` | Keep first and last character; fill middle with `***` | `alice@corp.com` | `a***m` |
| `hash` | First 12 hex chars of SHA-256 digest of the original text | `alice@corp.com` | `3d4e5f6a7b8c` |
| `remove` | Replace with an empty string | `alice@corp.com` | `` |
| `replace` | Replace with a fixed literal string (set `RedactionRule.replacement`) | `alice@corp.com` | `[EMAIL]` |

---

## Pydantic Models

---

### `PIIMatch`

```python
class PIIMatch(BaseModel):
    pii_type: PIIType
    start: int           # Field(ge=0)
    end: int             # Field(ge=0)
    original_text: str
    confidence: float    # Field(ge=0.0, le=1.0)
```

A single detected PII span within a text string. Returned by
`PIIDetector.detect` and stored in `RedactionResult.matches_found`.

| Field | Type | Description |
|---|---|---|
| `pii_type` | `PIIType` | Category of PII detected |
| `start` | `int` | Start index (inclusive) in the original string |
| `end` | `int` | End index (exclusive) in the original string |
| `original_text` | `str` | The matched substring |
| `confidence` | `float` | Confidence score in `[0.0, 1.0]` |

**Example:**

```python
from aumai_pii_redactor import PIIDetector, RedactionConfig

detector = PIIDetector(RedactionConfig())
matches = detector.detect("Email: bob@corp.com")
match = matches[0]
print(match.pii_type)        # PIIType.email
print(match.start, match.end) # 7, 19
print(match.original_text)   # bob@corp.com
print(match.confidence)      # 0.99
```

---

### `RedactionRule`

```python
class RedactionRule(BaseModel):
    pii_type: PIIType
    strategy: RedactionStrategy
    replacement: str | None = None
```

Maps a PII type to a specific redaction strategy. When `strategy` is `replace`,
set `replacement` to the literal string that will substitute the PII span.
If `replacement` is `None` with `strategy=replace`, the output is `[REDACTED]`.

| Field | Type | Description |
|---|---|---|
| `pii_type` | `PIIType` | The PII type this rule applies to |
| `strategy` | `RedactionStrategy` | How to redact matching spans |
| `replacement` | `str \| None` | Literal replacement string (only used with `replace` strategy) |

**Example:**

```python
from aumai_pii_redactor import PIIType, RedactionRule, RedactionStrategy

rule = RedactionRule(
    pii_type=PIIType.ssn,
    strategy=RedactionStrategy.replace,
    replacement="[SSN REDACTED]",
)
```

---

### `RedactionConfig`

```python
class RedactionConfig(BaseModel):
    rules: list[RedactionRule]            # default_factory=list
    default_strategy: RedactionStrategy   # default: mask
    custom_patterns: dict[str, str]       # default_factory=dict
```

Top-level configuration for the detection and redaction engine. Passed to
`PIIDetector`, `PIIRedactor`, and `PIIRedactingSpanProcessor`.

| Field | Type | Description |
|---|---|---|
| `rules` | `list[RedactionRule]` | Per-type redaction overrides; highest specificity wins |
| `default_strategy` | `RedactionStrategy` | Strategy used for any PII type not covered by `rules` |
| `custom_patterns` | `dict[str, str]` | Mapping of custom label to raw regex pattern string |

**Notes:**

- `rules` is a list; the **last** rule for a given `pii_type` wins if duplicates exist
  (use a dict-like structure internally via `{rule.pii_type: rule}` lookup).
- `custom_patterns` keys are arbitrary strings used as labels; all custom matches
  receive `PIIType.custom`.
- Custom patterns are compiled with `re.compile` at `PIIDetector` construction time;
  invalid regex strings raise `re.error`.

**Example:**

```python
from aumai_pii_redactor import (
    PIIType, RedactionConfig, RedactionRule, RedactionStrategy,
)

config = RedactionConfig(
    default_strategy=RedactionStrategy.mask,
    rules=[
        RedactionRule(pii_type=PIIType.ssn, strategy=RedactionStrategy.replace,
                      replacement="[SSN]"),
        RedactionRule(pii_type=PIIType.credit_card, strategy=RedactionStrategy.remove),
    ],
    custom_patterns={
        "employee_id": r"\bEMP-\d{5}\b",
    },
)
```

---

### `RedactionResult`

```python
class RedactionResult(BaseModel):
    original_length: int         # Field(ge=0)
    redacted_text: str
    matches_found: list[PIIMatch]  # default_factory=list
    redactions_applied: int      # Field(ge=0)
```

Summary of a single `PIIRedactor.redact` operation.

| Field | Type | Description |
|---|---|---|
| `original_length` | `int` | Character length of the input string |
| `redacted_text` | `str` | The input string with all PII replaced |
| `matches_found` | `list[PIIMatch]` | All detected PII matches (sorted by start position) |
| `redactions_applied` | `int` | Number of PII spans that were replaced |

**Example:**

```python
from aumai_pii_redactor import PIIRedactor, RedactionConfig

redactor = PIIRedactor(RedactionConfig())
result = redactor.redact("Call 555-123-4567 or email me@corp.com")
print(result.redacted_text)        # Call 5***7 or email m***m
print(result.redactions_applied)  # 2
print(result.original_length)     # 38
```

---

## Classes

### `PIIDetector`

```python
class PIIDetector:
    def __init__(self, config: RedactionConfig) -> None: ...

    def detect(self, text: str) -> list[PIIMatch]: ...

    def detect_in_dict(
        self, data: dict[str, object]
    ) -> dict[str, list[PIIMatch]]: ...
```

Detects PII spans in text using compiled regular expressions.

---

#### `PIIDetector.__init__`

```python
def __init__(self, config: RedactionConfig) -> None
```

Compile all custom patterns from `config.custom_patterns` at construction time.
Built-in patterns are pre-compiled module-level constants and are shared across
all `PIIDetector` instances.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `config` | `RedactionConfig` | Configuration including custom patterns |

**Raises:** `re.error` if any value in `config.custom_patterns` is not a valid regex.

---

#### `PIIDetector.detect`

```python
def detect(self, text: str) -> list[PIIMatch]
```

Find all PII spans in `text`. Results are deduplicated by span (same start/end
position) and sorted by start position.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `text` | `str` | The input text to scan |

**Returns:** Sorted list of `PIIMatch` objects. Empty list if no PII found.

**Example:**

```python
from aumai_pii_redactor import PIIDetector, RedactionConfig

detector = PIIDetector(RedactionConfig())
matches = detector.detect("SSN: 123-45-6789, email: test@example.com")
for m in matches:
    print(f"{m.pii_type.value}: {m.original_text!r}")
# ssn: '123-45-6789'
# email: 'test@example.com'
```

---

#### `PIIDetector.detect_in_dict`

```python
def detect_in_dict(
    self, data: dict[str, object]
) -> dict[str, list[PIIMatch]]
```

Recursively traverse `data` and detect PII in all string leaf values.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `data` | `dict[str, object]` | Nested dict/list structure to scan |

**Returns:** Dict mapping dotted key paths (e.g. `"user.email"`, `"items[0].text"`)
to the list of PII matches found in that value. Only paths with at least one match
are included.

**Example:**

```python
from aumai_pii_redactor import PIIDetector, RedactionConfig

detector = PIIDetector(RedactionConfig())
data = {
    "user": {"email": "alice@corp.com", "age": 30},
    "tools": [{"output": "IP: 10.0.0.1"}],
}
results = detector.detect_in_dict(data)
print(list(results.keys()))
# ['user.email', 'tools[0].output']
```

---

### `PIIRedactor`

```python
class PIIRedactor:
    def __init__(self, config: RedactionConfig) -> None: ...

    def redact(self, text: str) -> RedactionResult: ...

    def redact_dict(self, data: dict[str, object]) -> dict[str, object]: ...
```

Detects and redacts PII from text strings or nested dicts using the strategies
defined in `RedactionConfig`.

---

#### `PIIRedactor.__init__`

```python
def __init__(self, config: RedactionConfig) -> None
```

Build a `PIIDetector` and a rule lookup dict from `config`.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `config` | `RedactionConfig` | Redaction rules and strategy configuration |

---

#### `PIIRedactor.redact`

```python
def redact(self, text: str) -> RedactionResult
```

Detect all PII in `text` and replace each span according to the configured
strategy. Overlapping spans are handled by processing matches in **reverse order**
so that character positions remain valid throughout.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `text` | `str` | The input text to redact |

**Returns:** `RedactionResult` containing the redacted text, all matches, and a
count of applied redactions.

**Example:**

```python
from aumai_pii_redactor import PIIRedactor, RedactionConfig

redactor = PIIRedactor(RedactionConfig())
result = redactor.redact("Contact: support@example.com / 555-100-2000")
print(result.redacted_text)       # Contact: s***m / 5***0
print(result.redactions_applied)  # 2
```

---

#### `PIIRedactor.redact_dict`

```python
def redact_dict(self, data: dict[str, object]) -> dict[str, object]
```

Recursively redact all string values in `data`. The original dict is not mutated;
a new structure is returned. Non-string leaf values (int, float, bool, None) are
copied unchanged.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `data` | `dict[str, object]` | Nested dict/list to redact |

**Returns:** A new dict with the same structure but all string leaves redacted.

**Example:**

```python
from aumai_pii_redactor import PIIRedactor, RedactionConfig

redactor = PIIRedactor(RedactionConfig())
span_attrs = {
    "user.email": "alice@corp.com",
    "http.status": 200,
    "nested": {"ip": "10.0.0.1"},
}
clean = redactor.redact_dict(span_attrs)
# {"user.email": "a***m", "http.status": 200, "nested": {"ip": "1***1"}}
```

---

### `PIIRedactingSpanProcessor`

```python
class PIIRedactingSpanProcessor:
    def __init__(self, config: RedactionConfig | None = None) -> None: ...

    def on_start(self, span: Span, parent_context: Context | None = None) -> None: ...
    def on_end(self, span: ReadableSpan) -> None: ...
    def shutdown(self) -> None: ...
    def force_flush(self, timeout_millis: int = 30_000) -> bool: ...
```

OpenTelemetry `SpanProcessor` that redacts PII from all string span attributes
before they reach any downstream exporter.

**Requires:** `opentelemetry-sdk` (`pip install opentelemetry-sdk`).

---

#### `PIIRedactingSpanProcessor.__init__`

```python
def __init__(self, config: RedactionConfig | None = None) -> None
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `config` | `RedactionConfig \| None` | Redaction config; defaults to `RedactionConfig()` (all built-in patterns, mask strategy) |

---

#### `PIIRedactingSpanProcessor.on_start`

```python
def on_start(
    self,
    span: Span,
    parent_context: Context | None = None,
) -> None
```

No-op. PII redaction is applied on span end, not on start, so that all attributes
set during the span's lifetime are captured.

---

#### `PIIRedactingSpanProcessor.on_end`

```python
def on_end(self, span: ReadableSpan) -> None
```

Redact PII from all string attributes on the finished span. The span's internal
`_attributes` dict is mutated in-place so downstream exporters receive clean data.
Non-string attribute values are left unchanged.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `span` | `ReadableSpan` | The finished OTel span |

**Example:**

```python
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from aumai_pii_redactor import PIIRedactingSpanProcessor, RedactionConfig

exporter = InMemorySpanExporter()
provider = TracerProvider()
provider.add_span_processor(PIIRedactingSpanProcessor(RedactionConfig()))
provider.add_span_processor(BatchSpanProcessor(exporter))

tracer = provider.get_tracer("test")
with tracer.start_as_current_span("my-span") as span:
    span.set_attribute("user.email", "alice@example.com")

spans = exporter.get_finished_spans()
print(spans[0].attributes["user.email"])  # "a***m"
```

---

#### `PIIRedactingSpanProcessor.shutdown`

```python
def shutdown(self) -> None
```

No-op. No resources to release.

---

#### `PIIRedactingSpanProcessor.force_flush`

```python
def force_flush(self, timeout_millis: int = 30_000) -> bool
```

No-op (synchronous processor). Returns `True` immediately.

---

## Built-in PII Patterns

The following patterns are compiled once at module import time and applied to every
`PIIDetector.detect` call. They are defined in `detector.py` as `_BUILTIN_PATTERNS`.

| PII Type | Pattern description | Confidence | Notes |
|---|---|---|---|
| `ssn` | `\b(?!000\|666\|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b` | 0.90 | Excludes invalid SSA area/group/serial numbers |
| `credit_card` | `\b(?:\d{4}[\s\-]?){3}\d{4}\b` | 0.90 base | +0.08 if Luhn-valid; -0.30 if Luhn-invalid |
| `email` | RFC-5321 local part + `@` + domain | 0.99 | Case-insensitive |
| `phone` | US/North American + E.164 international | 0.85 | Various separator formats |
| `ip_address` (IPv6) | Full and compressed IPv6 notation | 0.98 | Matched before IPv4 |
| `ip_address` (IPv4) | `0-255` octet-validated quad | 0.95 | |
| `passport` | `[A-Z]{1,2}\d{6,9}` | 0.70 | Low confidence; high false-positive risk |
| `date_of_birth` | `MM/DD/YYYY` and `MM-DD-YYYY` for 1900-2099 | 0.80 | |

---

## Internal Implementation Notes

### Strategy dispatch (`redactor.py`)

The four strategy functions are module-level:

```python
def _apply_mask(text: str) -> str:
    # len <= 2: all asterisks; otherwise first + "***" + last
    ...

def _apply_hash(text: str) -> str:
    # SHA-256 hex digest, first 12 chars
    ...

def _apply_remove(_text: str) -> str:
    return ""

def _apply_replace(text: str, replacement: str | None) -> str:
    return replacement if replacement is not None else "[REDACTED]"
```

### Dict flattening (`detector.py`)

`_flatten_dict` is a recursive generator that yields `(dotted_path, leaf_value)`
pairs. List indices are formatted as `path[0]`, `path[1]`, etc.

### Luhn validation (`detector.py`)

`_luhn_valid(number_str: str) -> bool` strips all non-digit characters and applies
the standard Luhn checksum algorithm. Called only for `credit_card` matches.
