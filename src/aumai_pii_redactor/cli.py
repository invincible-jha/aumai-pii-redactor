"""CLI entry point for aumai-pii-redactor."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from aumai_pii_redactor.detector import PIIDetector
from aumai_pii_redactor.models import (
    RedactionConfig,
    RedactionRule,
    RedactionStrategy,
)
from aumai_pii_redactor.redactor import PIIRedactor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config(config_path: str) -> RedactionConfig:
    """Load a :class:`RedactionConfig` from a YAML or JSON file."""
    file_path = Path(config_path)
    raw = file_path.read_text(encoding="utf-8")
    if file_path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
            data: dict[str, Any] = yaml.safe_load(raw)
        except ImportError:
            click.echo("PyYAML required for YAML config. Install: pip install pyyaml", err=True)
            sys.exit(1)
    else:
        data = json.loads(raw)
    return RedactionConfig(**data)


def _default_config() -> RedactionConfig:
    return RedactionConfig(
        rules=[],
        default_strategy=RedactionStrategy.mask,
        custom_patterns={},
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option()
def main() -> None:
    """AumAI PII Redactor — detect and redact PII in agent telemetry."""


@main.command("scan")
@click.option("--input", "input_path", required=True, metavar="PATH", help="Text file to scan.")
@click.option("--config", "config_path", default=None, metavar="PATH", help="Redaction config file.")
@click.option("--json-output", is_flag=True, help="Emit results as JSON.")
def scan_command(input_path: str, config_path: str | None, json_output: bool) -> None:
    """Scan a text file for PII and report all matches."""
    config = _load_config(config_path) if config_path else _default_config()
    detector = PIIDetector(config)

    text = Path(input_path).read_text(encoding="utf-8")
    matches = detector.detect(text)

    if json_output:
        output = [m.model_dump(mode="json") for m in matches]
        click.echo(json.dumps(output, indent=2))
        return

    if not matches:
        click.echo("No PII detected.")
        return

    click.echo(f"Found {len(matches)} PII match(es):\n")
    for match in matches:
        snippet = match.original_text[:40]
        click.echo(
            f"  [{match.pii_type.value}]  "
            f"pos={match.start}-{match.end}  "
            f"confidence={match.confidence:.2f}  "
            f'"{snippet}"'
        )


@main.command("redact")
@click.option("--input", "input_path", required=True, metavar="PATH", help="Input text file.")
@click.option("--output", "output_path", required=True, metavar="PATH", help="Output text file.")
@click.option("--config", "config_path", default=None, metavar="PATH", help="Redaction config file.")
@click.option("--strategy", type=click.Choice(["mask", "hash", "remove", "replace"]), default="mask", show_default=True)
def redact_command(
    input_path: str,
    output_path: str,
    config_path: str | None,
    strategy: str,
) -> None:
    """Redact PII from a text file and write the result to a new file."""
    if config_path:
        config = _load_config(config_path)
    else:
        config = RedactionConfig(
            default_strategy=RedactionStrategy(strategy),
        )

    redactor = PIIRedactor(config)
    text = Path(input_path).read_text(encoding="utf-8")
    result = redactor.redact(text)

    Path(output_path).write_text(result.redacted_text, encoding="utf-8")

    click.echo(f"Redacted {result.redactions_applied} PII instance(s).")
    click.echo(f"Output written to: {output_path}")


@main.command("configure")
@click.option(
    "--output",
    default="rules.yaml",
    show_default=True,
    metavar="PATH",
    help="Path to write the default config.",
)
def configure_command(output: str) -> None:
    """Generate a default redaction config file."""
    out_path = Path(output)

    if out_path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
            config_dict: dict[str, Any] = {
                "default_strategy": "mask",
                "rules": [
                    {"pii_type": "email", "strategy": "mask"},
                    {"pii_type": "phone", "strategy": "mask"},
                    {"pii_type": "ssn", "strategy": "replace", "replacement": "[SSN REDACTED]"},
                    {"pii_type": "credit_card", "strategy": "replace", "replacement": "[CARD REDACTED]"},
                    {"pii_type": "ip_address", "strategy": "hash"},
                ],
                "custom_patterns": {},
            }
            out_path.write_text(yaml.dump(config_dict, default_flow_style=False), encoding="utf-8")
        except ImportError:
            click.echo("PyYAML required. Falling back to JSON.", err=True)
            out_path = out_path.with_suffix(".json")

    if out_path.suffix == ".json":
        config_json: dict[str, Any] = {
            "default_strategy": "mask",
            "rules": [
                {"pii_type": "email", "strategy": "mask"},
                {"pii_type": "phone", "strategy": "mask"},
                {"pii_type": "ssn", "strategy": "replace", "replacement": "[SSN REDACTED]"},
                {"pii_type": "credit_card", "strategy": "replace", "replacement": "[CARD REDACTED]"},
                {"pii_type": "ip_address", "strategy": "hash"},
            ],
            "custom_patterns": {},
        }
        out_path.write_text(json.dumps(config_json, indent=2), encoding="utf-8")

    click.echo(f"Default config written to: {out_path}")


if __name__ == "__main__":
    main()
