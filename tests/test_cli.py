"""Tests for aumai_pii_redactor.cli — Click command interface."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from aumai_pii_redactor.cli import _default_config, _load_config, main
from aumai_pii_redactor.models import RedactionStrategy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_temp_text(content: str, suffix: str = ".txt") -> str:
    """Write *content* to a temp file and return the path string."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    tmp.write(content)
    tmp.flush()
    tmp.close()
    return tmp.name


def _write_temp_json_config(config_dict: dict) -> str:  # type: ignore[type-arg]
    raw = json.dumps(config_dict)
    return _write_temp_text(raw, suffix=".json")


# ---------------------------------------------------------------------------
# Version / help
# ---------------------------------------------------------------------------


class TestVersionAndHelp:
    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "redact" in result.output

    def test_scan_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--input" in result.output

    def test_redact_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["redact", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


class TestScanCommand:
    def test_scan_detects_email(self) -> None:
        path = _write_temp_text("Contact alice@example.com for info.")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", path])
        assert result.exit_code == 0
        assert "email" in result.output

    def test_scan_no_pii_reports_none(self) -> None:
        path = _write_temp_text("No personal data here at all.")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", path])
        assert result.exit_code == 0
        assert "No PII detected" in result.output

    def test_scan_json_output_valid_json(self) -> None:
        path = _write_temp_text("user@example.com")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", path, "--json-output"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) >= 1
        assert parsed[0]["pii_type"] == "email"

    def test_scan_json_output_no_pii_returns_empty_list(self) -> None:
        path = _write_temp_text("nothing sensitive here")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", path, "--json-output"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed == []

    def test_scan_shows_count_in_output(self) -> None:
        path = _write_temp_text("alice@example.com and bob@example.com")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", path])
        assert result.exit_code == 0
        assert "PII match" in result.output

    def test_scan_shows_position_and_confidence(self) -> None:
        path = _write_temp_text("user@example.com")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", path])
        assert result.exit_code == 0
        assert "pos=" in result.output
        assert "confidence=" in result.output

    def test_scan_missing_input_fails(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", "/nonexistent/path/file.txt"])
        assert result.exit_code != 0

    def test_scan_with_json_config(self) -> None:
        config = {
            "default_strategy": "mask",
            "rules": [],
            "custom_patterns": {},
        }
        config_path = _write_temp_json_config(config)
        input_path = _write_temp_text("Call 555-123-4567")
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--input", input_path, "--config", config_path]
        )
        assert result.exit_code == 0
        assert "phone" in result.output

    def test_scan_json_output_contains_required_fields(self) -> None:
        path = _write_temp_text("123-45-6789")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", path, "--json-output"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed  # non-empty
        item = parsed[0]
        assert "pii_type" in item
        assert "start" in item
        assert "end" in item
        assert "original_text" in item
        assert "confidence" in item


# ---------------------------------------------------------------------------
# redact command
# ---------------------------------------------------------------------------


class TestRedactCommand:
    def test_redact_email_default_mask(self) -> None:
        input_path = _write_temp_text("Email: user@example.com")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path],
        )
        assert result.exit_code == 0
        output_text = Path(output_path).read_text(encoding="utf-8")
        assert "user@example.com" not in output_text

    def test_redact_reports_count(self) -> None:
        input_path = _write_temp_text("alice@corp.com and bob@corp.com")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path],
        )
        assert result.exit_code == 0
        assert "Redacted" in result.output

    def test_redact_reports_output_path(self) -> None:
        input_path = _write_temp_text("SSN: 123-45-6789")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path],
        )
        assert result.exit_code == 0
        assert "Output written to" in result.output

    def test_redact_hash_strategy_flag(self) -> None:
        input_path = _write_temp_text("user@example.com")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path, "--strategy", "hash"],
        )
        assert result.exit_code == 0
        output_text = Path(output_path).read_text(encoding="utf-8")
        assert "user@example.com" not in output_text

    def test_redact_remove_strategy_flag(self) -> None:
        input_path = _write_temp_text("user@example.com")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path, "--strategy", "remove"],
        )
        assert result.exit_code == 0
        output_text = Path(output_path).read_text(encoding="utf-8")
        assert "user@example.com" not in output_text

    def test_redact_replace_strategy_flag(self) -> None:
        input_path = _write_temp_text("user@example.com")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path, "--strategy", "replace"],
        )
        assert result.exit_code == 0
        output_text = Path(output_path).read_text(encoding="utf-8")
        assert "user@example.com" not in output_text
        assert "[REDACTED]" in output_text

    def test_redact_invalid_strategy_fails(self) -> None:
        input_path = _write_temp_text("user@example.com")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "redact",
                "--input", input_path,
                "--output", output_path,
                "--strategy", "explode",
            ],
        )
        assert result.exit_code != 0

    def test_redact_with_json_config(self) -> None:
        config = {
            "default_strategy": "remove",
            "rules": [],
            "custom_patterns": {},
        }
        config_path = _write_temp_json_config(config)
        input_path = _write_temp_text("SSN: 123-45-6789")
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path, "--config", config_path],
        )
        assert result.exit_code == 0
        output_text = Path(output_path).read_text(encoding="utf-8")
        assert "123-45-6789" not in output_text

    def test_redact_clean_file_unchanged(self) -> None:
        clean = "Nothing sensitive here."
        input_path = _write_temp_text(clean)
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        runner.invoke(
            main,
            ["redact", "--input", input_path, "--output", output_path],
        )
        output_text = Path(output_path).read_text(encoding="utf-8")
        assert output_text == clean

    def test_redact_missing_input_fails(self) -> None:
        output_path = _write_temp_text("", suffix=".txt")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["redact", "--input", "/no/such/file.txt", "--output", output_path],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# configure command
# ---------------------------------------------------------------------------


class TestConfigureCommand:
    def test_configure_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "config.json")
            runner = CliRunner()
            result = runner.invoke(main, ["configure", "--output", out_path])
            assert result.exit_code == 0
            assert Path(out_path).exists()
            data = json.loads(Path(out_path).read_text(encoding="utf-8"))
            assert "default_strategy" in data
            assert "rules" in data
            assert "custom_patterns" in data

    def test_configure_json_rules_non_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "cfg.json")
            runner = CliRunner()
            runner.invoke(main, ["configure", "--output", out_path])
            data = json.loads(Path(out_path).read_text(encoding="utf-8"))
            assert len(data["rules"]) > 0

    def test_configure_output_path_in_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "config.json")
            runner = CliRunner()
            result = runner.invoke(main, ["configure", "--output", out_path])
            assert result.exit_code == 0
            assert "config" in result.output.lower()

    def test_configure_default_strategy_is_mask(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "out.json")
            runner = CliRunner()
            runner.invoke(main, ["configure", "--output", out_path])
            data = json.loads(Path(out_path).read_text(encoding="utf-8"))
            assert data["default_strategy"] == "mask"

    def test_configure_writes_yaml_when_pyyaml_available(self) -> None:
        pytest.importorskip("yaml")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "config.yaml")
            runner = CliRunner()
            result = runner.invoke(main, ["configure", "--output", out_path])
            assert result.exit_code == 0
            assert Path(out_path).exists()
            # YAML file must be parseable by PyYAML
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(Path(out_path).read_text(encoding="utf-8"))
            assert "default_strategy" in data
            assert "rules" in data


# ---------------------------------------------------------------------------
# _load_config / _default_config helpers
# ---------------------------------------------------------------------------


class TestLoadConfigHelper:
    def test_load_json_config(self) -> None:
        config_dict = {
            "default_strategy": "hash",
            "rules": [],
            "custom_patterns": {},
        }
        path = _write_temp_json_config(config_dict)
        config = _load_config(path)
        assert config.default_strategy == RedactionStrategy.hash

    def test_load_yaml_config(self) -> None:
        pytest.importorskip("yaml")
        import yaml  # type: ignore[import-untyped]
        config_dict = {
            "default_strategy": "remove",
            "rules": [],
            "custom_patterns": {},
        }
        raw = yaml.dump(config_dict)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(raw)
            yaml_path = f.name
        config = _load_config(yaml_path)
        assert config.default_strategy == RedactionStrategy.remove

    def test_default_config_has_mask_strategy(self) -> None:
        config = _default_config()
        assert config.default_strategy == RedactionStrategy.mask
        assert config.rules == []
        assert config.custom_patterns == {}

    def test_scan_with_yaml_config(self) -> None:
        pytest.importorskip("yaml")
        import yaml  # type: ignore[import-untyped]
        config_dict = {
            "default_strategy": "mask",
            "rules": [],
            "custom_patterns": {},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(yaml.dump(config_dict))
            yaml_path = f.name
        input_path = _write_temp_text("Call 555-123-4567")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--input", input_path, "--config", yaml_path])
        assert result.exit_code == 0
        assert "phone" in result.output

    def test_load_yaml_config_without_pyyaml_exits(self) -> None:
        """_load_config must exit with error message when PyYAML is missing for .yaml files."""
        import unittest.mock as _mock

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write("default_strategy: mask\nrules: []\ncustom_patterns: {}\n")
            yaml_path = f.name

        # Patch 'import yaml' to raise ImportError inside the CLI module
        with _mock.patch.dict("sys.modules", {"yaml": None}):
            runner = CliRunner()
            result = runner.invoke(main, ["scan", "--input", yaml_path, "--config", yaml_path])
            # CLI should have called sys.exit(1) via click.echo + sys.exit
            assert result.exit_code != 0

    def test_configure_yaml_falls_back_to_json_without_pyyaml(self) -> None:
        """configure_command must fall back to JSON when PyYAML is missing."""
        import unittest.mock as _mock

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "config.yaml")
            with _mock.patch.dict("sys.modules", {"yaml": None}):
                runner = CliRunner()
                result = runner.invoke(main, ["configure", "--output", out_path])
                assert result.exit_code == 0
            # JSON fallback file must exist
            json_path = Path(out_path).with_suffix(".json")
            assert json_path.exists()
            data = json.loads(json_path.read_text(encoding="utf-8"))
            assert "default_strategy" in data
