"""Tests for the OSINT report CLI wrapper."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import osint_report_cli


def _payload() -> dict:
    return {
        "report_id": "osint-cli-001",
        "generated_at": "2026-04-18T12:00:00+00:00",
        "subject": "CLI validation test",
        "objective": "Validate and render a defensive OSINT report.",
        "authorized_scope": True,
        "summary": "This payload exists to exercise the CLI wrapper.",
        "indicators": [
            {
                "type": "domain",
                "value": "phish-login-support.com",
                "confidence": 0.9,
                "tags": ["phishing"],
            }
        ],
        "findings": [
            {
                "title": "Example finding",
                "summary": "The sample domain matches a suspicious naming convention.",
                "severity": "medium",
                "confidence": 0.75,
                "indicator_refs": ["phish-login-support.com"],
                "evidence": [
                    {
                        "source_name": "Passive DNS",
                        "source_url": "https://intel.example/pdns/domain",
                        "collected_at": "2026-04-18T11:30:00+00:00",
                        "detail": "Observed during testing.",
                    }
                ],
                "recommendations": ["Block and monitor the domain."],
            }
        ],
        "next_steps": ["Share the report with the blue team."],
    }


def test_cli_renders_markdown_to_stdout(tmp_path, capsys):
    input_path = tmp_path / "report.json"
    input_path.write_text(json.dumps(_payload()), encoding="utf-8")

    exit_code = osint_report_cli.main([str(input_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Defensive OSINT Report" in output
    assert "CLI validation test" in output


def test_cli_writes_json_output_file(tmp_path, capsys):
    input_path = tmp_path / "report.json"
    output_path = tmp_path / "report.out.json"
    input_path.write_text(json.dumps(_payload()), encoding="utf-8")

    exit_code = osint_report_cli.main([str(input_path), "--json", "--output", str(output_path)])
    output = capsys.readouterr().out
    parsed = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert f"Wrote {output_path}" in output
    assert parsed["report_id"] == "osint-cli-001"
    assert parsed["schema_version"] == "1.0.0"


def test_cli_rejects_missing_input_file(capsys):
    exit_code = osint_report_cli.main(["/tmp/does-not-exist-report.json"])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Input file not found" in output


def test_cli_rejects_invalid_json(tmp_path, capsys):
    input_path = tmp_path / "report.json"
    input_path.write_text("{bad json", encoding="utf-8")

    exit_code = osint_report_cli.main([str(input_path)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Invalid JSON" in output


def test_cli_rejects_validation_errors(tmp_path, capsys):
    invalid_payload = _payload()
    invalid_payload["authorized_scope"] = False
    input_path = tmp_path / "report.json"
    input_path.write_text(json.dumps(invalid_payload), encoding="utf-8")

    exit_code = osint_report_cli.main([str(input_path)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Report validation failed" in output
