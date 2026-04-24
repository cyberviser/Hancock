import json

import pytest

from collectors.osint_guardrails import GuardrailViolation
from collectors.osint_report_builder import (
    build_report,
    main,
    render_markdown,
    summarize_report,
)


def _base_config(tmp_path):
    return {
        "profile": "joint",
        "target": "Example Corp",
        "scope": {
            "authorized_assets": ["example.com"]
        },
        "inputs": {
            "asset_inventory": str(tmp_path / "assets.json"),
            "evidence_bundle": str(tmp_path / "evidence.json"),
        },
        "engagement_defaults": {
            "requester": "Security Engineering",
            "business_owner": "Example Corp Security",
            "authorization_reference": "AUTH-001",
            "objective": "Generate a defensive exposure assessment report.",
            "report_profile": "joint",
        },
        "scope_defaults": {
            "in_scope": ["example.com"],
            "out_of_scope": [],
            "collection_constraints": ["Passive evidence only"],
            "source_policy": "approved-only",
        },
        "outputs": {
            "markdown": str(tmp_path / "report.md"),
            "json": str(tmp_path / "report.json"),
            "html": None,
        },
        "render": {
            "classification": "UNCLASSIFIED // OSINT",
            "redact_pii": True,
            "include_social_summary": True,
            "include_appendix": True,
        },
        "enrichment": {
            "geoip": True,
            "threat_intel": True,
            "historical_dns": False,
            "brand_monitoring": True,
        },
        "guardrails": {
            "authorization_required": True,
            "allow_active_collection": False,
            "forbid_dark_web_collection": True,
            "allowed_source_hosts": ["example.com"],
            "min_confidence": 60,
            "pii_policy": "mask-low-value",
        },
        "dev": {
            "lab_mode": False,
            "strict_schema_validation": True,
            "save_intermediates": True,
            "fail_on_missing_citation": True,
            "sample_limit": 100,
            "debug": False,
        },
    }


def _base_bundle():
    return {
        "assets": [
            {
                "asset_id": "A-001",
                "asset_type": "domain",
                "value": "example.com",
                "owner": "Security Engineering",
                "criticality": "high",
            }
        ],
        "findings": [
            {
                "title": "Public security contact needs rotation",
                "severity": "medium",
                "summary": "Legacy public contact information is still published in a security page.",
                "asset_refs": ["A-001"],
                "evidence_refs": ["EVID-001"],
                "confidence": 85,
                "risk_score": 5.5,
                "status": "open",
            }
        ],
        "evidence": [
            {
                "type": "web",
                "source_name": "Example Corp Security",
                "source_url": "https://example.com/security",
                "retrieved_at": "2026-04-15T00:00:00Z",
                "claim": "Contact security@example.com or +1 555 123 4567 for urgent issues.",
                "sensitivity": "public",
            }
        ],
        "recommendations": {
            "immediate": [
                {
                    "action": "Rotate the public security contact and owner metadata.",
                    "owner": "Security Engineering",
                    "priority": "P1",
                    "due_in_days": 7,
                }
            ],
            "thirty_day": [],
            "long_term": [],
        },
    }


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_build_report_redacts_low_value_pii(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()

    report = build_report(config, bundle)

    assert report.report_metadata.title == "Example Corp Exposure Assessment"
    assert report.findings[0].id == "F-001"
    assert report.evidence[0].id == "EVID-001"
    assert "[REDACTED-EMAIL]" in report.evidence[0].claim
    assert "[REDACTED-PHONE]" in report.evidence[0].claim


def test_build_report_rejects_missing_citation(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    del bundle["evidence"][0]["source_url"]

    with pytest.raises(GuardrailViolation, match="source_url and retrieved_at"):
        build_report(config, bundle)


def test_build_report_collapses_duplicate_evidence_and_renders_markdown(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["evidence"].append(dict(bundle["evidence"][0]))

    report = build_report(config, bundle)
    markdown = render_markdown(report)

    assert len(report.evidence) == 1
    assert "## Executive Summary" in markdown
    assert "## Key Findings" in markdown
    assert "## Evidence Register" in markdown


def test_guardrails_reject_active_collection_without_lab_mode(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    config["guardrails"]["allow_active_collection"] = True
    config["dev"]["lab_mode"] = False

    with pytest.raises(GuardrailViolation, match="requires dev.lab_mode=true"):
        build_report(config, bundle)


def test_guardrails_reject_disabled_dark_web_block(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    config["guardrails"]["forbid_dark_web_collection"] = False

    with pytest.raises(GuardrailViolation, match="cannot be disabled"):
        build_report(config, bundle)


def test_build_report_uses_asset_inventory_fallback(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["assets"] = []
    bundle["findings"][0]["asset_refs"] = ["A-002"]

    inventory = {
        "assets": [
            {
                "asset_id": "A-002",
                "asset_type": "repo",
                "value": "github.com/example/repo",
                "owner": "Platform Security",
                "criticality": "medium",
            }
        ]
    }
    _write_json(tmp_path / "assets.json", inventory)

    report = build_report(config, bundle)

    assert len(report.assets) == 1
    assert report.assets[0].asset_id == "A-002"
    assert report.assets[0].value == "github.com/example/repo"


def test_build_report_rejects_unknown_evidence_reference(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["findings"][0]["evidence_refs"] = ["EVID-999"]

    with pytest.raises(GuardrailViolation, match="references unknown evidence"):
        build_report(config, bundle)


def test_render_markdown_includes_unsafe_dev_warning(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    report = build_report(config, bundle)

    markdown = render_markdown(
        report,
        unsafe_options=["dev.debug=true", "dev.fail_on_missing_citation=false"],
    )

    assert "Generated with non-default developer settings" in markdown
    assert "dev.debug=true" in markdown
    assert "dev.fail_on_missing_citation=false" in markdown


def test_summarize_report_returns_audience_specific_text(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    report = build_report(config, bundle)

    ciso_summary = summarize_report(report, "ciso")
    soc_summary = summarize_report(report, "soc")
    joint_summary = summarize_report(report, "joint")

    assert "Highest risk score" in ciso_summary
    assert "incident-response routing" in soc_summary
    assert "exposure assessment contains" in joint_summary


def test_build_report_rejects_non_https_source_outside_lab_mode(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["evidence"][0]["source_url"] = "http://example.com/security"

    with pytest.raises(GuardrailViolation, match="must use https outside lab mode"):
        build_report(config, bundle)


def test_build_report_rejects_non_allowlisted_source_host(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["evidence"][0]["source_url"] = "https://evil.example.net/security"

    with pytest.raises(GuardrailViolation, match="approved source allowlist"):
        build_report(config, bundle)


def test_build_report_rejects_localhost_source_outside_lab_mode(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["evidence"][0]["source_url"] = "https://localhost/security"

    with pytest.raises(GuardrailViolation, match="private network hosts"):
        build_report(config, bundle)


def test_build_report_rejects_invalid_retrieval_timestamp(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["evidence"][0]["retrieved_at"] = "not-a-timestamp"

    with pytest.raises(GuardrailViolation, match="valid ISO-8601 datetime"):
        build_report(config, bundle)


def test_build_report_rejects_findings_below_min_confidence(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["findings"][0]["confidence"] = 59

    with pytest.raises(GuardrailViolation, match="below min_confidence"):
        build_report(config, bundle)


def test_build_report_rejects_findings_without_evidence_refs(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    bundle["findings"][0]["evidence_refs"] = []

    with pytest.raises(GuardrailViolation, match="must cite at least one evidence item"):
        build_report(config, bundle)


def test_build_report_enforces_sample_limit(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    config["dev"]["sample_limit"] = 1
    bundle["evidence"].append(
        {
            "type": "web",
            "source_name": "Example Corp Status",
            "source_url": "https://example.com/status",
            "retrieved_at": "2026-04-15T01:00:00Z",
            "claim": "Status page references the same service boundary.",
            "sensitivity": "public",
        }
    )
    bundle["findings"][0]["evidence_refs"] = ["EVID-001", "EVID-002"]

    with pytest.raises(GuardrailViolation, match="exceeds sample_limit=1"):
        build_report(config, bundle)


def test_build_report_allows_http_localhost_in_lab_mode(tmp_path):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    config["dev"]["lab_mode"] = True
    config["guardrails"]["allowed_source_hosts"] = []
    config["scope_defaults"]["source_policy"] = "lab-only"
    bundle["evidence"][0]["source_url"] = "http://localhost:8080/security"

    report = build_report(config, bundle)

    assert report.evidence[0].source_url == "http://localhost:8080/security"


def test_cli_build_validate_render_and_summarize(tmp_path, capsys):
    config = _base_config(tmp_path)
    bundle = _base_bundle()
    config_path = tmp_path / "config.json"
    evidence_path = tmp_path / "evidence.json"
    report_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    rendered_path = tmp_path / "rendered.md"

    _write_json(config_path, config)
    _write_json(evidence_path, bundle)

    assert main(
        [
            "build",
            "--config",
            str(config_path),
            "--evidence",
            str(evidence_path),
            "--output",
            str(markdown_path),
            "--json-output",
            str(report_path),
        ]
    ) == 0
    assert markdown_path.exists()
    assert report_path.exists()

    assert main(["validate", "--report", str(report_path)]) == 0
    assert main(["render", "--report", str(report_path), "--output", str(rendered_path)]) == 0
    assert rendered_path.exists()

    assert main(["summarize", "--report", str(report_path), "--audience", "soc"]) == 0
    captured = capsys.readouterr()
    assert "incident-response routing" in captured.out
