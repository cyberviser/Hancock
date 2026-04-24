from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .osint_guardrails import (
    GuardrailViolation,
    normalize_evidence_records,
    normalize_findings,
    unsafe_dev_options,
    validate_dev_config,
    validate_report_guardrails,
)
from .osint_report_models import ModelValidationError, OSINTReport


TOOL_VERSION = "0.6.0"


def load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: str | Path, payload: Any) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _load_assets_from_inventory(path: str | Path | None) -> list[dict[str, Any]]:
    if not path:
        return []

    inventory_path = Path(path)
    if not inventory_path.exists():
        return []

    payload = load_json(inventory_path)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return list(payload.get("assets", []))
    return []


def _default_recommendations() -> dict[str, list[dict[str, Any]]]:
    return {
        "immediate": [],
        "thirty_day": [],
        "long_term": [],
    }


def build_report_dict(config: dict[str, Any], evidence_bundle: dict[str, Any]) -> dict[str, Any]:
    validate_dev_config(config)

    guardrails = config.get("guardrails", {})
    dev = config.get("dev", {})
    scope_config = config.get("scope_defaults", {})
    pii_policy = config.get("guardrails", {}).get("pii_policy", "mask-low-value")
    fail_on_missing_citation = bool(dev.get("fail_on_missing_citation", True))
    source_policy = str(scope_config.get("source_policy", "approved-only"))
    lab_mode = bool(dev.get("lab_mode", False))
    allowed_source_hosts = [str(item) for item in guardrails.get("allowed_source_hosts", [])]
    sample_limit = dev.get("sample_limit")
    if sample_limit is not None:
        sample_limit = int(sample_limit)

    evidence_records = normalize_evidence_records(
        list(evidence_bundle.get("evidence", [])),
        pii_policy=pii_policy,
        fail_on_missing_citation=fail_on_missing_citation,
        source_policy=source_policy,
        lab_mode=lab_mode,
        allowed_source_hosts=allowed_source_hosts,
        sample_limit=sample_limit,
    )
    evidence_ids = {item["id"] for item in evidence_records}

    finding_records = normalize_findings(
        list(evidence_bundle.get("findings", [])),
        evidence_ids=evidence_ids,
    )

    assets = list(evidence_bundle.get("assets", []))
    if not assets:
        assets = _load_assets_from_inventory(config.get("inputs", {}).get("asset_inventory"))

    metadata_overrides = dict(evidence_bundle.get("report_metadata", {}))
    engagement_defaults = dict(config.get("engagement_defaults", {}))
    engagement_defaults.update(evidence_bundle.get("engagement", {}))
    scope_defaults = dict(scope_config)
    scope_defaults.update(evidence_bundle.get("scope", {}))

    report_data = {
        "report_metadata": {
            "title": metadata_overrides.get("title") or f"{config['target']} Exposure Assessment",
            "target": metadata_overrides.get("target") or config["target"],
            "classification": metadata_overrides.get("classification")
            or config.get("render", {}).get("classification", "UNCLASSIFIED // OSINT"),
            "generated_at": metadata_overrides.get("generated_at")
            or datetime.now(timezone.utc).isoformat(),
            "analyst": metadata_overrides.get("analyst") or engagement_defaults.get("requester", "Hancock"),
            "report_profile": metadata_overrides.get("report_profile") or config["profile"],
            "tool_version": metadata_overrides.get("tool_version") or TOOL_VERSION,
            "authorized_use_only": True,
        },
        "engagement": {
            "requester": engagement_defaults.get("requester", "Security Engineering"),
            "business_owner": engagement_defaults.get("business_owner", config["target"]),
            "authorization_reference": engagement_defaults.get("authorization_reference", ""),
            "objective": engagement_defaults.get(
                "objective",
                "Generate a defensive OSINT exposure assessment report.",
            ),
            "report_profile": engagement_defaults.get("report_profile", config["profile"]),
        },
        "scope": {
            "in_scope": scope_defaults.get(
                "in_scope",
                list(config.get("scope", {}).get("authorized_assets", [])),
            ),
            "out_of_scope": scope_defaults.get("out_of_scope", []),
            "collection_constraints": scope_defaults.get(
                "collection_constraints",
                ["Passive evidence only", "Authorized defensive use only"],
            ),
            "source_policy": scope_defaults.get("source_policy", "approved-only"),
        },
        "assets": assets,
        "findings": finding_records,
        "evidence": evidence_records,
        "recommendations": evidence_bundle.get("recommendations", _default_recommendations()),
        "diagrams": list(evidence_bundle.get("diagrams", [])),
    }
    validate_report_guardrails(report_data, config)
    return report_data


def build_report(config: dict[str, Any], evidence_bundle: dict[str, Any]) -> OSINTReport:
    return OSINTReport.from_dict(build_report_dict(config, evidence_bundle))


def render_markdown(report: OSINTReport, *, unsafe_options: list[str] | None = None) -> str:
    data = report.to_dict()
    meta = data["report_metadata"]
    engagement = data["engagement"]
    scope = data["scope"]
    findings = data["findings"]
    evidence = data["evidence"]
    recommendations = data["recommendations"]
    unsafe_options = unsafe_options or []

    lines: list[str] = []
    lines.append(f"# {meta['title']}")
    lines.append("")
    if unsafe_options:
        lines.append("**WARNING:** Generated with non-default developer settings. Not for production distribution.")
        lines.append("")
        lines.append(f"Unsafe options: {', '.join(unsafe_options)}")
        lines.append("")
    lines.extend(
        [
            f"- **Target:** {meta['target']}",
            f"- **Classification:** {meta['classification']}",
            f"- **Generated At:** {meta['generated_at']}",
            f"- **Analyst:** {meta['analyst']}",
            f"- **Profile:** {meta['report_profile']}",
            f"- **Authorization Reference:** {engagement['authorization_reference']}",
            "",
            "## Executive Summary",
            "",
            f"This report summarizes defensive OSINT exposure for **{meta['target']}** within the approved scope. "
            f"It includes {len(findings)} findings across {len(data['assets'])} tracked assets with "
            f"{len(evidence)} cited evidence records.",
            "",
            "## Scope",
            "",
            f"- **In Scope:** {', '.join(scope['in_scope']) or 'None provided'}",
            f"- **Out of Scope:** {', '.join(scope['out_of_scope']) or 'None provided'}",
            f"- **Collection Constraints:** {', '.join(scope['collection_constraints']) or 'None provided'}",
            f"- **Source Policy:** {scope['source_policy']}",
            "",
            "## Key Findings",
            "",
            "| ID | Title | Severity | Confidence | Risk Score |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        lines.append(
            f"| {finding['id']} | {finding['title']} | {finding['severity']} | "
            f"{finding['confidence']:.1f}% | {finding['risk_score']:.1f} |"
        )

    lines.extend(["", "## Detailed Findings", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding['id']} - {finding['title']}",
                f"- **Severity:** {finding['severity']}",
                f"- **Confidence:** {finding['confidence']:.1f}%",
                f"- **Risk Score:** {finding['risk_score']:.1f}",
                f"- **Status:** {finding['status']}",
                f"- **Summary:** {finding['summary']}",
                f"- **Assets:** {', '.join(finding['asset_refs']) or 'None'}",
                f"- **Evidence:** {', '.join(finding['evidence_refs']) or 'None'}",
                f"- **MITRE ATT&CK:** {', '.join(finding['mitre_attack']) or 'None'}",
                f"- **NIST / Control Mapping:** {', '.join(finding['nist_controls']) or 'None'}",
                "",
            ]
        )

    lines.extend(["## Evidence Register", ""])
    for item in evidence:
        lines.extend(
            [
                f"### {item['id']} - {item['source_name']}",
                f"- **Source URL:** {item['source_url']}",
                f"- **Retrieved At:** {item['retrieved_at']}",
                f"- **Sensitivity:** {item['sensitivity']}",
                f"- **Claim:** {item['claim']}",
            ]
        )
        if item.get("raw_artifact_path"):
            lines.append(f"- **Raw Artifact Path:** {item['raw_artifact_path']}")
        if item.get("notes"):
            lines.append(f"- **Notes:** {item['notes']}")
        lines.append("")

    lines.extend(["## Recommendations", ""])
    for label, bucket in (
        ("Immediate", recommendations["immediate"]),
        ("30-Day", recommendations["thirty_day"]),
        ("Long-Term", recommendations["long_term"]),
    ):
        lines.append(f"### {label}")
        if not bucket:
            lines.append("- None provided")
        for item in bucket:
            due = f" ({item['due_in_days']} days)" if "due_in_days" in item else ""
            lines.append(
                f"- `{item['priority']}` {item['action']} — owner: {item['owner']}{due}"
            )
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def summarize_report(report: OSINTReport, audience: str) -> str:
    data = report.to_dict()
    findings = data["findings"]
    highest = max((item["risk_score"] for item in findings), default=0)
    if audience == "ciso":
        return (
            f"{data['report_metadata']['target']} has {len(findings)} tracked findings. "
            f"Highest risk score: {highest:.1f}/10. Focus on ownership, external exposure reduction, and remediation SLA."
        )
    if audience == "soc":
        return (
            f"{data['report_metadata']['target']} has {len(findings)} findings with {len(data['evidence'])} evidence records. "
            "Prioritize verification, monitoring coverage, and incident-response routing."
        )
    return (
        f"{data['report_metadata']['target']} exposure assessment contains {len(findings)} findings "
        f"across {len(data['assets'])} assets."
    )


def _write_text(path: str | Path, content: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


def _write_build_outputs(report: OSINTReport, config: dict[str, Any], output: str | None, json_output: str | None) -> None:
    unsafe = unsafe_dev_options(config)
    markdown_path = output or config.get("outputs", {}).get("markdown")
    json_path = json_output or config.get("outputs", {}).get("json")

    if markdown_path:
        _write_text(markdown_path, render_markdown(report, unsafe_options=unsafe))
    if json_path:
        Path(json_path).parent.mkdir(parents=True, exist_ok=True)
        save_json(json_path, report.to_dict())


def _load_and_validate_report(path: str | Path) -> OSINTReport:
    return OSINTReport.from_dict(load_json(path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hancock OSINT reporting prototype")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build Markdown / JSON report outputs")
    build_parser.add_argument("--config", required=True, help="Path to JSON config")
    build_parser.add_argument("--evidence", required=True, help="Path to evidence bundle JSON")
    build_parser.add_argument("--output", help="Markdown output path")
    build_parser.add_argument("--json-output", help="JSON output path")

    validate_parser = subparsers.add_parser("validate", help="Validate config + evidence or a report JSON")
    validate_parser.add_argument("--config", help="Path to JSON config")
    validate_parser.add_argument("--evidence", help="Path to evidence bundle JSON")
    validate_parser.add_argument("--report", help="Path to normalized report JSON")

    render_parser = subparsers.add_parser("render", help="Render Markdown from a normalized report JSON")
    render_parser.add_argument("--report", required=True, help="Path to normalized report JSON")
    render_parser.add_argument("--output", required=True, help="Markdown output path")

    summarize_parser = subparsers.add_parser("summarize", help="Print a short summary for an audience")
    summarize_parser.add_argument("--report", required=True, help="Path to normalized report JSON")
    summarize_parser.add_argument("--audience", default="joint", choices=["joint", "ciso", "soc"])

    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            config = load_json(args.config)
            evidence_bundle = load_json(args.evidence)
            report = build_report(config, evidence_bundle)
            _write_build_outputs(report, config, args.output, args.json_output)
            return 0

        if args.command == "validate":
            if args.report:
                _load_and_validate_report(args.report)
                return 0
            if not args.config or not args.evidence:
                raise GuardrailViolation("validate requires --report or both --config and --evidence")
            config = load_json(args.config)
            evidence_bundle = load_json(args.evidence)
            build_report(config, evidence_bundle)
            return 0

        if args.command == "render":
            report = _load_and_validate_report(args.report)
            _write_text(args.output, render_markdown(report))
            return 0

        if args.command == "summarize":
            report = _load_and_validate_report(args.report)
            print(summarize_report(report, args.audience))
            return 0

        raise GuardrailViolation(f"unsupported command: {args.command}")
    except (GuardrailViolation, ModelValidationError, FileNotFoundError, json.JSONDecodeError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
