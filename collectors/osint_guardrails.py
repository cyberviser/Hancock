from __future__ import annotations

from datetime import datetime
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\+?\d[\d\-\(\) ]{7,}\d")


class GuardrailViolation(ValueError):
    """Raised when the OSINT reporting workflow is configured unsafely."""


def _parse_iso_datetime(value: str, field_name: str) -> None:
    normalized = value.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise GuardrailViolation(f"{field_name} must be a valid ISO-8601 datetime") from exc


def _is_loopback_or_private_host(hostname: str) -> bool:
    lowered = hostname.lower()
    if lowered in {"localhost", "localhost.localdomain"}:
        return True

    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
    )


def _host_matches_allowlist(hostname: str, allowed_hosts: list[str]) -> bool:
    lowered = hostname.lower()
    for allowed in allowed_hosts:
        candidate = allowed.lower().strip()
        if not candidate:
            continue
        if lowered == candidate or lowered.endswith(f".{candidate}"):
            return True
    return False


def _validate_source_url(
    source_url: str,
    *,
    field_name: str,
    source_policy: str,
    lab_mode: bool,
    allowed_hosts: list[str],
) -> None:
    parsed = urlparse(source_url)
    if parsed.scheme not in {"https", "http"}:
        raise GuardrailViolation(f"{field_name} must use http or https")
    if not parsed.netloc:
        raise GuardrailViolation(f"{field_name} must include a hostname")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise GuardrailViolation(f"{field_name} must include a hostname")

    if parsed.scheme != "https" and not lab_mode:
        raise GuardrailViolation(f"{field_name} must use https outside lab mode")

    if _is_loopback_or_private_host(hostname) and not lab_mode:
        raise GuardrailViolation(f"{field_name} cannot reference localhost or private network hosts")

    if source_policy != "lab-only" and allowed_hosts:
        if not _host_matches_allowlist(hostname, allowed_hosts):
            raise GuardrailViolation(f"{field_name} host {hostname} is not in the approved source allowlist")


def validate_dev_config(config: dict[str, Any]) -> None:
    if not isinstance(config, dict):
        raise GuardrailViolation("config must be an object")

    required = ("profile", "target", "render", "guardrails", "dev")
    for key in required:
        if key not in config:
            raise GuardrailViolation(f"config missing required key: {key}")

    if config["profile"] not in {"ciso", "soc", "joint"}:
        raise GuardrailViolation("profile must be ciso, soc, or joint")

    guardrails = config.get("guardrails", {})
    dev = config.get("dev", {})

    if guardrails.get("allow_active_collection") and not dev.get("lab_mode"):
        raise GuardrailViolation("allow_active_collection requires dev.lab_mode=true")

    if guardrails.get("forbid_dark_web_collection") is False:
        raise GuardrailViolation("forbid_dark_web_collection cannot be disabled in this prototype")


def redact_text(text: str, pii_policy: str) -> str:
    if pii_policy != "mask-low-value":
        return text

    redacted = EMAIL_RE.sub("[REDACTED-EMAIL]", text)
    redacted = PHONE_RE.sub("[REDACTED-PHONE]", redacted)
    return redacted


def normalize_evidence_records(
    evidence_records: list[dict[str, Any]],
    *,
    pii_policy: str,
    fail_on_missing_citation: bool,
    source_policy: str,
    lab_mode: bool,
    allowed_source_hosts: list[str],
    sample_limit: int | None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()

    for record in evidence_records:
        source_url = str(record.get("source_url", "")).strip()
        retrieved_at = str(record.get("retrieved_at", "")).strip()
        claim = str(record.get("claim", "")).strip()

        if fail_on_missing_citation and (not source_url or not retrieved_at):
            raise GuardrailViolation("every evidence item must include source_url and retrieved_at")
        if not claim:
            raise GuardrailViolation("every evidence item must include a claim")
        if source_url:
            _validate_source_url(
                source_url,
                field_name="evidence.source_url",
                source_policy=source_policy,
                lab_mode=lab_mode,
                allowed_hosts=allowed_source_hosts,
            )
        if retrieved_at:
            _parse_iso_datetime(retrieved_at, "evidence.retrieved_at")

        fingerprint = (source_url, claim)
        if fingerprint in seen_keys:
            continue
        seen_keys.add(fingerprint)

        item = dict(record)
        item["id"] = item.get("id") or f"EVID-{len(normalized) + 1:03d}"
        item["claim"] = redact_text(claim, pii_policy)
        normalized.append(item)

        if sample_limit is not None and len(normalized) > sample_limit:
            raise GuardrailViolation(f"evidence count exceeds sample_limit={sample_limit}")

    return normalized


def normalize_findings(
    findings: list[dict[str, Any]],
    *,
    evidence_ids: set[str],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

    for finding in findings:
        item = dict(finding)
        item["id"] = item.get("id") or f"F-{len(normalized) + 1:03d}"
        item.setdefault("asset_refs", [])
        item.setdefault("evidence_refs", [])
        item.setdefault("mitre_attack", [])
        item.setdefault("nist_controls", [])
        item.setdefault("status", "open")

        missing_evidence = [ref for ref in item["evidence_refs"] if ref not in evidence_ids]
        if missing_evidence:
            raise GuardrailViolation(
                f"finding {item['id']} references unknown evidence: {', '.join(missing_evidence)}"
            )

        normalized.append(item)

    return normalized


def validate_report_guardrails(report_data: dict[str, Any], config: dict[str, Any]) -> None:
    guardrails = config.get("guardrails", {})
    authorization_required = bool(guardrails.get("authorization_required", True))
    min_confidence = float(guardrails.get("min_confidence", 0))

    engagement = report_data.get("engagement", {})
    if authorization_required and not str(engagement.get("authorization_reference", "")).strip():
        raise GuardrailViolation("authorization_reference is required")

    metadata = report_data.get("report_metadata", {})
    if metadata.get("authorized_use_only") is not True:
        raise GuardrailViolation("report_metadata.authorized_use_only must be true")

    config_profile = str(config.get("profile", "")).strip()
    if metadata.get("report_profile") != config_profile or engagement.get("report_profile") != config_profile:
        raise GuardrailViolation("report profile must match config.profile across metadata and engagement")

    scope = report_data.get("scope", {})
    if not scope.get("in_scope"):
        raise GuardrailViolation("scope.in_scope must contain at least one authorized asset")

    findings = report_data.get("findings", [])
    for finding in findings:
        confidence = float(finding.get("confidence", 0))
        if confidence < min_confidence:
            raise GuardrailViolation(
                f"finding {finding.get('id', '<unknown>')} is below min_confidence={min_confidence:g}"
            )
        if not finding.get("evidence_refs"):
            raise GuardrailViolation(f"finding {finding.get('id', '<unknown>')} must cite at least one evidence item")


def unsafe_dev_options(config: dict[str, Any]) -> list[str]:
    dev = config.get("dev", {})
    guardrails = config.get("guardrails", {})
    issues: list[str] = []

    if dev.get("lab_mode"):
        issues.append("dev.lab_mode=true")
    if dev.get("debug"):
        issues.append("dev.debug=true")
    if dev.get("fail_on_missing_citation") is False:
        issues.append("dev.fail_on_missing_citation=false")
    if guardrails.get("allow_active_collection"):
        issues.append("guardrails.allow_active_collection=true")

    return issues
