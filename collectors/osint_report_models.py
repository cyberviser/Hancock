from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any


FINDING_ID_RE = re.compile(r"^F-[0-9]{3}$")
EVIDENCE_ID_RE = re.compile(r"^EVID-[0-9]{3}$")


class ModelValidationError(ValueError):
    """Raised when a report payload does not satisfy the model contract."""


def _require_mapping(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ModelValidationError(f"{name} must be an object")
    return value


def _require_list(name: str, value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ModelValidationError(f"{name} must be a list")
    return value


def _require_string(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{name} must be a non-empty string")
    return value


def _require_number(name: str, value: Any, minimum: float, maximum: float) -> float:
    if not isinstance(value, (int, float)):
        raise ModelValidationError(f"{name} must be a number")
    numeric = float(value)
    if numeric < minimum or numeric > maximum:
        raise ModelValidationError(f"{name} must be between {minimum} and {maximum}")
    return numeric


@dataclass(slots=True)
class ReportMetadata:
    title: str
    target: str
    classification: str
    generated_at: str
    analyst: str
    report_profile: str
    tool_version: str
    authorized_use_only: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportMetadata":
        payload = _require_mapping("report_metadata", data)
        profile = _require_string("report_metadata.report_profile", payload.get("report_profile"))
        if profile not in {"ciso", "soc", "joint"}:
            raise ModelValidationError("report_metadata.report_profile must be ciso, soc, or joint")
        return cls(
            title=_require_string("report_metadata.title", payload.get("title")),
            target=_require_string("report_metadata.target", payload.get("target")),
            classification=_require_string("report_metadata.classification", payload.get("classification")),
            generated_at=_require_string("report_metadata.generated_at", payload.get("generated_at")),
            analyst=_require_string("report_metadata.analyst", payload.get("analyst")),
            report_profile=profile,
            tool_version=_require_string("report_metadata.tool_version", payload.get("tool_version")),
            authorized_use_only=bool(payload.get("authorized_use_only", True)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "target": self.target,
            "classification": self.classification,
            "generated_at": self.generated_at,
            "analyst": self.analyst,
            "report_profile": self.report_profile,
            "tool_version": self.tool_version,
            "authorized_use_only": self.authorized_use_only,
        }


@dataclass(slots=True)
class Engagement:
    requester: str
    business_owner: str
    authorization_reference: str
    objective: str
    report_profile: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Engagement":
        payload = _require_mapping("engagement", data)
        profile = _require_string("engagement.report_profile", payload.get("report_profile"))
        if profile not in {"ciso", "soc", "joint"}:
            raise ModelValidationError("engagement.report_profile must be ciso, soc, or joint")
        return cls(
            requester=_require_string("engagement.requester", payload.get("requester")),
            business_owner=_require_string("engagement.business_owner", payload.get("business_owner")),
            authorization_reference=_require_string(
                "engagement.authorization_reference",
                payload.get("authorization_reference"),
            ),
            objective=_require_string("engagement.objective", payload.get("objective")),
            report_profile=profile,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requester": self.requester,
            "business_owner": self.business_owner,
            "authorization_reference": self.authorization_reference,
            "objective": self.objective,
            "report_profile": self.report_profile,
        }


@dataclass(slots=True)
class Scope:
    in_scope: list[str]
    out_of_scope: list[str]
    collection_constraints: list[str]
    source_policy: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scope":
        payload = _require_mapping("scope", data)
        source_policy = _require_string("scope.source_policy", payload.get("source_policy"))
        if source_policy not in {"approved-only", "internal-plus-approved", "lab-only"}:
            raise ModelValidationError(
                "scope.source_policy must be approved-only, internal-plus-approved, or lab-only"
            )
        return cls(
            in_scope=[_require_string("scope.in_scope[]", item) for item in _require_list("scope.in_scope", payload.get("in_scope"))],
            out_of_scope=[
                _require_string("scope.out_of_scope[]", item)
                for item in _require_list("scope.out_of_scope", payload.get("out_of_scope"))
            ],
            collection_constraints=[
                _require_string("scope.collection_constraints[]", item)
                for item in _require_list("scope.collection_constraints", payload.get("collection_constraints"))
            ],
            source_policy=source_policy,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "collection_constraints": self.collection_constraints,
            "source_policy": self.source_policy,
        }


@dataclass(slots=True)
class Asset:
    asset_id: str
    asset_type: str
    value: str
    owner: str
    criticality: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Asset":
        payload = _require_mapping("asset", data)
        asset_type = _require_string("asset.asset_type", payload.get("asset_type"))
        if asset_type not in {"domain", "subdomain", "host", "ip", "repo", "brand", "social", "person", "other"}:
            raise ModelValidationError("asset.asset_type is invalid")
        criticality = _require_string("asset.criticality", payload.get("criticality"))
        if criticality not in {"critical", "high", "medium", "low"}:
            raise ModelValidationError("asset.criticality must be critical, high, medium, or low")
        return cls(
            asset_id=_require_string("asset.asset_id", payload.get("asset_id")),
            asset_type=asset_type,
            value=_require_string("asset.value", payload.get("value")),
            owner=_require_string("asset.owner", payload.get("owner")),
            criticality=criticality,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "value": self.value,
            "owner": self.owner,
            "criticality": self.criticality,
        }


@dataclass(slots=True)
class Evidence:
    id: str
    type: str
    source_name: str
    source_url: str
    retrieved_at: str
    claim: str
    sensitivity: str
    raw_artifact_path: str = ""
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        payload = _require_mapping("evidence", data)
        evidence_id = _require_string("evidence.id", payload.get("id"))
        if not EVIDENCE_ID_RE.match(evidence_id):
            raise ModelValidationError("evidence.id must look like EVID-001")
        evidence_type = _require_string("evidence.type", payload.get("type"))
        if evidence_type not in {"web", "screenshot", "ticket", "repo", "whois", "dns", "note", "other"}:
            raise ModelValidationError("evidence.type is invalid")
        sensitivity = _require_string("evidence.sensitivity", payload.get("sensitivity"))
        if sensitivity not in {"public", "internal", "sensitive"}:
            raise ModelValidationError("evidence.sensitivity must be public, internal, or sensitive")
        return cls(
            id=evidence_id,
            type=evidence_type,
            source_name=_require_string("evidence.source_name", payload.get("source_name")),
            source_url=_require_string("evidence.source_url", payload.get("source_url")),
            retrieved_at=_require_string("evidence.retrieved_at", payload.get("retrieved_at")),
            claim=_require_string("evidence.claim", payload.get("claim")),
            sensitivity=sensitivity,
            raw_artifact_path=str(payload.get("raw_artifact_path", "")),
            notes=str(payload.get("notes", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "source_name": self.source_name,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "claim": self.claim,
            "sensitivity": self.sensitivity,
            "raw_artifact_path": self.raw_artifact_path,
            "notes": self.notes,
        }


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    summary: str
    asset_refs: list[str]
    evidence_refs: list[str]
    confidence: float
    risk_score: float
    mitre_attack: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    status: str = "open"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        payload = _require_mapping("finding", data)
        finding_id = _require_string("finding.id", payload.get("id"))
        if not FINDING_ID_RE.match(finding_id):
            raise ModelValidationError("finding.id must look like F-001")
        severity = _require_string("finding.severity", payload.get("severity"))
        if severity not in {"critical", "high", "medium", "low", "informational"}:
            raise ModelValidationError("finding.severity is invalid")
        status = _require_string("finding.status", payload.get("status"))
        if status not in {"open", "accepted-risk", "mitigated", "monitoring"}:
            raise ModelValidationError("finding.status is invalid")
        return cls(
            id=finding_id,
            title=_require_string("finding.title", payload.get("title")),
            severity=severity,
            summary=_require_string("finding.summary", payload.get("summary")),
            asset_refs=[_require_string("finding.asset_refs[]", item) for item in _require_list("finding.asset_refs", payload.get("asset_refs"))],
            evidence_refs=[
                _require_string("finding.evidence_refs[]", item)
                for item in _require_list("finding.evidence_refs", payload.get("evidence_refs"))
            ],
            confidence=_require_number("finding.confidence", payload.get("confidence"), 0, 100),
            risk_score=_require_number("finding.risk_score", payload.get("risk_score"), 0, 10),
            mitre_attack=[str(item) for item in payload.get("mitre_attack", [])],
            nist_controls=[str(item) for item in payload.get("nist_controls", [])],
            status=status,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "asset_refs": self.asset_refs,
            "evidence_refs": self.evidence_refs,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "mitre_attack": self.mitre_attack,
            "nist_controls": self.nist_controls,
            "status": self.status,
        }


@dataclass(slots=True)
class Recommendation:
    action: str
    owner: str
    priority: str
    due_in_days: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Recommendation":
        payload = _require_mapping("recommendation", data)
        priority = _require_string("recommendation.priority", payload.get("priority"))
        if priority not in {"P0", "P1", "P2", "P3"}:
            raise ModelValidationError("recommendation.priority must be P0, P1, P2, or P3")
        due_in_days = payload.get("due_in_days")
        if due_in_days is not None and (not isinstance(due_in_days, int) or due_in_days < 0):
            raise ModelValidationError("recommendation.due_in_days must be a non-negative integer")
        return cls(
            action=_require_string("recommendation.action", payload.get("action")),
            owner=_require_string("recommendation.owner", payload.get("owner")),
            priority=priority,
            due_in_days=due_in_days,
        )

    def to_dict(self) -> dict[str, Any]:
        data = {
            "action": self.action,
            "owner": self.owner,
            "priority": self.priority,
        }
        if self.due_in_days is not None:
            data["due_in_days"] = self.due_in_days
        return data


@dataclass(slots=True)
class Recommendations:
    immediate: list[Recommendation] = field(default_factory=list)
    thirty_day: list[Recommendation] = field(default_factory=list)
    long_term: list[Recommendation] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Recommendations":
        payload = _require_mapping("recommendations", data)
        return cls(
            immediate=[Recommendation.from_dict(item) for item in _require_list("recommendations.immediate", payload.get("immediate", []))],
            thirty_day=[Recommendation.from_dict(item) for item in _require_list("recommendations.thirty_day", payload.get("thirty_day", []))],
            long_term=[Recommendation.from_dict(item) for item in _require_list("recommendations.long_term", payload.get("long_term", []))],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "immediate": [item.to_dict() for item in self.immediate],
            "thirty_day": [item.to_dict() for item in self.thirty_day],
            "long_term": [item.to_dict() for item in self.long_term],
        }


@dataclass(slots=True)
class Diagram:
    title: str
    diagram_type: str
    description: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Diagram":
        payload = _require_mapping("diagram", data)
        diagram_type = _require_string("diagram.diagram_type", payload.get("diagram_type"))
        if diagram_type not in {"mermaid", "plantuml", "table", "other"}:
            raise ModelValidationError("diagram.diagram_type is invalid")
        return cls(
            title=_require_string("diagram.title", payload.get("title")),
            diagram_type=diagram_type,
            description=_require_string("diagram.description", payload.get("description")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "diagram_type": self.diagram_type,
            "description": self.description,
        }


@dataclass(slots=True)
class OSINTReport:
    report_metadata: ReportMetadata
    engagement: Engagement
    scope: Scope
    assets: list[Asset]
    findings: list[Finding]
    evidence: list[Evidence]
    recommendations: Recommendations
    diagrams: list[Diagram] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OSINTReport":
        payload = _require_mapping("report", data)
        report = cls(
            report_metadata=ReportMetadata.from_dict(payload.get("report_metadata")),
            engagement=Engagement.from_dict(payload.get("engagement")),
            scope=Scope.from_dict(payload.get("scope")),
            assets=[Asset.from_dict(item) for item in _require_list("assets", payload.get("assets"))],
            findings=[Finding.from_dict(item) for item in _require_list("findings", payload.get("findings"))],
            evidence=[Evidence.from_dict(item) for item in _require_list("evidence", payload.get("evidence"))],
            recommendations=Recommendations.from_dict(payload.get("recommendations")),
            diagrams=[Diagram.from_dict(item) for item in payload.get("diagrams", [])],
        )

        evidence_ids = {item.id for item in report.evidence}
        asset_ids = {item.asset_id for item in report.assets}
        for finding in report.findings:
            for asset_id in finding.asset_refs:
                if asset_id not in asset_ids:
                    raise ModelValidationError(f"finding {finding.id} references unknown asset {asset_id}")
            for evidence_id in finding.evidence_refs:
                if evidence_id not in evidence_ids:
                    raise ModelValidationError(f"finding {finding.id} references unknown evidence {evidence_id}")
        return report

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_metadata": self.report_metadata.to_dict(),
            "engagement": self.engagement.to_dict(),
            "scope": self.scope.to_dict(),
            "assets": [item.to_dict() for item in self.assets],
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "recommendations": self.recommendations.to_dict(),
            "diagrams": [item.to_dict() for item in self.diagrams],
        }
