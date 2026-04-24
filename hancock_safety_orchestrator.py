#!/usr/bin/env python3
"""Hancock safe agentic orchestration planner.

Review-first planning only. This module does not execute commands, run scans,
exploit targets, contact third-party systems, or call LLM/tool APIs.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class ApprovalState(str, Enum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class AuthorizationScope:
    client: str
    engagement: str
    allowed_assets: tuple[str, ...]
    disallowed_assets: tuple[str, ...] = ()
    allow_active_testing: bool = False
    allow_payload_generation: bool = False
    allow_external_contact: bool = False
    ticket: str = ""

    @property
    def is_defined(self) -> bool:
        return bool(self.client and self.engagement and self.allowed_assets)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SafetyFinding:
    code: str
    message: str
    severity: RiskLevel

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "severity": self.severity.value}


@dataclass(frozen=True)
class PlanStep:
    name: str
    role: str
    objective: str
    allowed_actions: tuple[str, ...]
    blocked_actions: tuple[str, ...]
    requires_human_approval: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AgenticPlan:
    request: str
    mode: str
    risk_level: RiskLevel
    approval_state: ApprovalState
    scope: AuthorizationScope
    findings: tuple[SafetyFinding, ...]
    steps: tuple[PlanStep, ...]
    safety: dict[str, Any] = field(default_factory=dict)

    @property
    def can_execute(self) -> bool:
        return self.approval_state == ApprovalState.NOT_REQUIRED and self.risk_level not in {RiskLevel.HIGH, RiskLevel.BLOCKED}

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request,
            "mode": self.mode,
            "risk_level": self.risk_level.value,
            "approval_state": self.approval_state.value,
            "scope": self.scope.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "steps": [step.to_dict() for step in self.steps],
            "can_execute": self.can_execute,
            "safety": self.safety,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_markdown(self) -> str:
        lines = [
            "# Hancock Safe Agentic Plan",
            "",
            f"- Mode: `{self.mode}`",
            f"- Risk level: `{self.risk_level.value}`",
            f"- Approval: `{self.approval_state.value}`",
            f"- Can execute automatically: `{'yes' if self.can_execute else 'no'}`",
            "",
            "## Findings",
            "",
        ]
        if not self.findings:
            lines.append("- None")
        else:
            for finding in self.findings:
                lines.append(f"- `{finding.severity.value}` `{finding.code}`: {finding.message}")
        lines += ["", "## Steps", ""]
        for idx, step in enumerate(self.steps, start=1):
            lines += [
                f"### {idx}. {step.name}",
                "",
                f"- Role: `{step.role}`",
                f"- Objective: {step.objective}",
                f"- Human approval: `{'yes' if step.requires_human_approval else 'no'}`",
                "",
                "Allowed actions:",
                *[f"- {action}" for action in step.allowed_actions],
                "",
                "Blocked actions:",
                *[f"- {action}" for action in step.blocked_actions],
                "",
            ]
        lines += ["## Safety", ""]
        for key, value in self.safety.items():
            lines.append(f"- {key}: `{value}`")
        return "\n".join(lines)


class ScopeGuard:
    ACTIVE_TESTING_RE = re.compile(
        r"\b(nmap|masscan|sqlmap|metasploit|msfconsole|crackmapexec|impacket|hydra|bruteforce|brute force|lateral movement|persistence|pivot|exploit|reverse shell|port scan|network scan|service scan|vulnerability scan|scan (?:target|host|subnet|ip|ips|ports?|cidr|network|service))\b",
        re.IGNORECASE,
    )
    PAYLOAD_RE = re.compile(
        r"\b(payload|exploit code|proof[- ]of[- ]concept|poc|reverse shell|web shell|dropper|stager|shellcode)\b",
        re.IGNORECASE,
    )
    EXTERNAL_CONTACT_RE = re.compile(
        r"\b(upload|exfiltrate|send (?:to|data)|post (?:to|data)|call (?:an? )?(?:external|webhook|api)|webhook|third[- ]party|internet[- ]facing|public internet|shodan|censys|urlscan|virustotal)\b",
        re.IGNORECASE,
    )
    DESTRUCTIVE_RE = re.compile(
        r"\b(wipe|destroy|ransom|encrypt files|delete logs|disable edr|evade detection|steal|exfiltrate|credential dump|mimikatz)\b",
        re.IGNORECASE,
    )

    def evaluate(self, request: str, scope: AuthorizationScope) -> tuple[RiskLevel, ApprovalState, tuple[SafetyFinding, ...]]:
        findings: list[SafetyFinding] = []
        normalized_request = request.casefold()

        if not scope.is_defined:
            findings.append(SafetyFinding("missing_scope", "No complete authorization scope was supplied. Hancock must stay in recommendation-only mode.", RiskLevel.HIGH))

        disallowed_hits = tuple(asset for asset in scope.disallowed_assets if asset and asset.casefold() in normalized_request)
        if disallowed_hits:
            findings.append(SafetyFinding("disallowed_asset_referenced", f"Request references explicitly disallowed asset(s): {', '.join(disallowed_hits)}.", RiskLevel.BLOCKED))
            return RiskLevel.BLOCKED, ApprovalState.BLOCKED, tuple(findings)

        if self.DESTRUCTIVE_RE.search(request):
            findings.append(SafetyFinding("destructive_or_credential_theft_intent", "Request appears to involve destructive behavior, credential theft, evasion, or exfiltration.", RiskLevel.BLOCKED))
            return RiskLevel.BLOCKED, ApprovalState.BLOCKED, tuple(findings)

        payload = bool(self.PAYLOAD_RE.search(request))
        if payload and not scope.allow_payload_generation:
            findings.append(SafetyFinding("payload_generation_not_authorized", "The request appears to involve payload or PoC generation but scope does not permit payload generation.", RiskLevel.HIGH))
            return RiskLevel.HIGH, ApprovalState.REQUIRED, tuple(findings)

        external_contact = bool(self.EXTERNAL_CONTACT_RE.search(request))
        if external_contact and not scope.allow_external_contact:
            findings.append(SafetyFinding("external_contact_not_authorized", "The request appears to involve external contact, upload, webhook/API calls, or third-party services but scope does not permit external contact.", RiskLevel.HIGH))
            return RiskLevel.HIGH, ApprovalState.REQUIRED, tuple(findings)

        active = bool(self.ACTIVE_TESTING_RE.search(request))
        if active and not scope.allow_active_testing:
            findings.append(SafetyFinding("active_testing_not_authorized", "The request mentions active testing but scope does not permit active testing.", RiskLevel.HIGH))
            return RiskLevel.HIGH, ApprovalState.REQUIRED, tuple(findings)

        if payload:
            findings.append(SafetyFinding("payload_generation_requires_review", "Payload or PoC generation is in scope but requires human approval and sandbox review.", RiskLevel.MEDIUM))
            return RiskLevel.MEDIUM, ApprovalState.REQUIRED, tuple(findings)

        if external_contact:
            findings.append(SafetyFinding("external_contact_requires_review", "External contact is in scope but requires human approval and audit logging.", RiskLevel.MEDIUM))
            return RiskLevel.MEDIUM, ApprovalState.REQUIRED, tuple(findings)

        if active:
            findings.append(SafetyFinding("active_testing_requires_review", "Active testing is in scope but requires human approval and sandboxed execution.", RiskLevel.MEDIUM))
            return RiskLevel.MEDIUM, ApprovalState.REQUIRED, tuple(findings)

        if not scope.is_defined:
            return RiskLevel.HIGH, ApprovalState.REQUIRED, tuple(findings)

        findings.append(SafetyFinding("recommendation_only", "Plan is limited to analysis, triage, reporting, or defensive recommendations.", RiskLevel.LOW))
        return RiskLevel.LOW, ApprovalState.NOT_REQUIRED, tuple(findings)


class SafeAgenticOrchestrator:
    def __init__(self) -> None:
        self.guard = ScopeGuard()

    def plan(self, request: str, scope: AuthorizationScope, mode: str = "auto") -> AgenticPlan:
        risk, approval, findings = self.guard.evaluate(request, scope)
        return AgenticPlan(
            request=request,
            mode=mode,
            risk_level=risk,
            approval_state=approval,
            scope=scope,
            findings=findings,
            steps=self._steps_for(risk, approval),
            safety={
                "authorized_scope_only": True,
                "responsible_disclosure": True,
                "recommendation_first": True,
                "does_not_execute_commands": True,
                "does_not_contact_targets": True,
                "human_in_the_loop_for_high_risk": True,
                "pentest_prompt_core_unchanged": True,
            },
        )

    @staticmethod
    def _steps_for(risk: RiskLevel, approval: ApprovalState) -> tuple[PlanStep, ...]:
        blocked_common = ("No shell execution", "No network contact", "No exploitation", "No credential attacks", "No persistence", "No evasion")
        if risk == RiskLevel.BLOCKED:
            return (PlanStep("Refuse unsafe request", "ScopeGuard", "Stop unsafe/destructive workflow and redirect to defensive remediation.", ("Explain refusal", "Offer safe defensive alternatives", "Suggest incident response steps"), blocked_common, True),)
        return (
            PlanStep("Clarify and bind scope", "Planner", "Confirm client, engagement, assets, exclusions, active-testing allowance, and ticket.", ("Summarize scope", "Identify missing authorization fields", "Ask for approval when needed"), blocked_common, approval != ApprovalState.NOT_REQUIRED),
            PlanStep("Build passive analysis plan", "Recon", "Prepare passive research, asset inventory review, log review, or detection-engineering plan.", ("Use user-supplied data", "Recommend passive OSINT sources", "Draft safe command previews"), blocked_common, False),
            PlanStep("Sandbox and approval gate", "ExecutorGate", "Prepare sandbox requirements if active testing is later approved.", ("Generate dry-run checklist", "Require human approval", "Require isolated lab/sandbox"), blocked_common, approval == ApprovalState.REQUIRED),
            PlanStep("Critique safety and accuracy", "Critic", "Review output for scope drift, unsafe instructions, missing remediation, and weak evidence.", ("Check scope alignment", "Add remediation", "Add confidence and assumptions"), blocked_common, False),
            PlanStep("Generate report", "Reporter", "Produce executive and technical findings with responsible disclosure language.", ("Executive summary", "Technical findings", "Remediation plan", "Evidence checklist"), blocked_common, False),
        )


def _parse_assets(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hancock safe agentic orchestration planner")
    parser.add_argument("request")
    parser.add_argument("--mode", default="auto")
    parser.add_argument("--client", default="")
    parser.add_argument("--engagement", default="")
    parser.add_argument("--allowed-assets", default="")
    parser.add_argument("--disallowed-assets", default="")
    parser.add_argument("--ticket", default="")
    parser.add_argument("--allow-active-testing", action="store_true")
    parser.add_argument("--allow-payload-generation", action="store_true")
    parser.add_argument("--allow-external-contact", action="store_true")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    scope = AuthorizationScope(
        client=args.client,
        engagement=args.engagement,
        allowed_assets=_parse_assets(args.allowed_assets),
        disallowed_assets=_parse_assets(args.disallowed_assets),
        allow_active_testing=args.allow_active_testing,
        allow_payload_generation=args.allow_payload_generation,
        allow_external_contact=args.allow_external_contact,
        ticket=args.ticket,
    )
    plan = SafeAgenticOrchestrator().plan(args.request, scope, mode=args.mode)
    print(plan.to_markdown() if args.format == "markdown" else plan.to_json())
    if plan.risk_level == RiskLevel.BLOCKED:
        return 2
    if plan.approval_state == ApprovalState.REQUIRED or not plan.can_execute:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
