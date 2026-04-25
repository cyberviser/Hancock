#!/usr/bin/env python3
"""Hancock local project static assessor.

Local-only, review-first project assessment for Hancock operators.

Safety contract:
- Does not execute project code.
- Does not run shell commands.
- Does not scan networks.
- Does not contact external services.
- Does not upload files or secrets.
- Produces inventory, pattern findings, and review guidance only.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(str, Enum):
    MANIFEST = "manifest"
    SECRET = "secret"
    EXECUTION = "execution"
    CONFIG = "config"
    CONTAINER = "container"
    CI = "ci"
    SAFETY = "safety"


@dataclass(frozen=True)
class StaticFinding:
    path: str
    category: FindingCategory
    severity: Severity
    rule_id: str
    message: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class ProjectInventory:
    root: str
    total_files: int
    analyzed_files: int
    skipped_files: int
    manifests: tuple[str, ...]
    languages: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StaticAssessmentReport:
    inventory: ProjectInventory
    findings: tuple[StaticFinding, ...]
    safety: dict[str, Any] = field(default_factory=dict)

    @property
    def highest_severity(self) -> Severity:
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}
        if not self.findings:
            return Severity.INFO
        return max((finding.severity for finding in self.findings), key=lambda sev: order[sev])

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "highest_severity": self.highest_severity.value,
            "safety": self.safety,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_markdown(self) -> str:
        lines = [
            "# Hancock Local Static Assessment",
            "",
            f"- Root: `{self.inventory.root}`",
            f"- Total files seen: `{self.inventory.total_files}`",
            f"- Files analyzed: `{self.inventory.analyzed_files}`",
            f"- Files skipped: `{self.inventory.skipped_files}`",
            f"- Highest severity: `{self.highest_severity.value}`",
            "",
            "## Safety Contract",
            "",
        ]
        for key, value in self.safety.items():
            lines.append(f"- {key}: `{value}`")
        lines.extend(["", "## Manifests", ""])
        if self.inventory.manifests:
            lines.extend(f"- `{path}`" for path in self.inventory.manifests)
        else:
            lines.append("- None discovered")
        lines.extend(["", "## Language / File-Type Counts", ""])
        if self.inventory.languages:
            for suffix, count in sorted(self.inventory.languages.items()):
                lines.append(f"- `{suffix}`: `{count}`")
        else:
            lines.append("- None")
        lines.extend(["", "## Findings", ""])
        if not self.findings:
            lines.append("- No static findings from built-in rules.")
        else:
            for finding in self.findings:
                lines.extend(
                    [
                        f"### `{finding.rule_id}` — {finding.severity.value}",
                        "",
                        f"- Path: `{finding.path}`",
                        f"- Category: `{finding.category.value}`",
                        f"- Message: {finding.message}",
                    ]
                )
                if finding.evidence:
                    lines.append(f"- Evidence: `{finding.evidence}`")
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"


class LocalStaticAssessor:
    """Dependency-free static assessor for local project trees."""

    DEFAULT_EXCLUDES = {
        ".git",
        ".hg",
        ".svn",
        ".pytest_cache",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        ".next",
        ".turbo",
        "target",
    }
    ANALYZED_SUFFIXES = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".env",
        ".sh",
        ".dockerfile",
        ".md",
        ".txt",
    }
    MANIFEST_NAMES = {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        ".env",
        ".env.example",
        ".github/workflows/tests.yml",
        ".github/workflows/test.yml",
    }
    RULES: tuple[tuple[str, FindingCategory, Severity, str, str], ...] = (
        ("secret_literal", FindingCategory.SECRET, Severity.HIGH, "password=|password:|api_key|apikey|secret_key|client_secret|private_key", "Potential secret material or credential key reference."),
        ("unsafe_python_execution", FindingCategory.EXECUTION, Severity.HIGH, "eval(|exec(|os.system(|subprocess.Popen(|subprocess.run(|subprocess.call(|subprocess.check_call(|subprocess.check_output(", "Potential command/code execution sink. Review input control and shell usage."),
        ("shell_true", FindingCategory.EXECUTION, Severity.HIGH, "shell=True", "subprocess shell=True can expand attacker-controlled shell metacharacters."),
        ("unsafe_yaml_load", FindingCategory.EXECUTION, Severity.MEDIUM, "yaml.load(", "yaml.load can deserialize unsafe objects; prefer safe_load."),
        ("pickle_load", FindingCategory.EXECUTION, Severity.MEDIUM, "pickle.load|pickle.loads", "Pickle deserialization is unsafe for untrusted data."),
        ("tls_verify_disabled", FindingCategory.CONFIG, Severity.MEDIUM, "verify=False|NODE_TLS_REJECT_UNAUTHORIZED=0", "TLS verification appears disabled."),
        ("wide_bind", FindingCategory.CONFIG, Severity.LOW, "0.0.0.0", "Service binds to all interfaces; confirm this is intended."),
        ("permissive_chmod", FindingCategory.CONFIG, Severity.MEDIUM, "chmod 777", "World-writable permissions are risky."),
        ("docker_root", FindingCategory.CONTAINER, Severity.LOW, "USER root", "Container appears to run as root; prefer least privilege."),
        ("github_action_unpinned", FindingCategory.CI, Severity.MEDIUM, r"uses:\s*[^#\n]+@(?!(?:[0-9a-fA-F]{40})(?:\s|$|#))[^\s#]+", "GitHub Action uses a non-SHA ref; prefer full-length commit SHAs under restricted policies."),
    )

    def __init__(self, root: str | Path, extra_excludes: Iterable[str] = ()) -> None:
        self.root = Path(root).expanduser().resolve()
        self.excludes = set(self.DEFAULT_EXCLUDES) | set(extra_excludes)

    def assess(self) -> StaticAssessmentReport:
        if not self.root.exists() or not self.root.is_dir():
            raise FileNotFoundError(f"Assessment root does not exist or is not a directory: {self.root}")

        findings: list[StaticFinding] = []
        manifests: list[str] = []
        languages: dict[str, int] = {}
        total_files = 0
        analyzed_files = 0
        skipped_files = 0

        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            total_files += 1
            rel = path.relative_to(self.root).as_posix()
            if self._is_excluded(path):
                skipped_files += 1
                continue
            if path.name in self.MANIFEST_NAMES or rel in self.MANIFEST_NAMES:
                manifests.append(rel)
                findings.append(
                    StaticFinding(
                        path=rel,
                        category=FindingCategory.MANIFEST,
                        severity=Severity.INFO,
                        rule_id="manifest_discovered",
                        message="Security-relevant project manifest discovered.",
                    )
                )

            suffix = self._suffix_for(path)
            languages[suffix] = languages.get(suffix, 0) + 1
            if suffix not in self.ANALYZED_SUFFIXES:
                skipped_files += 1
                continue

            text = self._read_text(path)
            if text is None:
                skipped_files += 1
                continue
            analyzed_files += 1
            findings.extend(self._findings_for(rel, text))

        inventory = ProjectInventory(
            root=str(self.root),
            total_files=total_files,
            analyzed_files=analyzed_files,
            skipped_files=skipped_files,
            manifests=tuple(sorted(set(manifests))),
            languages=dict(sorted(languages.items())),
        )
        return StaticAssessmentReport(
            inventory=inventory,
            findings=tuple(findings),
            safety={
                "local_only": True,
                "does_not_execute_project_code": True,
                "does_not_run_shell_commands": True,
                "does_not_scan_networks": True,
                "does_not_contact_external_services": True,
                "does_not_upload_files": True,
                "review_first": True,
                "authorized_scope_only": True,
            },
        )

    def _is_excluded(self, path: Path) -> bool:
        try:
            rel_parts = path.relative_to(self.root).parts
        except ValueError:
            return True
        return any(part in self.excludes for part in rel_parts)

    @staticmethod
    def _suffix_for(path: Path) -> str:
        if path.name == "Dockerfile" or path.name.endswith(".Dockerfile"):
            return ".dockerfile"
        if path.name.startswith(".env"):
            return ".env"
        return path.suffix.lower() or "[no extension]"

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            if path.stat().st_size > 1_000_000:
                return None
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

    def _findings_for(self, rel: str, text: str) -> list[StaticFinding]:
        lowered = text.lower()
        findings: list[StaticFinding] = []
        for rule_id, category, severity, pattern, message in self.RULES:
            tokens = [token.lower() for token in pattern.split("|")]
            hit = next((token for token in tokens if token and token in lowered), "")
            if not hit:
                continue
            if rule_id == "github_action_unpinned" and not rel.startswith(".github/workflows/"):
                continue
            findings.append(
                StaticFinding(
                    path=rel,
                    category=category,
                    severity=severity,
                    rule_id=rule_id,
                    message=message,
                    evidence=hit[:120],
                )
            )
        return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hancock local-only static project assessor")
    parser.add_argument("root", help="Local project root to assess")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--exclude", action="append", default=[], help="Additional directory names to exclude")
    parser.add_argument("--fail-on", choices=("none", "medium", "high"), default="none")
    args = parser.parse_args(argv)

    report = LocalStaticAssessor(args.root, extra_excludes=args.exclude).assess()
    print(report.to_markdown() if args.format == "markdown" else report.to_json())

    if args.fail_on == "high" and report.highest_severity == Severity.HIGH:
        return 2
    if args.fail_on == "medium" and report.highest_severity in {Severity.MEDIUM, Severity.HIGH}:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
