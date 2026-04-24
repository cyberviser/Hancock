from pathlib import Path

from hancock_static_assessor import LocalStaticAssessor, Severity, main


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_assessor_discovers_manifests_and_safety_contract(tmp_path):
    write(tmp_path / "pyproject.toml", "[project]\nname='demo'\n")
    write(tmp_path / "package.json", '{"name":"demo"}')
    write(tmp_path / "app.py", "print('hello')\n")

    report = LocalStaticAssessor(tmp_path).assess()

    assert "pyproject.toml" in report.inventory.manifests
    assert "package.json" in report.inventory.manifests
    assert report.safety["does_not_execute_project_code"] is True
    assert report.safety["does_not_contact_external_services"] is True
    assert report.inventory.analyzed_files >= 3


def test_assessor_detects_high_risk_execution_and_secret_patterns(tmp_path):
    write(
        tmp_path / "agent" / "runner.py",
        "import os\npassword='hardcoded'\nos.system('echo bad')\n",
    )

    report = LocalStaticAssessor(tmp_path).assess()
    rule_ids = {finding.rule_id for finding in report.findings}

    assert "secret_literal" in rule_ids
    assert "unsafe_python_execution" in rule_ids
    assert report.highest_severity == Severity.HIGH


def test_assessor_detects_config_container_and_ci_patterns(tmp_path):
    write(tmp_path / "Dockerfile", "FROM python:3.11\nUSER root\n")
    write(tmp_path / ".github" / "workflows" / "tests.yml", "steps:\n  - uses: actions/checkout@v4\n")
    write(tmp_path / "config.py", "REQUESTS_VERIFY=False\nHOST='0.0.0.0'\n")

    report = LocalStaticAssessor(tmp_path).assess()
    rule_ids = {finding.rule_id for finding in report.findings}

    assert "docker_root" in rule_ids
    assert "github_action_unpinned" in rule_ids
    assert "wide_bind" in rule_ids


def test_assessor_skips_excluded_trees(tmp_path):
    write(tmp_path / "node_modules" / "pkg" / "index.js", "const secret_key = 'x';\n")
    write(tmp_path / "src" / "index.js", "console.log('safe');\n")

    report = LocalStaticAssessor(tmp_path).assess()

    assert all(not finding.path.startswith("node_modules/") for finding in report.findings)
    assert report.inventory.skipped_files >= 1


def test_assessor_supports_extra_excludes(tmp_path):
    write(tmp_path / "generated" / "bad.py", "eval('1+1')\n")
    write(tmp_path / "src" / "ok.py", "print('ok')\n")

    report = LocalStaticAssessor(tmp_path, extra_excludes=("generated",)).assess()

    assert all(not finding.path.startswith("generated/") for finding in report.findings)


def test_report_json_and_markdown_render(tmp_path):
    write(tmp_path / "requirements.txt", "flask\n")

    report = LocalStaticAssessor(tmp_path).assess()
    js = report.to_json()
    md = report.to_markdown()

    assert '"local_only": true' in js
    assert "# Hancock Local Static Assessment" in md
    assert "requirements.txt" in md


def test_cli_success_returns_zero(tmp_path, capsys):
    write(tmp_path / "README.md", "hello\n")

    rc = main([str(tmp_path), "--format", "json"])

    assert rc == 0
    assert '"does_not_run_shell_commands": true' in capsys.readouterr().out


def test_cli_fail_on_high_returns_two(tmp_path, capsys):
    write(tmp_path / "bad.py", "eval(user_input)\n")

    rc = main([str(tmp_path), "--fail-on", "high"])

    assert rc == 2
    assert '"highest_severity": "high"' in capsys.readouterr().out


def test_cli_fail_on_medium_returns_one(tmp_path, capsys):
    write(tmp_path / "bad.py", "yaml.load(data)\n")

    rc = main([str(tmp_path), "--fail-on", "medium"])

    assert rc == 1
    assert '"highest_severity": "medium"' in capsys.readouterr().out
