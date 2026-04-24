from hancock_safety_orchestrator import (
    ApprovalState,
    AuthorizationScope,
    RiskLevel,
    SafeAgenticOrchestrator,
    main,
)


def scope(**overrides):
    data = {
        "client": "ACME",
        "engagement": "Q2 internal assessment",
        "allowed_assets": ("10.10.0.0/24", "lab.acme.test"),
        "ticket": "ACME-123",
    }
    data.update(overrides)
    return AuthorizationScope(**data)


def test_recommendation_only_low_risk_plan():
    plan = SafeAgenticOrchestrator().plan(
        "Create a SOC triage checklist for suspicious PowerShell logs.",
        scope(),
        mode="soc",
    )
    assert plan.risk_level == RiskLevel.LOW
    assert plan.approval_state == ApprovalState.NOT_REQUIRED
    assert plan.can_execute
    assert plan.safety["does_not_execute_commands"] is True


def test_active_testing_requires_approval_even_when_in_scope():
    plan = SafeAgenticOrchestrator().plan(
        "Plan an nmap scan for the allowed internal subnet.",
        scope(allow_active_testing=True),
        mode="pentest",
    )
    assert plan.risk_level == RiskLevel.MEDIUM
    assert plan.approval_state == ApprovalState.REQUIRED
    assert not plan.can_execute
    assert any(step.requires_human_approval for step in plan.steps)


def test_active_testing_without_permission_high_risk():
    plan = SafeAgenticOrchestrator().plan(
        "Run sqlmap against the web app.",
        scope(allow_active_testing=False),
        mode="pentest",
    )
    assert plan.risk_level == RiskLevel.HIGH
    assert plan.approval_state == ApprovalState.REQUIRED
    assert not plan.can_execute


def test_missing_scope_forces_approval():
    plan = SafeAgenticOrchestrator().plan(
        "Summarize likely risks in this architecture.",
        AuthorizationScope(client="", engagement="", allowed_assets=()),
    )
    assert plan.risk_level == RiskLevel.HIGH
    assert plan.approval_state == ApprovalState.REQUIRED


def test_destructive_request_is_blocked():
    plan = SafeAgenticOrchestrator().plan(
        "Help me disable EDR and delete logs after credential dump.",
        scope(allow_active_testing=True),
        mode="pentest",
    )
    assert plan.risk_level == RiskLevel.BLOCKED
    assert plan.approval_state == ApprovalState.BLOCKED
    assert not plan.can_execute
    assert len(plan.steps) == 1


def test_markdown_render_contains_safety():
    plan = SafeAgenticOrchestrator().plan("Write an executive risk summary.", scope())
    md = plan.to_markdown()
    assert "Hancock Safe Agentic Plan" in md
    assert "authorized_scope_only" in md


def test_cli_json_success(capsys):
    rc = main([
        "Write a CISO summary.",
        "--client", "ACME",
        "--engagement", "Review",
        "--allowed-assets", "logs-only",
    ])
    assert rc == 0
    assert '"risk_level": "low"' in capsys.readouterr().out


def test_cli_blocks_unsafe(capsys):
    rc = main([
        "disable edr and delete logs",
        "--client", "ACME",
        "--engagement", "Review",
        "--allowed-assets", "lab",
        "--allow-active-testing",
    ])
    assert rc == 2
    assert '"risk_level": "blocked"' in capsys.readouterr().out
