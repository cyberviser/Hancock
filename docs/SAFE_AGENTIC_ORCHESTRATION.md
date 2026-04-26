# Hancock Safe Agentic Orchestration

Hancock adds a review-first agentic orchestration planner.

It does **not** execute commands, run scans, exploit targets, contact third-party systems, upload data, or call external training APIs. It produces a structured plan for human review.

## Goals

- Preserve Hancock's authorized-scope-only pentest guardrails.
- Add planning primitives for Planner → Recon → ExecutorGate → Critic → Reporter.
- Require human approval for active testing.
- Block destructive, credential-theft, evasion, persistence, or exfiltration intent.
- Prepare the project for future LangGraph orchestration without adding hard dependency risk.

## CLI

```bash
python hancock_safety_orchestrator.py \
  "Plan an internal web assessment" \
  --client ACME \
  --engagement "Q2 internal assessment" \
  --allowed-assets "lab.acme.test,10.10.0.0/24" \
  --allow-active-testing \
  --ticket ACME-123 \
  --format markdown
```

## Risk behavior

| Request type | Result |
|---|---|
| Defensive analysis/reporting | Low risk, approval not required |
| Missing scope | High risk, approval required |
| Active testing without active-testing scope | High risk, approval required |
| Active testing inside scope | Medium risk, human approval required |
| Destructive/evasion/credential-theft intent | Blocked |

## Safety contract

- Authorized scope only.
- Responsible disclosure.
- Recommendation-first.
- No command execution.
- No network contact.
- No exploitation.
- Human-in-the-loop for high-risk actions.
- Pentest prompt core remains unchanged.
