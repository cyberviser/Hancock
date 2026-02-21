# Security Policy

## Reporting a Vulnerability

**CyberViser takes security seriously.** If you discover a vulnerability in Hancock, please do NOT open a public GitHub issue.

### How to Report

Email: **security@cyberviser.ai**

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested remediation (optional)

We will acknowledge receipt within **48 hours** and aim to resolve critical issues within **7 days**.

### Scope

This policy applies to the **Hancock** codebase:

| Component | In Scope |
|-----------|----------|
| `hancock_agent.py` REST API | ✅ Yes |
| Fine-tuning pipeline | ✅ Yes |
| Data collectors | ✅ Yes |
| GitHub Actions workflows | ✅ Yes |
| Training data / JSONL files | ✅ Yes |
| Third-party dependencies | ⚠️ Report upstream |

### Out of Scope

- Social engineering attacks
- Physical attacks
- Issues requiring physical access to a device
- Issues in dependencies — please report those to the upstream project

### Safe Harbor

We will not take legal action against researchers who:
- Report vulnerabilities in good faith
- Do not access, modify, or delete data beyond what's necessary to demonstrate the issue
- Do not disrupt service availability
- Give us reasonable time to remediate before public disclosure

### Responsible AI Use

Hancock is designed **strictly for authorized security work**. If you discover the model can be prompted to assist with unauthorized attacks, please report this as a safety issue using the process above.

---

*Thank you for helping keep CyberViser and the security community safe.*
