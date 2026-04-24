# Security Policy

This repository is operated by Johnny Watters (`0ai-Cyberviser`) as part of the `0AI` company portfolio.

If you discover a security vulnerability or a safety issue, do not open a public issue first.

Report privately to:

- 0ai@cyberviserai.com
- cyberviser@proton.me

Please include:

- affected repository
- impact summary
- reproduction details
- any suggested remediation

If the issue belongs to upstream code in a forked repository, report upstream as well when appropriate.

## Runtime Safety Controls (v0.3.1 stream)

- Intent verification and scope checks run before the new agentic orchestration endpoint executes.
- API access can be protected with `HANCOCK_API_KEYS` (or legacy `HANCOCK_API_KEY`) and `X-API-Key`.
- `/v1/agentic/run` applies route-level rate limiting with per-minute and per-hour controls.
- Sandboxed tool execution uses restrictive Docker flags (`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--network none`).
- Execution remains recommendation-only by default; action execution is intentionally gated off unless later approval wiring is added.
