
## v0.3.1 — Agentic Security Controls (PROPOSED/IN PROGRESS)
- [x] LangGraph-style Planner → Recon → Executor → Critic → Reporter orchestration in `langgraph/`.
- [x] API key support for `X-API-Key` via `HANCOCK_API_KEYS` (with legacy `HANCOCK_API_KEY` compatibility).
- [x] Route-specific rate-limiting controls for `/v1/agentic/run`.
- [x] Intent verification and scope enforcement guardrail before orchestration.
- [x] Sandbox runner profiles with least-privilege Docker defaults (`read-only`, `cap-drop=ALL`, `no-new-privileges`, `network=none`).
- [ ] Human-in-the-loop approval flow to allow explicitly authorized execution.
- [ ] OTel spans for each agentic node (non-sensitive telemetry only).

## v0.4.2 — Hybrid RAG + Sponsorship Integration (COMPLETE)
- [x] BuyMeACoffee Bronze tier LIVE → https://buymeacoffee.com/0aic
- [x] Official QR code added (`assets/bmc_qr.png`)
- [x] Full Funding section in README.md (BuyMeACoffee + Open Collective + GitHub Sponsors badges)
- [x] Sponsor Mode node added to LangGraph (priority RAG + early-access)
- [ ] Full Hybrid RAG node (faiss + live collectors)
NIST: AU-6, IR-4

## 2026-04-17 194919 — Continuous Improvement Run v0.4.8
- Fuzz suite completed
- v3 dataset built
- LangGraph + RAG verified
- Sandbox rebuilt
- Security lint passed (Hancock-only, no cuda noise)
- Deps + cppcheck auto-installed
- Script recreated after interrupted paste
- Unstaged changes auto-stashed
