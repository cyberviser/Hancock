# Hancock — Competitive Landscape Analysis

> **Last Updated:** July 2025  
> **Version:** v0.4.0  
> **Prepared by:** CyberViser Team

---

## Executive Summary

Hancock occupies a unique position in the AI-powered cybersecurity tooling space as a **self-hostable, fine-tuned model with a full REST API**. Most competitors are either locked to proprietary platforms (ChatGPT, cloud-only) or lack domain-specific fine-tuning. This analysis covers the primary competitor — Arcanum — and the broader open-source landscape.

---

## 1. Primary Competitor: Arcanum Cyber Security Bot

| Attribute | Arcanum | Hancock |
|---|---|---|
| **Creator** | Jason Haddix (Arcanum Security) | CyberViser |
| **Platform** | ChatGPT custom GPT (GPT Store) | Self-hosted / Fly.io / HF Spaces |
| **Base Model** | OpenAI GPT-4 (closed) | Mistral-7B-Instruct-v0.3 (fine-tuned) |
| **Self-Hosting** | ❌ No | ✅ Yes (Docker, Ollama, bare metal) |
| **REST API** | ❌ No (ChatGPT UI only) | ✅ 12 endpoints |
| **Offline / Air-Gapped** | ❌ No | ✅ Yes |
| **Cost** | $20/mo (ChatGPT Plus required) | Free (personal/research) |
| **Fine-Tuned** | ❌ No (prompt-engineered GPT wrapper) | ✅ LoRA fine-tuned on 5,670 cybersecurity samples |
| **Open Weights** | ❌ No | ✅ Published on Hugging Face |
| **SDKs** | ❌ None | ✅ Python, TypeScript, Go |

### Arcanum Bot Suite

Arcanum is not a single bot — it's a suite of 10 ChatGPT custom GPTs:

| Bot | Focus | Hancock Equivalent |
|---|---|---|
| Arcanum Cyber Security Bot | AppSec, pentest, vuln discovery | `/v1/hunt`, `/v1/code` (pentest + code modes) |
| Arcanum OSQuery Bot | Endpoint visibility queries | — (gap) |
| Arcanum YARA Bot | Malware indicators, YARA rules | `/v1/yara` (yara mode) ✅ |
| Arcanum Suricata Bot | Network IDS rule generation | — (gap, partial via sigma) |
| Arcanum Splunk Bot | SIEM query optimization | — (gap) |
| Arcanum SOC Manager Bot | Incident coordination | `/v1/respond` (soc mode) ✅ |
| Arcanum ELK Sec Bot | Elastic Security operations | — (gap) |
| Arcanum Incident Responder Bot | IR playbooks | `/v1/respond` (soc mode) ✅ |
| Arcanum Tabletop Designer Bot | TTX exercise design | — (gap) |
| Arcanum Acquisition & Recon Bot | Recon & attack surface | `/v1/hunt` (pentest mode) ✅ |

### Arcanum Strengths
- **Brand recognition** — Jason Haddix is a well-known figure in the bug bounty and appsec community
- **GPT-4 backbone** — leverages the most capable commercial LLM
- **Breadth** — 10 specialized bots covering detection, response, and simulation
- **Community** — active Discord, training events, YouTube content
- **Low barrier** — no setup needed if user already has ChatGPT Plus

### Arcanum Weaknesses (Hancock's Advantages)
- **Vendor lock-in** — entirely dependent on OpenAI / ChatGPT platform
- **No API** — cannot integrate into CI/CD, SOAR, SIEM, or automation pipelines
- **No self-hosting** — data leaves the user's environment (compliance risk for enterprises)
- **No offline capability** — useless in air-gapped or restricted networks
- **Subscription cost** — $20/mo minimum, per-user
- **No fine-tuning** — prompt-engineered GPT wrapper, not a domain-trained model
- **Fragmented UX** — 10 separate bots instead of one unified system
- **No open weights** — users cannot inspect, audit, or extend the model

---

## 2. Open-Source Competitors

| Tool | Self-Hosted | Fine-Tuned | REST API | Specialist Modes | Active |
|---|---|---|---|---|---|
| **Hancock** | ✅ | ✅ (Mistral-7B) | ✅ (12 endpoints) | 8 modes | ✅ |
| **PentestGPT** | ✅ | ❌ (GPT wrapper) | ❌ | Terminal-guided | ✅ |
| **HackingBuddyGPT** | ✅ | ❌ (GPT wrapper) | ❌ | Chat assistant | ✅ |
| **CAI** | ✅ | ❌ | ❌ | Distributed agents | ⚠️ |
| **Nebula** | ✅ | ❌ | ❌ | Anomaly detection | ⚠️ |
| **AutoPentest-DRL** | ✅ | ❌ | ❌ | Multi-agent | ⚠️ |

### Key Differentiators vs Open-Source Field
1. **Fine-tuned model** — Hancock is one of the only tools with a purpose-built, LoRA fine-tuned model trained on curated cybersecurity data (MITRE ATT&CK, NVD CVE, CISA KEV, Atomic Red Team, GHSA)
2. **Production REST API** — 12 documented endpoints with OpenAPI spec, ready for pipeline integration
3. **Multiple deployment targets** — Docker, Ollama, Fly.io, HF Spaces, bare metal
4. **Client SDKs** — Python, TypeScript, Go packages for rapid integration
5. **Unified system** — 8 specialist modes in one model, not separate tools

---

## 3. Commercial / Enterprise Competitors

| Platform | Focus | Self-Hosted | Pricing |
|---|---|---|---|
| **Darktrace** | Network anomaly detection, autonomous response | Cloud/On-prem | Enterprise ($$$) |
| **CrowdStrike Falcon** | EDR, XDR, threat intelligence | Cloud | Enterprise ($$$) |
| **SentinelOne** | Autonomous endpoint protection | Cloud | Enterprise ($$$) |
| **Microsoft Copilot for Security** | SOC assistant, incident triage | Cloud (Azure) | Per-usage ($4/query) |

These are not direct competitors — they are full-platform enterprise security products. Hancock competes in the **AI cybersecurity assistant / co-pilot** segment, not the endpoint protection market.

---

## 4. Competitive Positioning

### Hancock's Unique Value Proposition

```
"The only self-hostable, fine-tuned AI cybersecurity agent with a production REST API."
```

### Target Segments Where Hancock Wins

| Segment | Why Hancock Wins |
|---|---|
| **Government / Defense** | Air-gapped deployment, no data exfiltration risk |
| **Enterprise Security Teams** | Self-hosted, API-driven, integrates with SOAR/SIEM |
| **MSSPs** | Multi-tenant API, white-label potential |
| **Bug Bounty Hunters** | Free, offline-capable, no subscription needed |
| **Security Researchers** | Open weights, inspectable, fine-tunable |
| **DevSecOps** | CI/CD integration via REST API and SDKs |

### Where Arcanum Wins (and How to Close the Gap)

| Arcanum Advantage | Hancock Response |
|---|---|
| GPT-4 reasoning quality | Continue fine-tuning; upgrade base model as open-source LLMs improve |
| Brand / community (Haddix) | Build community via content, training, and open-source contributions |
| Breadth (10 bots) | Already have 8 modes; add Suricata, OSQuery, Splunk, TTX modes |
| Zero-setup onboarding | HF Spaces demo provides zero-setup experience |
| ChatGPT ecosystem | Not addressable — different market segment |

---

## 5. Feature Gap Analysis

### Modes to Add (Inspired by Arcanum Suite)

| Priority | New Mode | Covers | Effort |
|---|---|---|---|
| 🔴 High | `suricata` | Network IDS rule generation | Medium — add training data + endpoint |
| 🔴 High | `osquery` | Endpoint visibility queries | Medium — add training data + endpoint |
| 🟡 Medium | `splunk` | SIEM query optimization (SPL) | Medium — add training data + endpoint |
| 🟡 Medium | `elk` | Elastic/KQL query generation | Medium — add training data + endpoint |
| 🟢 Low | `tabletop` | TTX scenario design | Low — mostly prompt engineering |

### Other Enhancements

| Enhancement | Impact | Effort |
|---|---|---|
| Streaming responses (`/v1/chat/stream`) | UX parity with ChatGPT | Medium |
| Web UI chat interface | Lower barrier for non-API users | Medium |
| Plugin/tool-use (function calling) | Enable agentic workflows | High |
| RAG over user documents | Custom knowledge bases | High |
| Multi-model support (swap base LLM) | Future-proofing | Medium |

---

## 6. Sources

- [Arcanum Cyber Security Bot — ChatGPT](https://chatgpt.com/g/g-HTsfg2w2z-arcanum-cyber-security-bot)
- [Arcanum AI Bots — arcanum-sec.com](https://www.arcanum-sec.com/bots)
- [Arcanum Security — Official Site](https://www.arcanum-sec.com/)
- [AIPRM — Arcanum GPT Profile](https://app.aiprm.com/gpts/g-HTsfg2w2z/arcanum-cyber-security-bot)
- [Black Hills InfoSec — AI Pentesting with Arcanum](https://www.blackhillsinfosec.com/penetration-testing-with-ai-part-3/)
- [Visive AI — AI-Enhanced Pentesting Review](https://www.visive.ai/news/ai-enhanced-penetration-testing-arcanum-cyber-security-bot)
- [Open Source AI Pentesting Tools](https://blog.spark42.tech/top-10-open-source-ai-agent-penetration-testing-projects/)
- [10 Open Source AI Agents for Cybersecurity](https://www.itera-research.com/10-best-open-source-ai-agents/)

---

*This document is confidential to CyberViser. Do not distribute externally.*
