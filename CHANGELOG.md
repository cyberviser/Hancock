# Changelog

All notable changes to Hancock by CyberViser are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [0.2.0] — 2026-02-21

### Added
- **API authentication** — Bearer token auth on all `/v1/*` endpoints via `HANCOCK_API_KEY` env var
- **Rate limiting** — configurable per-IP request throttle (`HANCOCK_RATE_LIMIT`, default 60 req/min)
- **Netlify auto-deploy workflow** (`.github/workflows/deploy.yml`) — pushes to `docs/` auto-deploy to `cyberviser.netlify.app`
- **Pricing page** (`docs/pricing.html`) — 4-tier plan: Community / Pro $299/mo / Enterprise / API $0.008/req
- **Contact/lead form** (`docs/contact.html`) — lead capture form via Formspree → cyberviser@proton.me
- **Fine-tuning v2** (`hancock_finetune_v2.py`) — dedup, LoRA r=32, resume from checkpoint, HuggingFace Hub push
- **Outreach templates** (`OUTREACH_TEMPLATES.md`) — 5 ready-to-send cold email/DM templates + target list

### Changed
- `.env.example` — documents `HANCOCK_API_KEY` and `HANCOCK_RATE_LIMIT`
- `docs/index.html` — updated nav and hero CTA to point to Pricing page
- `docs/_redirects` — added `/pricing` and `/contact` Netlify routes

### Security
- All API endpoints now return `401 Unauthorized` without valid Bearer token (when auth is configured)
- `429 Too Many Requests` on rate limit breach
- Auth disabled by default for local dev (set `HANCOCK_API_KEY` in production)

---

## [0.1.0] — 2025-02-21

### Added
- **Hancock Agent** (`hancock_agent.py`) — CLI + REST API with NVIDIA NIM inference backend
- **Three specialist modes**: Pentest (`/mode pentest`), SOC Analyst (`/mode soc`), Auto (`/mode auto`)
- **REST API endpoints**:
  - `GET  /health` — status and capabilities
  - `POST /v1/chat` — conversational AI with history and streaming
  - `POST /v1/ask` — single-shot question
  - `POST /v1/triage` — SOC alert triage with MITRE ATT&CK mapping
  - `POST /v1/hunt` — threat hunting query generator (Splunk/Elastic/Sentinel)
  - `POST /v1/respond` — PICERL incident response playbook generator
- **Data pipeline** (`hancock_pipeline.py`) — automated dataset collection and formatting
- **Collectors**: MITRE ATT&CK, NVD/CVE, Pentest KB, SOC KB
- **Fine-tuning** (`hancock_finetune.py`) — LoRA fine-tuning on Mistral 7B via Unsloth
- **Training datasets**: `data/hancock_pentest_v1.jsonl`, `data/hancock_v2.jsonl`
- **Jupyter notebook**: `Hancock_CyberViser_Finetune.ipynb`
- **Burp Suite + Brave integration**: `burp-brave.sh`, `setup-burp-brave.sh`
- **Website**: dark hacker-themed GitHub Pages landing page (`docs/index.html`)
- **Business Proposal**: `BUSINESS_PROPOSAL.md`
- **GitHub project structure**: CI workflow, issue templates, PR template, CONTRIBUTING.md

### Infrastructure
- NVIDIA NIM inference backend (Mistral 7B default)
- Flask REST API server
- MIT License

---

## [Unreleased]

### Planned (Phase 2)
- [ ] Expanded SOC fine-tuning dataset
- [ ] Detection engineering (Sigma/YARA rule generation pipeline)
- [ ] Threat intelligence feed integration (MISP/TAXII/STIX)
- [ ] Burp Suite extension (Python)
- [ ] Docker image on Docker Hub

### Planned (Phase 3)
- [ ] CISO Strategy mode
- [ ] Compliance automation (SOC2, ISO 27001, NIST CSF)
- [ ] Executive report generator

---

[0.1.0]: https://github.com/cyberviser/Hancock/releases/tag/v0.1.0
