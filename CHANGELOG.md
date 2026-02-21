# Changelog

All notable changes to Hancock by CyberViser are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [0.3.0] — 2026-02-21

### Added
- **Qwen 2.5 Coder 32B integration** — `MODELS` dict with aliases (`mistral-7b`, `qwen-coder`, `llama-8b`, `mixtral-8x7b`)
- **`/v1/code` REST endpoint** — security code generation: YARA/Sigma rules, KQL/SPL queries, exploit PoCs, CTF scripts
- **`/mode code` CLI command** — auto-switches to Qwen Coder model on entry
- **`CODE_SYSTEM` prompt** — security code specialist persona for Python, Bash, PowerShell, Go, KQL, SPL, YARA, Sigma
- **Python SDK** (`clients/python/`) — `HancockClient` class with `ask/code/triage/hunt/respond/chat` methods
- **Python CLI** (`clients/python/hancock_cli.py`) — interactive + one-shot, `/mode`, `/model` commands, multi-turn history
- **Node.js SDK** (`clients/nodejs/`) — streaming CLI backed by NVIDIA NIM, ES module, same model aliases
- **`pyproject.toml`** — Python SDK installable as `hancock-client` package via `pip install -e .`
- **`__init__.py`** for Python SDK package — exports `HancockClient`, `MODELS`, `__version__`
- **GPU training page** (`docs/train.html`) — 4 free GPU options (Modal ⭐, Kaggle, Colab, NVIDIA NIM)
- **Modal.com GPU runner** (`train_modal.py`) — full LoRA pipeline: data → train → GGUF export, free $30/mo
- **Kaggle fine-tune notebook** (`Hancock_Kaggle_Finetune.ipynb`) — 30h/week free T4
- **Manual finetune workflow** (`.github/workflows/finetune.yml`) — GPU choice dropdown (T4/A10G/A100)
- **Makefile `client-python` + `client-node` targets** — one-command SDK launch
- **1,375 training samples** (`data/hancock_v2.jsonl`) — 691 MITRE ATT&CK + 600 CVEs + 75 pentest/SOC KB + 9 Sigma

### Changed
- `requirements.txt` — added `openai>=1.0.0`, `flask>=3.0.0`, `python-dotenv>=1.0.0`
- `docs/api.html` — added `/v1/code` endpoint, Python SDK + Node.js SDK sections, updated Modes table with `code` mode
- `/health` endpoint — now exposes `modes_available`, `models_available`, and all 6 endpoints
- `.env.example` — documents `HANCOCK_CODER_MODEL=qwen/qwen2.5-coder-32b-instruct`

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
