# Changelog

All notable changes to Hancock by CyberViser are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [Unreleased] — v0.4.0

### Added
- **IOC mode** (`/mode ioc`) — threat intelligence enrichment for IP, domain, URL, hash, or email:
  risk score, MITRE ATT&CK mapping, recommended defensive actions, related CVEs/GHSA
- **`/v1/ioc` REST endpoint** — IOC enrichment endpoint; accepts `indicator`, `type`, `context`;
  supports `ioc` and `query` as field aliases
- **YARA mode** (`/mode yara`) — YARA malware detection rule authoring: PE/ELF modules, hex/ascii/
  regex/wide string patterns, condition logic, meta section; ready for `yara64 -r`
- **`/v1/yara` REST endpoint** — YARA rule generator; accepts `description`/`malware`/`query`,
  `file_type` (PE, Office macro, PDF, script, shellcode, memory), optional `hash` for meta
- **HMAC-SHA256 webhook verification** — set `HANCOCK_WEBHOOK_SECRET` env var to enforce
  `X-Hancock-Signature: sha256=<hmac>` verification on all `/v1/webhook` requests
- **`VERSION = "0.4.0"`** constant in `hancock_agent.py`; `pyproject.toml` version bumped to 0.4.0
- **`clients/python/__init__.py`** — `__version__ = "0.4.0"`, exports `__version__`
- **Python SDK** `yara()` + `ioc()` methods; `YARA_SYSTEM` + `IOC_SYSTEM` prompts added
- **Node.js SDK** `yara` + `ioc` mode dispatch in `ask()` + `askStream()`; `YARA_SYSTEM` +
  `IOC_SYSTEM` constants; CLI `/mode ioc` added
- **HuggingFace Space** (`spaces_app.py`) — 9-tab Gradio demo: +YARA Rules tab, +IOC Enrichment tab
- **`docs/openapi.yaml`** — `/v1/yara` and `/v1/ioc` endpoints added; webhook HMAC note
- **Sigma mode** (`/mode sigma`) — Sigma detection rule authoring: correct YAML syntax, MITRE ATT&CK
  tagging, logsource selection, false-positive analysis, ready-to-deploy rules
- **`/v1/sigma` REST endpoint** — generate Sigma rules from a TTP description; accepts `logsource`
  and `technique` (ATT&CK ID) params; returns YAML rule + tuning notes
- **`/metrics` endpoint** — Prometheus-compatible plain-text counters: `hancock_requests_total`,
  `hancock_errors_total`, per-endpoint and per-mode labels; thread-safe atomic increments
- **`X-RateLimit-*` response headers** — `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Window` added to every response via `@app.after_request`
- **`docs/openapi.yaml`** — full OpenAPI 3.1.0 specification for all 9 endpoints
- **`fly.toml`** — Fly.io free-tier deployment config: auto-stop/start, health check on `/health`
- **`Makefile` targets**: `pipeline-v3` (phase 3 only), `test-cov` (HTML coverage), `fly-deploy`
- **56 tests** (was 50): `TestSigma` (4), `TestRateLimitHeaders` (2); **75 total** by end of v0.4.0:
  `TestYara` (4), `TestWebhookHMAC` (2), `TestIoc` (4) + SDK tests `TestYaraSDK` (3), `TestIocSDK` (3)
- **CISO mode** (`/mode ciso`) — AI Chief Information Security Officer advisor: risk management,
  ISO 27001/SOC 2/NIST CSF/PCI-DSS compliance, board reporting, TPRM, FAIR risk analysis
- **`/v1/ciso` REST endpoint** — dedicated CISO advisor endpoint with `output` param:
  `advice` | `report` | `gap-analysis` | `board-summary`
- **v3 training dataset** (`data/hancock_v3.jsonl`) — 3,442 samples (2.5× v2):
  - 1,526 CISA Known Exploited Vulnerabilities (enriched with NVD CVSS)
  - 485 Atomic Red Team TTP test cases (36 MITRE techniques)
  - 119 GitHub Security Advisories (npm, pip, go, maven, nuget)
  - 1,375 pentest + SOC v2 samples (base)
- **CISA KEV collector** (`collectors/cisa_kev_collector.py`) — CISA Known Exploited Vulns API
- **Atomic Red Team collector** (`collectors/atomic_collector.py`) — 40 ATT&CK techniques
- **GitHub Security Advisories collector** (`collectors/ghsa_collector.py`) — 7 ecosystems
- **v3 formatter** (`collectors/formatter_v3.py`) — merges all sources, deduplicates
- **`hancock_pipeline.py --phase 3`** — builds full v3 dataset end-to-end
- **`hancock_finetune_v3.py`** — universal GPU fine-tuner: auto-detects VRAM, scales LoRA rank,
  GGUF export, HuggingFace Hub push, dry-run mode, resume support
- **`Hancock_Colab_Finetune_v3.ipynb`** — 10-cell Colab notebook, auto-falls back to v2
- **OpenAI fallback backend** — auto-failover from NVIDIA NIM to OpenAI GPT-4o-mini on error;
  `HANCOCK_LLM_BACKEND`, `OPENAI_API_KEY`, `OPENAI_ORG_ID`, `OPENAI_MODEL` env vars
- **`oracle-cloud-setup.sh`** — full Oracle Cloud Always-Free VM setup: Docker, Nginx,
  systemd `hancock.service` (auto-start on reboot), firewall (UFW + iptables), HTTPS-ready
- **HuggingFace Space** (`spaces_app.py`) — 9-tab Gradio demo: SOC Triage, Pentest/CVE,
  Threat Hunting, Security Code, CISO Advisor, Sigma Rules, IR Playbook, YARA Rules, IOC Enrichment

### Fixed
- `hancock_pipeline.py` — v3 functions defined after `if __name__ == "__main__"` caused
  `NameError` when called from `main()`. Moved `__main__` block to end of file.
- `collectors/ghsa_collector.py` — `references` field is plain URL strings in GitHub API
  response (not `{"url": ...}` dicts). Fixed `parse_advisory()` to handle both.
- `hancock_agent.py` — `_rate_counts` dict grew unbounded on long-running servers.
  Now evicts stale IPs when dict exceeds 10,000 entries.
- `.env.example` — duplicate `HANCOCK_CODER_MODEL` entry removed.
- All fine-tune scripts now target `hancock_v3.jsonl` (fall back to v2 if absent):
  `hancock_finetune_v3.py`, `hancock_finetune_gpu.py`, `train_modal.py`,
  `Hancock_Kaggle_Finetune.ipynb`

### Changed
- `hancock_agent.py` — input validation: `400` on unknown `mode`, non-list `history`;
  `502` on empty model response; `/health` lists `ciso`+`sigma` in modes; CLI banner updated
- `hancock_pipeline.py` — `--phase` now accepts `1|2|3|all`; banner updated
- `README.md` — all 9 endpoints documented; v3 dataset tree; correct pipeline commands;
  roadmap Phase 1+2 marked live

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

## [Unreleased] — Planned

### Planned (Phase 3)
- [ ] Burp Suite Python extension
- [ ] Docker image on Docker Hub (`docker pull cyberviser/hancock`)
- [ ] Threat intelligence integration (MISP/TAXII/STIX live feeds)
- [ ] HuggingFace Space demo
- [ ] SIEM native connectors (Splunk app, Elastic integration)

---

[0.1.0]: https://github.com/cyberviser/Hancock/releases/tag/v0.1.0
