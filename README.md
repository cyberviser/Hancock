# 🛡️ Hancock — CyberViser AI Security Agent

<div align="center">

![Hancock Banner](https://img.shields.io/badge/CyberViser-Hancock-00ff88?style=for-the-badge&logo=hackthebox&logoColor=black)

[![License: Apache%202.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Model](https://img.shields.io/badge/Model-Mistral%207B-orange?logo=huggingface)](https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.3)
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA-NIM-76b900?logo=nvidia)](https://build.nvidia.com)
[![Portfolio](https://img.shields.io/badge/Portfolio-0AI-00ff88?style=for-the-badge&logo=githubpages&logoColor=black)](https://0ai-cyberviser.github.io/0ai/)
[![Docs](https://img.shields.io/badge/Docs-Repository-0ea5e9?style=flat-square&logo=readthedocs&logoColor=white)](docs/)

**Automate cybersecurity through specialized LLMs — from pentesting to SOC analysis.**

[🌐 Portfolio Hub](https://0ai-cyberviser.github.io/0ai/) · [📚 Docs](docs/) · [🧾 OpenAPI](docs/openapi.yaml) · [🧭 Public Surface](PUBLIC_SURFACE.md) · [📋 Business Proposal](BUSINESS_PROPOSAL.md) · [🐛 Report Bug](https://github.com/cyberviser/Hancock/issues/new/choose) · [✨ Request Feature](https://github.com/cyberviser/Hancock/issues/new/choose)

</div>

---

## 🚀 What is Hancock?

Hancock is **CyberViser's** AI-powered cybersecurity agent, fine-tuned on Mistral 7B using:
- **MITRE ATT&CK** — TTPs, tactics, procedures
- **NVD/CVE** — Real vulnerability data
- **Pentest Knowledge Base** — Recon, exploitation, post-exploitation

It operates in nine specialist modes and exposes a clean REST API.

Public company and repository routing is documented in [PUBLIC_SURFACE.md](PUBLIC_SURFACE.md) so
README links, support paths, security reporting, and PR metadata stay aligned
across forks and upstream repos.

```
╔══════════════════════════════════════════════════════════╗
║  ██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ██████╗  ██████╗██╗ ║
║  ██║  ██║██╔══██╗████╗  ██║██╔════╝██╔═══██╗██╔════╝██║ ║
║  ███████║███████║██╔██╗ ██║██║     ██║   ██║██║     ██║ ║
║  ██╔══██║██╔══██║██║╚██╗██║██║     ██║   ██║██║     ██╚╗║
║  ██║  ██║██║  ██║██║ ╚████║╚██████╗╚██████╔╝╚██████╗╚═╝║║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝  ╚═════╝   ║
║          CyberViser — Pentest + SOC Specialist           ║
╚══════════════════════════════════════════════════════════╝
```

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
- [CLI Commands](#-cli-commands)
- [Environment Variables](#-environment-variables)
- [Backend Selection](#-backend-selection)
- [OSINT Geolocation Intelligence](#-osint-geolocation-intelligence)
- [Security Tool Integrations](#-security-tool-integrations)
- [Client SDKs](#-client-sdks)
- [Monitoring & Observability](#-monitoring--observability)
- [Deployment](#-deployment)
- [Fuzzing & Security Testing](#-fuzzing--security-testing)
- [CI/CD Pipelines](#-cicd-pipelines)
- [Hugging Face Spaces](#-hugging-face-spaces)
- [Fine-Tuning](#-fine-tuning)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Mode | Description | Status |
|------|-------------|--------|
| 🔴 **Pentest Specialist** | Recon, exploitation, CVE analysis, PTES reporting | ✅ Live |
| 🔵 **SOC Analyst** | Alert triage, SIEM queries, PICERL IR, Sigma/YARA | ✅ Live |
| ⚡ **Auto** | Context-aware switching between pentest + SOC | ✅ Live |
| 💻 **Code** | Security code: YARA, KQL, SPL, Sigma, Python, Bash | ✅ Live |
| 👔 **CISO** | Compliance, risk reporting, board summaries, gap analysis | ✅ Live |
| 🔍 **Sigma** | Sigma detection rule authoring with ATT&CK tagging | ✅ Live |
| 🦠 **YARA** | YARA malware detection rule authoring | ✅ Live |
| 🔎 **IOC** | Threat intelligence enrichment for IOCs | ✅ Live |
| 🌍 **OSINT** | IP/domain geolocation, infrastructure mapping, predictive analytics | ✅ Live |
| 🔐 **GraphQL Security** | GraphQL auth/authz testing, IDOR detection, JWT security | ✅ Live |

---

## ⚡ Quick Start

### 1. Install dependencies

```bash
git clone https://github.com/0ai-Cyberviser/Hancock.git
cd Hancock
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure your API key

```bash
cp .env.example .env
# Edit .env and add your NVIDIA API key
# Get one free at: https://build.nvidia.com
```

### 3. Run the CLI

```bash
export NVIDIA_API_KEY="nvapi-..."
python hancock_agent.py
```

### 4. Or run as a REST API server

```bash
python hancock_agent.py --server --port 5000
```

### 5. Build the training dataset

```bash
# v2 dataset (pentest + SOC):
python hancock_pipeline.py --phase all

# v3 dataset (+ CISA KEV + Atomic Red Team + GitHub Advisories):
python hancock_pipeline.py --phase 3
```

### 6. Fine-tune Hancock on Mistral 7B

```bash
python hancock_finetune.py
```

### 7. Run the local `0AI` CLI

`ai_agent.py` is a separate local Ollama-backed CLI. It now has a stable run loop through [`script/build_and_run.sh`](script/build_and_run.sh).

```bash
# preflight only: Python + openai + Ollama endpoint + required 0ai model
make run-0ai-verify

# launch the local 0AI CLI
make run-0ai
```

Useful modes:

```bash
make run-0ai-logs
make run-0ai-debug
```

If you use the Codex app locally, the Run button is wired to `./script/build_and_run.sh` through `.codex/environments/environment.toml`.

---

## 🌐 API Reference

Start the server: `python hancock_agent.py --server`

`/internal/diagnostics` stays hidden unless `HANCOCK_ENABLE_INTERNAL_DIAGNOSTICS`
is set to a truthy value (`1`, `true`, `yes`, or `on`). When enabled, it still
requires `HANCOCK_API_KEY` to be configured and uses the normal Bearer auth and
rate-limit checks.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/health`       | Agent status and capabilities |
| `GET`  | `/metrics`      | Prometheus-compatible request counters |
| `GET`  | `/internal/diagnostics` | Auth-gated internal runtime metadata |
| `GET`  | `/v1/agents`    | All agent system prompts and defaults |
| `POST` | `/v1/chat`      | Conversational AI with history + streaming |
| `POST` | `/v1/ask`       | Single-shot question |
| `POST` | `/v1/triage`    | SOC alert triage + MITRE ATT&CK mapping |
| `POST` | `/v1/hunt`      | Threat hunting query generator (Splunk/Elastic/Sentinel) |
| `POST` | `/v1/respond`   | PICERL incident response playbook |
| `POST` | `/v1/code`      | Security code generation (YARA/Sigma/KQL/SPL) |
| `POST` | `/v1/ciso`      | CISO advisory: risk, compliance, board reports, gap analysis |
| `POST` | `/v1/sigma`     | Sigma detection rule generator |
| `POST` | `/v1/yara`      | YARA malware detection rule generator |
| `POST` | `/v1/ioc`       | IOC threat intelligence enrichment |
| `POST` | `/v1/geolocate` | OSINT geolocation for IPs/domains |
| `POST` | `/v1/predict-locations` | Predict future threat infrastructure locations |
| `POST` | `/v1/map-infrastructure` | Map and cluster threat infrastructure geographically |
| `POST` | `/v1/webhook`   | Ingest alerts from Splunk/Elastic/Sentinel/CrowdStrike |

### Examples

**Alert Triage:**
```bash
curl -X POST http://localhost:5000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"alert": "Mimikatz detected on DC01 at 03:14 UTC"}'
```

**Threat Hunting (Splunk):**
```bash
curl -X POST http://localhost:5000/v1/hunt \
  -H "Content-Type: application/json" \
  -d '{"target": "lateral movement via PsExec", "siem": "splunk"}'
```

**Sigma Rule Generation:**
```bash
curl -X POST http://localhost:5000/v1/sigma \
  -H "Content-Type: application/json" \
  -d '{"description": "Detect LSASS memory dump", "logsource": "windows sysmon", "technique": "T1003.001"}'
```

**YARA Rule Generation:**
```bash
curl -X POST http://localhost:5000/v1/yara \
  -H "Content-Type: application/json" \
  -d '{"description": "Cobalt Strike beacon default HTTP profile", "file_type": "PE"}'
```

**Internal Diagnostics:**
```bash
curl http://localhost:5000/internal/diagnostics \
  -H "Authorization: Bearer $HANCOCK_API_KEY"
```

**IOC Enrichment:**
```bash
curl -X POST http://localhost:5000/v1/ioc \
  -H "Content-Type: application/json" \
  -d '{"indicator": "185.220.101.35", "type": "ip"}'
```

**OSINT Geolocation:**
```bash
curl -X POST http://localhost:5000/v1/geolocate \
  -H "Content-Type: application/json" \
  -d '{"indicators": ["185.220.101.35", "evil.example.com"]}'
```

**Predict Threat Infrastructure Locations:**
```bash
curl -X POST http://localhost:5000/v1/predict-locations \
  -H "Content-Type: application/json" \
  -d '{"historical_data": [{"indicator": "185.220.101.35", "indicator_type": "ip", "geo_results": [{"ip": "185.220.101.35", "country_code": "NL", "asn": "AS9009"}], "first_seen": "2025-01-01T00:00:00Z", "last_seen": "2025-03-01T00:00:00Z"}]}'
```

**Map Threat Infrastructure:**
```bash
curl -X POST http://localhost:5000/v1/map-infrastructure \
  -H "Content-Type: application/json" \
  -d '{"indicators": ["185.220.101.35", "45.33.32.156", "93.184.216.34"]}'
```

**GraphQL Security Testing:**
```bash
# Generate GraphQL security knowledge base
python collectors/graphql_security_kb.py

# Run GraphQL security tests (requires authorization)
python collectors/graphql_security_tester.py \
  --url https://api.example.com/graphql \
  --token <jwt-token> \
  --verbose \
  --report graphql_security_report.json
```

**CISO Board Summary:**
```bash
curl -X POST http://localhost:5000/v1/ciso \
  -H "Content-Type: application/json" \
  -d '{"question": "Summarise top 5 risks for the board", "output": "board-summary", "context": "50-person SaaS, AWS"}'
```

**Incident Response Playbook:**
```bash
curl -X POST http://localhost:5000/v1/respond \
  -H "Content-Type: application/json" \
  -d '{"incident": "ransomware"}'
```

> 📖 Full OpenAPI 3.1.0 spec: [`docs/openapi.yaml`](docs/openapi.yaml) · [Docs source](docs/)

### CLI Commands

```
/mode pentest   — switch to Pentest Specialist
/mode soc       — switch to SOC Analyst
/mode auto      — combined persona (default)
/mode code      — security code (Qwen Coder 32B)
/mode ciso      — CISO strategy & compliance
/mode sigma     — Sigma detection rule authoring
/mode yara      — YARA malware detection rule authoring
/mode ioc       — IOC threat intelligence enrichment
/mode osint     — OSINT geolocation intelligence analyst
/clear          — clear conversation history
/history        — show history
/model <id>     — switch active model
/exit           — quit
```

### Local 0AI CLI

The repo also includes a local `0AI` runner for Ollama-backed defensive workflows:

```bash
make run-0ai-verify
make run-0ai
```

Notes:
- `make run-0ai-verify` validates the local scaffold and attempts a live Ollama probe when available.
- `make run-0ai` launches [`ai_agent.py`](ai_agent.py) against `OLLAMA_BASE_URL`.
- Override the model with `ZEROAI_MODEL=0ai make run-0ai` or any other local Ollama tag.

---

## 🔧 Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|----------|-------------|---------|
| `HANCOCK_LLM_BACKEND` | Backend engine: `ollama` \| `nvidia` \| `openai` | `ollama` |
| `OLLAMA_BASE_URL` | Ollama server URL | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama chat model | `llama3.1:8b` |
| `OLLAMA_CODER_MODEL` | Ollama code generation model | `qwen2.5-coder:7b` |
| `ZEROAI_MODEL` | Optional model override for the local `0AI` CLI | `0ai` |
| `ZEROAI_DEFAULT_MODE` | Default mode for the local `0AI` CLI | `osint` |
| `NVIDIA_API_KEY` | NVIDIA NIM API key ([get free](https://build.nvidia.com)) | — |
| `OPENAI_API_KEY` | OpenAI API key (fallback) | — |
| `OPENAI_ORG_ID` | OpenAI organization ID | — |
| `HANCOCK_MODEL` | NIM/OpenAI model override | `mistralai/mistral-7b-instruct-v0.3` |
| `HANCOCK_CODER_MODEL` | NIM/OpenAI code model | `qwen/qwen2.5-coder-32b-instruct` |
| `HANCOCK_PORT` | REST API server port | `5000` |
| `HANCOCK_API_KEY` | Bearer token for API auth (empty = no auth) | — |
| `HANCOCK_RATE_LIMIT` | Max requests per IP per minute | `60` |
| `HANCOCK_ENABLE_INTERNAL_DIAGNOSTICS` | Enable `GET /internal/diagnostics` for operators | disabled |
| `HANCOCK_WEBHOOK_SECRET` | HMAC-SHA256 secret for `/v1/webhook` | — |
| `HANCOCK_SLACK_WEBHOOK` | Slack incoming webhook URL | — |
| `HANCOCK_TEAMS_WEBHOOK` | Microsoft Teams incoming webhook URL | — |
| `IPINFO_TOKEN` | ipinfo.io API token (OSINT geolocation primary source) | — |
| `HANCOCK_ALLOW_INSECURE_GEOIP` | Allow plaintext `ip-api.com` fallback for OSINT lookups | disabled |
| `ABUSEIPDB_KEY` | AbuseIPDB API key (threat enrichment) | — |
| `VT_API_KEY` | VirusTotal API key (threat enrichment) | — |

---

## 🔀 Backend Selection

Hancock uses one canonical backend selection strategy:

1. **Primary backend** from `HANCOCK_LLM_BACKEND` (default: `ollama`).
   - `ollama` uses `OLLAMA_BASE_URL` + `OLLAMA_MODEL` / `OLLAMA_CODER_MODEL`
   - `nvidia` uses NVIDIA NIM (`NVIDIA_API_KEY`) and `HANCOCK_MODEL` / `HANCOCK_CODER_MODEL`
   - `openai` uses `OPENAI_API_KEY` and `OPENAI_MODEL` / `OPENAI_CODER_MODEL`
2. **Automatic runtime fallback**: if a primary Ollama or NVIDIA request fails, Hancock retries with OpenAI when `OPENAI_API_KEY` is configured.
3. **Startup fallback**: if the configured backend cannot initialize, Hancock attempts OpenAI before exiting.

This fallback order is therefore:
**configured primary (`ollama`/`nvidia`/`openai`) → OpenAI (if configured) → exit with configuration error.**

---

## 🌍 OSINT Geolocation Intelligence

The OSINT module (`collectors/osint_geolocation.py`) provides multi-source IP/domain geolocation, threat infrastructure mapping, geographic clustering, and predictive location analytics.

### Capabilities

- **Multi-source geolocation** — ipinfo.io (primary HTTPS), ipapi.co (secondary HTTPS), optional plaintext ip-api.com fallback
- **Threat enrichment** — AbuseIPDB + VirusTotal integration for risk scoring
- **Infrastructure mapping** — Geographic clustering via Haversine distance, ASN/ISP grouping
- **Predictive analytics** — Forecast future threat infrastructure locations based on historical patterns
- **Risk scoring** — Bulletproof ASN detection, country cyber-risk index (see `collectors/osint_geolocation.py` for the full list)

### CLI Mode

```bash
python hancock_agent.py
# Then type: /mode osint
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/geolocate` | Geolocate a list of IP/domain indicators |
| `POST` | `/v1/predict-locations` | Predict future threat infrastructure locations |
| `POST` | `/v1/map-infrastructure` | Map and cluster indicators geographically |

> 📖 Full guide: [`docs/osint-geolocation.md`](docs/osint-geolocation.md)
>
> 📄 Reporting assets:
> [`templates/osint_report_template.md`](templates/osint_report_template.md) ·
> [`docs/osint-reporting-spec.md`](docs/osint-reporting-spec.md) ·
> [`schemas/osint_report.schema.json`](schemas/osint_report.schema.json) ·
> [`examples/osint_report.dev.json`](examples/osint_report.dev.json)
>
> 🔧 Prototype builder: `python -m collectors.osint_report_builder --help`

### Reporting Scaffold

For defensive reporting workflows, the repo now includes:
- Typed report models and a guarded builder in [`collectors/osint_report_builder.py`](collectors/osint_report_builder.py)
- Published schema in [`docs/schemas/osint_report.schema.json`](docs/schemas/osint_report.schema.json)
- Markdown template in [`docs/templates/osint_report.md.tmpl`](docs/templates/osint_report.md.tmpl)
- Dev defaults in [`docs/config/osint_report.dev.json`](docs/config/osint_report.dev.json)
- Sample payload in [`docs/examples/osint_report.sample.json`](docs/examples/osint_report.sample.json)

Render the sample report scaffold:

```bash
make osint-report
```

Render a specific payload to a file:

```bash
make osint-report OSINT_REPORT_INPUT=path/to/report.json OUTPUT=report.md
```

Emit normalized validated JSON:

```bash
make osint-report-json
```

Run the focused scaffold tests with:

```bash
pytest -q tests/test_osint_report_builder.py tests/test_osint_report_cli.py
```

---

## 🛠️ Security Tool Integrations

Hancock integrates with common security tools for automated reconnaissance and testing:

| Tool | Module | Description |
|------|--------|-------------|
| **Nmap** | `collectors/nmap_recon.py` | Port scanning, service enumeration, XML-to-JSON parsing |
| **SQLMap** | `collectors/sqlmap_exploit.py` | Automated SQL injection testing via SQLMap API |
| **Burp Suite** | `collectors/burp_post_exploit.py` | Active scanning via Burp REST API |

### GraphQL Security Testing

The GraphQL security framework provides automated penetration testing:

```bash
# Generate GraphQL security knowledge base
python collectors/graphql_security_kb.py

# Run GraphQL security tests
python collectors/graphql_security_tester.py \
  --url https://api.example.com/graphql \
  --token <jwt-token> \
  --verbose \
  --report graphql_security_report.json
```

Tests include: introspection detection, IDOR/BOLA, JWT vulnerabilities, mutation authorization bypass, field-level auth flaws, and rate limiting bypasses.

> 📖 Guides: [`docs/graphql-security-guide.md`](docs/graphql-security-guide.md) · [`docs/graphql-security-quickstart.md`](docs/graphql-security-quickstart.md) · [`TOOL_INTEGRATION.md`](TOOL_INTEGRATION.md)

---

## 📦 Client SDKs

### Python SDK

```bash
pip install openai python-dotenv
python clients/python/hancock_cli.py
# or: make client-python
```

See [`clients/python/README.md`](clients/python/README.md) for library usage.

### Node.js SDK

```bash
cd clients/nodejs && npm install
node clients/nodejs/hancock.js
# or: make client-node
```

See [`clients/nodejs/README.md`](clients/nodejs/README.md) for library usage.

---

## 📊 Monitoring & Observability

### Prometheus Metrics

The `/metrics` endpoint exposes Prometheus-compatible metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `hancock_requests_total` | Counter | Total requests |
| `hancock_errors_total` | Counter | Total 4xx/5xx errors |
| `hancock_requests_by_endpoint` | Counter | Requests per endpoint |
| `hancock_requests_by_mode` | Counter | Requests per specialist mode |

Additional metrics (histograms, gauges) are available via `monitoring/metrics_exporter.py` when integrated as middleware — see `docs/monitoring.md`.

### Health Checks

The `/health` endpoint checks backend availability (Ollama, NVIDIA NIM, or OpenAI) with 30-second TTL caching.

Pre-flight validation:
```bash
python deploy/startup_checks.py
```

> 📖 Full guide: [`docs/monitoring.md`](docs/monitoring.md) · [`docs/performance.md`](docs/performance.md)

---

## 🚢 Deployment

### Docker

```bash
# Build image
docker build -t cyberviser/hancock:latest .
# or: make docker

# Run with Docker Compose (Ollama + Hancock)
docker-compose up -d
# or: make docker-up
```

### Kubernetes / Helm

```bash
# Apply manifests directly
kubectl apply -f deploy/k8s/

# Or install via Helm
helm install hancock deploy/helm/ -f deploy/helm/values.yaml
```

Includes HPA (2–10 replicas), ConfigMap, and Secret manifests.

### Terraform (AWS ECS Fargate)

```bash
cd deploy/terraform
terraform init && terraform apply
```

### Fly.io

```bash
flyctl deploy --config fly.toml
# or: make fly-deploy
```

> 📖 Guides: [`docs/deployment.md`](docs/deployment.md) · [`docs/production-checklist.md`](docs/production-checklist.md) · [`docs/ci-cd.md`](docs/ci-cd.md)

---

## 🔒 Fuzzing & Security Testing

Hancock includes [atheris](https://github.com/google/atheris)-based fuzz targets for continuous security testing:

| Target | Module Under Test |
|--------|-------------------|
| `fuzz/fuzz_nvd_parser.py` | NVD CVE parser |
| `fuzz/fuzz_mitre_parser.py` | MITRE ATT&CK parser |
| `fuzz/fuzz_formatter.py` | JSONL formatter |
| `fuzz/fuzz_formatter_v3.py` | v3 formatter |
| `fuzz/fuzz_api_inputs.py` | API endpoint inputs |
| `fuzz/fuzz_webhook_signature.py` | Webhook HMAC verification |
| `fuzz/fuzz_ghsa_parser.py` | GitHub Security Advisory parser |
| `fuzz/fuzz_xml_parsing.py` | XML parsing |

```bash
# Run all fuzz targets (60s each)
make fuzz

# Run a specific fuzz target
make fuzz-target TARGET=fuzz_nvd_parser
```

CIFuzz runs on every PR via `.github/workflows/cifuzz.yml` and daily continuous fuzzing runs via `.github/workflows/continuous-fuzz.yml`.

---

## ⚙️ CI/CD Pipelines

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `test.yml` | Push / PR | Unit and integration test suite |
| `security.yml` | Push / PR | Bandit SAST, pip-audit, Trivy container scan |
| `codeql.yml` | Push / PR | CodeQL static analysis |
| `cifuzz.yml` | PR | CIFuzz atheris fuzz testing |
| `continuous-fuzz.yml` | Daily schedule | Extended continuous fuzzing |
| `benchmark.yml` | PR | Latency regression benchmarking |
| `python-package.yml` | Push | Package distribution |
| `deploy.yml` | Push to main | Automatic deployment to staging |
| `finetune.yml` | Manual | Model fine-tuning pipeline |
| `release.yml` | Tag | GitHub release automation |

---

## 🤗 Hugging Face Spaces

Hancock is available as a free Gradio web UI on Hugging Face Spaces:

```
https://huggingface.co/spaces/cyberviser/hancock
```

To self-host the Spaces app, set these environment variables:

| Variable | Description |
|----------|-------------|
| `HANCOCK_API_URL` | URL of your deployed Hancock instance |
| `HANCOCK_API_KEY` | Bearer token (optional, leave blank if auth is disabled) |

```bash
python spaces_app.py
```

---

## 🤖 Fine-Tuning

Hancock uses **LoRA fine-tuning** on Mistral 7B — trained on a multi-source cybersecurity dataset (MITRE ATT&CK + NVD CVEs + SOC/Pentest KB + CISA KEV + Atomic Red Team + GitHub Security Advisories).

### ⚡ One-Click: Colab / Kaggle (Free T4)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/cyberviser/Hancock/blob/main/Hancock_Universal_Finetune.ipynb)

Works on **both** Google Colab and Kaggle — auto-detects environment:

1. Click the badge above (or import `Hancock_Universal_Finetune.ipynb` on Kaggle)
2. **Enable GPU** (Colab: Runtime → T4 GPU / Kaggle: Settings → Accelerator → T4)
3. **Run all** (~30 min)
4. Downloads GGUF Q4_K_M at end — run locally with Ollama

Or use the CLI script directly:
```bash
python hancock_finetune_v3.py --steps 300 --export-gguf --push-to-hub
```

### CPU Fine-Tuning (No GPU Required)

Install the optional training stack, then run on any machine to fine-tune TinyLlama-1.1B with LoRA:

```bash
make finetune-install

# Quick test (10 steps, ~40 min)
python hancock_cpu_finetune.py --debug

# Full run (500 steps, ~25 hr on 16-core CPU)
python hancock_cpu_finetune.py --max-steps 500

# Load and test the saved adapter
python hancock_cpu_finetune.py --test
```

Pre-trained adapter: [`hancock-cpu-adapter/`](./hancock-cpu-adapter/) — TinyLlama-1.1B + LoRA (r=8, eval_loss=2.084)

### Other GPU Options

| Platform | GPU | Cost | Script |
|----------|-----|------|--------|
| Google Colab | T4 16GB | Free (15 hr/day) | `Hancock_Universal_Finetune.ipynb` |
| Kaggle | T4 16GB | Free (30 hr/week) | `Hancock_Universal_Finetune.ipynb` |
| Modal.com | T4/A10G | Free $30/mo | `modal run train_modal.py` |
| Any GPU server | Any | Varies | `python hancock_finetune_gpu.py` |

### After Training — Run Locally

```bash
# Load fine-tuned model in Ollama
ollama create hancock -f Modelfile.hancock-finetuned
ollama run hancock
```

### Training Data

| Dataset | Samples | Sources | Command |
|---------|---------|---------|---------|
| `hancock_v2.jsonl` | 1,375 | MITRE ATT&CK + NVD CVE + Pentest KB + SOC KB | `python hancock_pipeline.py --phase 2` |
| `hancock_v3.jsonl` | 5,670 | v2 + CISA KEV + Atomic Red Team + GitHub Security Advisories | `python hancock_pipeline.py --phase 3` |

```bash
# Generate latest v3 dataset (internet required)
python hancock_pipeline.py --phase 3

# Or offline-only (static KB, no internet)
python hancock_pipeline.py --kb-only
```

```
data/
├── hancock_pentest_v1.jsonl    # Pentest training data (MITRE + CVE + KB)
├── hancock_v2.jsonl            # v2 dataset — pentest + SOC
└── hancock_v3.jsonl            # v3 dataset — + CISA KEV + Atomic Red Team + GHSA (build with --phase 3)

collectors/
├── mitre_collector.py          # Fetches MITRE ATT&CK TTPs
├── nvd_collector.py            # Fetches NVD/CVE vulnerability data
├── pentest_kb.py               # Pentest knowledge base Q&A
├── soc_collector.py / soc_kb.py
├── cisa_kev_collector.py       # CISA Known Exploited Vulnerabilities
├── atomic_collector.py         # Atomic Red Team test cases
├── ghsa_collector.py           # GitHub Security Advisories
├── graphql_security_kb.py      # GraphQL auth/authz vulnerability KB
└── graphql_security_tester.py  # GraphQL security testing framework

formatter/
├── to_mistral_jsonl.py         # v1 formatter
├── to_mistral_jsonl_v2.py      # v2 formatter
└── formatter_v3.py             # v3 formatter — merges all sources
```

---

## 🗺️ Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 1** | Pentest Specialist + SOC REST API | ✅ Live |
| **Phase 2** | SOC deep specialization + v3 dataset (KEV/Atomic/GHSA) | ✅ Live |
| **Phase 3** | CISO strategy + compliance automation | ✅ Live |
| **Phase 4** | Enterprise platform + SIEM/SOAR integrations | 📋 Planned |

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push and open a PR

---

## 📄 License

**CyberViser / 0ai-Cyberviser Project License** — see [LICENSE](LICENSE) for
repository terms and [OWNERSHIP.md](OWNERSHIP.md) for the control notice.

- ✅ View and study the code
- ✅ Run locally for personal or internal non-commercial evaluation
- ✅ Submit contributions for maintainer review
- ❗ Commercial or production use requires a separate written agreement
- ❗ Branding, repository administration, and merge approval remain controlled by Johnny Watters / `0ai-Cyberviser`
- ❗ Third-party materials and non-assigned contributions remain governed by their own terms
- ❗ Maintainers may require additional written rights confirmation before merging a contribution

**Project contacts:** `0ai@cyberviserai.com` · `cyberviser@proton.me`

---

<div align="center">
Maintained by <a href="https://github.com/0ai-Cyberviser">Johnny Watters (0ai-Cyberviser)</a> · Powered by NVIDIA NIM · Mistral 7B · LoRA
</div>

## Sponsors & Supporters

**Hancock Bronze Supporter** — $5/mo  
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/0aic)

**Scan to join instantly:**
![Hancock Bronze QR](assets/bmc_qr.png)

**Perks you get:**
- Early access to new modes & preview builds
- Exclusive technical deep-dives & roadmap votes
- Priority support + permanent name in Sponsors section
- Private Discord “Hancock Bronze” role & members-only channel

Thank you to every Bronze Supporter powering the next evolution of Hancock.


## Funding & Sponsors

**Support Hancock development**

- **Buy Me a Coffee** (Bronze $5/mo) → [buymeacoffee.com/0aic](https://buymeacoffee.com/0aic)  
  ![Hancock Bronze QR](assets/bmc_qr.png)

- **Open Collective** → [opencollective.com/hancock](https://opencollective.com/hancock) (coming soon — transparent expense tracking)

- **GitHub Sponsors** → [github.com/sponsors/0ai-Cyberviser](https://github.com/sponsors/0ai-Cyberviser)

Every contribution directly funds Hybrid RAG, secure sandboxes, fine-tuning, and Phase 4 enterprise features. Thank you!

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%23EA4AAA?style=for-the-badge&logo=GitHub-Sponsors&logoColor=white)](https://github.com/sponsors/0ai-Cyberviser)

[![Open Collective](https://img.shields.io/badge/Open%20Collective-7F00FF?style=for-the-badge&logo=opencollective&logoColor=white)](https://opencollective.com/oai-cyberviserai)
