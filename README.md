# 🛡️ Hancock — CyberViser AI Security Agent

<div align="center">

![Hancock Banner](https://img.shields.io/badge/CyberViser-Hancock-00ff88?style=for-the-badge&logo=hackthebox&logoColor=black)

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Model](https://img.shields.io/badge/Model-Mistral%207B-orange?logo=huggingface)](https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.3)
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA-NIM-76b900?logo=nvidia)](https://build.nvidia.com)
[![GitHub Pages](https://img.shields.io/badge/Website-Live-00ff88?logo=github)](https://cyberviser.github.io/Hancock/)
[![Netlify](https://img.shields.io/badge/Netlify-Live-00C7B7?style=flat-square&logo=netlify)](https://cyberviser.netlify.app)

**Automate cybersecurity through specialized LLMs — from pentesting to SOC analysis.**

[🌐 Website](https://cyberviser.netlify.app) · [📖 API Docs](https://cyberviser.netlify.app/api) · [📋 Business Proposal](BUSINESS_PROPOSAL.md) · [🐛 Report Bug](https://github.com/cyberviser/Hancock/issues) · [✨ Request Feature](https://github.com/cyberviser/Hancock/issues)

</div>

---

## 🚀 What is Hancock?

Hancock is **CyberViser's** AI-powered cybersecurity agent, fine-tuned on Mistral 7B using:
- **MITRE ATT&CK** — TTPs, tactics, procedures
- **NVD/CVE** — Real vulnerability data
- **Pentest Knowledge Base** — Recon, exploitation, post-exploitation

It operates in three specialist modes and exposes a clean REST API.

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

---

## ⚡ Quick Start

### 1. Install dependencies

```bash
git clone https://github.com/cyberviser/Hancock.git
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

---

## 🌐 API Reference

Start the server: `python hancock_agent.py --server`

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/health`       | Agent status and capabilities |
| `GET`  | `/metrics`      | Prometheus-compatible request counters |
| `POST` | `/v1/chat`      | Conversational AI with history + streaming |
| `POST` | `/v1/ask`       | Single-shot question |
| `POST` | `/v1/triage`    | SOC alert triage + MITRE ATT&CK mapping |
| `POST` | `/v1/hunt`      | Threat hunting query generator (Splunk/Elastic/Sentinel) |
| `POST` | `/v1/respond`   | PICERL incident response playbook |
| `POST` | `/v1/code`      | Security code generation (YARA/Sigma/KQL/SPL) |
| `POST` | `/v1/ciso`      | CISO advisory: risk, compliance, board reports, gap analysis |
| `POST` | `/v1/sigma`     | Sigma detection rule generator |
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

> 📖 Full OpenAPI 3.1.0 spec: [`docs/openapi.yaml`](docs/openapi.yaml) · [Interactive API Docs](https://cyberviser.netlify.app/api)

### CLI Commands

```
/mode pentest   — switch to Pentest Specialist
/mode soc       — switch to SOC Analyst
/mode auto      — combined persona (default)
/mode code      — security code (Qwen Coder 32B)
/mode ciso      — CISO strategy & compliance
/mode sigma     — Sigma detection rule authoring
/clear          — clear conversation history
/history        — show history
/model <id>     — switch NVIDIA NIM model
/exit           — quit
```

---

## 🤖 Fine-Tuning

Hancock uses **LoRA fine-tuning** on Mistral 7B — trained on a multi-source cybersecurity dataset (MITRE ATT&CK + NVD CVEs + SOC/Pentest KB + CISA KEV + Atomic Red Team + GitHub Security Advisories).

### ⚡ One-Click: Google Colab (Free T4)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/cyberviser/Hancock/blob/main/Hancock_Colab_Finetune_v3.ipynb)

1. Click the badge above
2. **Runtime → Change runtime type → T4 GPU**
3. **Runtime → Run all** (~50 min)
4. Downloads GGUF Q4_K_M at end — run locally with Ollama

### CPU Fine-Tuning (No GPU Required)

Run on any machine — trains TinyLlama-1.1B with LoRA (adapter already included):

```bash
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
| Google Colab | T4 16GB | Free (15 hr/day) | `Hancock_Colab_Finetune_v3.ipynb` |
| Kaggle | T4 16GB | Free (30 hr/week) | `Hancock_Kaggle_Finetune.ipynb` |
| Modal.com | T4/A10G | Free $30/mo | `modal run train_modal.py` |
| Any GPU server | Any | Varies | `python hancock_finetune_gpu.py` |

### After Training — Run Locally

```bash
# Load fine-tuned model in Ollama
ollama create hancock -f Modelfile.hancock-finetuned
ollama run hancock
```

### Training Data

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
└── ghsa_collector.py           # GitHub Security Advisories

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
| **Phase 3** | CISO strategy + compliance automation | 📋 Planned |
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

**CyberViser Proprietary License** — see [LICENSE](LICENSE) for full terms.

- ✅ View and study the code
- ✅ Run locally for personal/research use
- ✅ Submit contributions (assigned to CyberViser)
- ❌ Commercial use without a written license agreement
- ❌ Redistribution or reselling
- ❌ Building competing products or services
- ❌ Training AI/ML models on the code or datasets
- ❌ White-labeling or removing CyberViser branding

**For commercial licensing:** contact@cyberviser.ai

---

<div align="center">
Built by <a href="https://github.com/cyberviser">CyberViser</a> · Powered by NVIDIA NIM · Mistral 7B · LoRA
</div>
