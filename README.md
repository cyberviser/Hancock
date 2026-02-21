# 🛡️ Hancock — CyberViser AI Security Agent

<div align="center">

![Hancock Banner](https://img.shields.io/badge/CyberViser-Hancock-00ff88?style=for-the-badge&logo=hackthebox&logoColor=black)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Model](https://img.shields.io/badge/Model-Mistral%207B-orange?logo=huggingface)](https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.3)
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA-NIM-76b900?logo=nvidia)](https://build.nvidia.com)
[![GitHub Pages](https://img.shields.io/badge/Website-Live-00ff88?logo=github)](https://cyberviser.github.io/Hancock/)

**Automate cybersecurity through specialized LLMs — from pentesting to SOC analysis.**

[🌐 Website](https://cyberviser.github.io/Hancock/) · [📋 Business Proposal](BUSINESS_PROPOSAL.md) · [🐛 Report Bug](https://github.com/cyberviser/Hancock/issues) · [✨ Request Feature](https://github.com/cyberviser/Hancock/issues)

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
| 👔 **CISO Strategy** | Compliance, risk reporting, board summaries | 🗓️ Phase 3 |

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
python hancock_pipeline.py
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
| `GET` | `/health` | Agent status and capabilities |
| `POST` | `/v1/chat` | Conversational AI with history |
| `POST` | `/v1/ask` | Single-shot question |
| `POST` | `/v1/triage` | SOC alert triage |
| `POST` | `/v1/hunt` | Threat hunting query generator |
| `POST` | `/v1/respond` | PICERL incident response playbook |

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

**Incident Response Playbook:**
```bash
curl -X POST http://localhost:5000/v1/respond \
  -H "Content-Type: application/json" \
  -d '{"incident": "ransomware"}'
```

**Chat (pentest mode):**
```bash
curl -X POST http://localhost:5000/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "How do I enumerate subdomains?", "mode": "pentest"}'
```

### CLI Commands

```
/mode pentest   — switch to Pentest Specialist
/mode soc       — switch to SOC Analyst
/mode auto      — combined persona (default)
/clear          — clear conversation history
/history        — show history
/model <id>     — switch NVIDIA NIM model
/exit           — quit
```

---

## 🤖 Fine-Tuning

Hancock uses **LoRA fine-tuning** on Mistral 7B via NVIDIA NIM.

```
data/
├── hancock_pentest_v1.jsonl    # Pentest training data (MITRE + CVE + KB)
└── hancock_v2.jsonl            # v2 dataset (pentest + SOC combined)

collectors/
├── mitre_collector.py          # Fetches MITRE ATT&CK TTPs
├── nvd_collector.py            # Fetches NVD/CVE vulnerability data
├── pentest_kb.py               # Pentest knowledge base Q&A
└── soc_collector.py / soc_kb.py

formatter/
└── to_mistral_jsonl.py         # Converts to Mistral instruct format
```

See [`Hancock_CyberViser_Finetune.ipynb`](Hancock_CyberViser_Finetune.ipynb) for the full fine-tuning notebook.

---

## 🗺️ Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 1** | Pentest Specialist + SOC REST API | 🔨 Building |
| **Phase 2** | SOC deep specialization + detection engineering | 📋 Planned |
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

MIT License — see [LICENSE](LICENSE) for details.

> Hancock operates strictly within authorized scope and legal boundaries.
> All training data is sourced from public, legal cybersecurity knowledge bases.

---

<div align="center">
Built by <a href="https://github.com/cyberviser">CyberViser</a> · Powered by NVIDIA NIM · Mistral 7B · LoRA
</div>
