---
title: Hancock — CyberViser AI Security Agent
emoji: 🛡️
colorFrom: green
colorTo: cyan
sdk: gradio
sdk_version: "4.44.0"
app_file: spaces_app.py
pinned: true
license: other
tags:
  - cybersecurity
  - pentest
  - soc
  - mitre-attack
  - mistral
  - security
---

# 🛡️ Hancock — AI Cybersecurity Agent

> **by [CyberViser](https://cyberviser.netlify.app)** — Mistral 7B fine-tuned on MITRE ATT&CK, NVD/CVE, CISA KEV, and Atomic Red Team data.

## Modes

| Tab | What it does |
|-----|-------------|
| 🔵 SOC Triage | MITRE ATT&CK alert classification |
| 🔴 Pentest / CVE | Recon, exploitation, CVE analysis |
| 🎯 Threat Hunting | SIEM query generation (Splunk/Elastic/Sentinel) |
| 💻 Security Code | YARA, Sigma, KQL, SPL, Python, Bash |
| 👔 CISO Advisor | Risk, compliance, board reporting |
| 🚨 IR Playbook | PICERL incident response |

## Setup

Set two Space Secrets (`Settings → Variables and secrets`):
- `HANCOCK_API_URL` — your Hancock API URL (Oracle Cloud VM or elsewhere)
- `HANCOCK_API_KEY` — Bearer token (`HANCOCK_API_KEY` from your `.env`)

## Links

- 🌐 [Website](https://cyberviser.netlify.app)
- 📖 [API Docs](https://cyberviser.netlify.app/api)
- 💻 [GitHub](https://github.com/cyberviser/Hancock)
- 📧 contact@cyberviser.ai
