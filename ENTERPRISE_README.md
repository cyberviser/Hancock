# 🏢 Hancock Enterprise — CyberViser AI Security Platform

<div align="center">

![Hancock Enterprise](https://img.shields.io/badge/CyberViser-Enterprise-00ff88?style=for-the-badge&logo=hackthebox&logoColor=black)
[![SOC 2](https://img.shields.io/badge/SOC_2-Type_II-blue?style=flat-square)](https://cyberviser.ai/compliance)
[![ISO 27001](https://img.shields.io/badge/ISO-27001-blue?style=flat-square)](https://cyberviser.ai/compliance)
[![GDPR](https://img.shields.io/badge/GDPR-Compliant-blue?style=flat-square)](https://cyberviser.ai/compliance)
[![FedRAMP](https://img.shields.io/badge/FedRAMP-In_Progress-orange?style=flat-square)](https://cyberviser.ai/compliance)

**AI-powered cybersecurity for the enterprise — on-premise, private cloud, or fully managed.**

[🌐 Website](https://cyberviser.ai) · [📖 API Docs](https://cyberviser.ai/api) · [💰 Pricing](https://cyberviser.ai/pricing) · [📞 Contact Sales](mailto:contact@cyberviser.ai)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Enterprise Capabilities](#enterprise-capabilities)
- [Architecture](#architecture)
- [Deployment Options](#deployment-options)
- [Integration Guide](#integration-guide)
- [API Reference](#api-reference)
- [SDKs](#sdks)
- [Security & Compliance](#security--compliance)
- [Support & SLAs](#support--slas)
- [Pricing](#pricing)
- [Getting Started](#getting-started)
- [Contact](#contact)

---

## Overview

Hancock Enterprise is CyberViser's production-grade AI security platform, purpose-built for organizations that require dedicated model instances, SIEM/SOAR integrations, compliance automation, and enterprise-grade access controls.

Unlike general-purpose LLMs with security prompts, Hancock is **fine-tuned on curated cybersecurity datasets** — MITRE ATT&CK, NVD/CVE, CISA KEV, Atomic Red Team, and GitHub Security Advisories — delivering domain-specific accuracy across offensive, defensive, and executive security workflows.

### Why Hancock Enterprise?

| Challenge | Hancock Enterprise Solution |
|-----------|----------------------------|
| 3.5M unfilled cybersecurity jobs globally | AI agent that augments your team at machine speed |
| SOC teams ignore 45% of daily alerts | Automated triage with MITRE ATT&CK mapping and severity scoring |
| $15K–$50K per penetration test engagement | On-demand pentest guidance and attack path analysis |
| 204-day average breach detection time | Real-time threat hunting query generation for your SIEM |
| 15–30 disconnected security tools per org | Unified AI-native platform across offense, defense, and executive intelligence |

---

## Enterprise Capabilities

### 🔴 Offensive Security Engine
- Automated penetration testing guidance and attack path analysis
- CVE exploitation chain mapping with MITRE ATT&CK correlation
- PTES-compliant professional report generation
- Trained on MITRE ATT&CK, NVD/CVE, CISA KEV, and Atomic Red Team

### 🔵 Defensive Operations Engine
- Real-time alert triage with severity scoring and MITRE ATT&CK mapping
- Threat hunting query generation (Splunk SPL, Elastic KQL, Microsoft Sentinel)
- PICERL incident response playbook generation
- Sigma detection rule and YARA malware rule authoring
- IOC enrichment (IP, domain, URL, hash, email)

### 👔 Executive Intelligence Engine
- Board-ready risk reporting and security posture summaries
- Compliance gap analysis (SOC 2, ISO 27001, NIST CSF, CMMC, FedRAMP)
- Security program roadmaps and budget justification models
- M&A security due diligence

### 🛡️ Code Security Engine
- YARA, KQL, SPL, Sigma, Python, and Bash generation
- Supply chain risk analysis via GitHub Security Advisories (GHSA)
- SAST/DAST augmentation workflows

### 🔐 Enterprise Platform Features

| Feature | Description |
|---------|-------------|
| **RBAC** | Role-based access control with granular permissions |
| **SSO/SAML** | Single sign-on via Okta, Azure AD, Google Workspace, or any SAML 2.0 IdP |
| **Audit Logging** | Immutable audit trail for all API calls, user actions, and model responses |
| **API Key Management** | Scoped API keys with rotation policies and rate limiting |
| **Multi-Tenancy** | Isolated environments per team, BU, or client |
| **Custom Fine-Tuning** | Train on your organization's proprietary threat data and SOPs |
| **Dedicated Model Instances** | Isolated inference with guaranteed SLA |
| **Data Residency** | Deploy in your region — US, EU, APAC, or sovereign cloud |
| **Air-Gap Support** | Fully offline deployment for classified or restricted environments |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                     HANCOCK ENTERPRISE PLATFORM                    │
│                                                                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────┐ │
│  │  Offensive    │ │  Defensive   │ │  Executive   │ │   Code    │ │
│  │  Security     │ │  Operations  │ │   Intel      │ │  Security │ │
│  │  Engine       │ │  Engine      │ │  Engine      │ │  Engine   │ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └─────┬─────┘ │
│         │                │                │               │       │
│  ┌──────┴────────────────┴────────────────┴───────────────┴─────┐ │
│  │                    REST API (v1) + SDKs                       │ │
│  │  /v1/chat · /v1/ask · /v1/triage · /v1/hunt · /v1/respond    │ │
│  │  /v1/code · /v1/ciso  · /v1/sigma · /v1/yara · /v1/ioc      │ │
│  │  /v1/webhook                                                  │ │
│  └──────┬───────────────────────────────────────────────────────┘ │
│         │                                                         │
│  ┌──────┴───────────────────────────────────────────────────────┐ │
│  │              Enterprise Services Layer                        │ │
│  │  SSO/SAML · RBAC · Audit Logging · API Key Management        │ │
│  │  Multi-Tenancy · Rate Limiting · Data Residency               │ │
│  └──────┬───────────────────────────────────────────────────────┘ │
│         │                                                         │
│  ┌──────┴───────────────────────────────────────────────────────┐ │
│  │              Inference Layer                                  │ │
│  │  Fine-Tuned Mistral 7B · LoRA Adapters · NVIDIA NIM          │ │
│  │  Ollama (Self-Hosted) · Multi-Backend Support                 │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              Integrations                                     │ │
│  │  Splunk · Elastic · Sentinel · CrowdStrike · XSOAR           │ │
│  │  Swimlane · Tines · Jira · ServiceNow · PagerDuty            │ │
│  └──────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

---

## Deployment Options

### Option 1: Managed Cloud (SaaS)

Fully managed by CyberViser. No infrastructure to maintain.

```
cyberviser.ai → Your tenant → Isolated model instance → Your SIEM
```

- Zero setup — onboard in minutes
- Automatic updates and model improvements
- Multi-region availability (US, EU, APAC)
- 99.9% uptime SLA

### Option 2: Private Cloud / VPC

Deployed within your cloud account (AWS, Azure, GCP) for full data sovereignty.

```bash
# AWS deployment
aws cloudformation deploy --template-file hancock-enterprise.yaml \
  --stack-name hancock-prod --parameter-overrides Environment=production

# Azure deployment
az deployment group create --resource-group hancock-rg \
  --template-file hancock-enterprise-azure.json
```

### Option 3: On-Premise / Docker

Run entirely within your infrastructure using Docker Compose or Kubernetes.

```bash
# Docker Compose — includes Hancock + Ollama for local inference
git clone https://github.com/cyberviser/Hancock.git
cd Hancock
cp .env.example .env
# Configure environment variables (see Configuration section)
docker compose up -d
```

```yaml
# docker-compose.yml ships with the repo:
# - hancock: Flask API on port 5000
# - ollama: Local LLM inference on port 11434
# Health checks included for both services
```

### Option 4: Air-Gapped Deployment

For classified, SCIF, or restricted environments with no internet connectivity.

1. Pre-download model weights and container images on a connected system
2. Transfer via approved media to the air-gapped environment
3. Deploy with `HANCOCK_LLM_BACKEND=ollama` for fully offline inference
4. All training data and knowledge bases are bundled — no external API calls required

### Kubernetes (Helm)

```bash
helm repo add cyberviser https://charts.cyberviser.ai
helm install hancock cyberviser/hancock-enterprise \
  --namespace hancock \
  --set replicas=3 \
  --set inference.backend=ollama \
  --set auth.sso.enabled=true
```

---

## Integration Guide

### SIEM Integration

Hancock accepts alerts via the `/v1/webhook` endpoint and generates queries for your SIEM platform.

| SIEM | Supported | Query Language |
|------|-----------|---------------|
| **Splunk** | ✅ | SPL |
| **Elastic / OpenSearch** | ✅ | KQL |
| **Microsoft Sentinel** | ✅ | KQL |
| **CrowdStrike** | ✅ | Event Search |

**Webhook Configuration (Splunk example):**

```bash
# Forward Splunk alerts to Hancock for automated triage
curl -X POST https://hancock.yourcompany.com/v1/webhook \
  -H "Authorization: Bearer $HANCOCK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "splunk",
    "alert": "Mimikatz detected on DC01 at 03:14 UTC",
    "severity": "critical"
  }'
```

**Threat Hunting Query Generation:**

```bash
# Generate Splunk hunt query
curl -X POST https://hancock.yourcompany.com/v1/hunt \
  -H "Authorization: Bearer $HANCOCK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "lateral movement via PsExec", "siem": "splunk"}'
```

### SOAR Integration

| Platform | Integration Method |
|----------|--------------------|
| **Palo Alto XSOAR** | REST API playbook action |
| **Swimlane** | HTTP connector |
| **Tines** | HTTP request action |
| **Splunk SOAR** | REST API connector |

### Ticketing & Alerting

| Platform | Integration Method |
|----------|--------------------|
| **Jira** | Webhook + REST API |
| **ServiceNow** | REST API |
| **PagerDuty** | Events API v2 |
| **Slack** | Incoming webhook |
| **Microsoft Teams** | Incoming webhook |

---

## API Reference

Base URL: `https://hancock.yourcompany.com` (on-premise) or `https://api.cyberviser.ai` (managed)

Full OpenAPI 3.1.0 specification: [`docs/openapi.yaml`](docs/openapi.yaml)

### Authentication

All enterprise API calls require a bearer token:

```bash
curl -H "Authorization: Bearer $HANCOCK_API_KEY" \
  https://hancock.yourcompany.com/health
```

Set `HANCOCK_API_KEY` as an environment variable on the server to enable authentication.

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/health` | Agent status, capabilities, and version |
| `GET`  | `/metrics` | Prometheus-compatible request counters |
| `POST` | `/v1/chat` | Conversational AI with history + streaming |
| `POST` | `/v1/ask` | Single-shot cybersecurity question |
| `POST` | `/v1/triage` | SOC alert triage + MITRE ATT&CK mapping |
| `POST` | `/v1/hunt` | Threat hunting query generator (Splunk/Elastic/Sentinel) |
| `POST` | `/v1/respond` | PICERL incident response playbook |
| `POST` | `/v1/code` | Security code generation (YARA/Sigma/KQL/SPL) |
| `POST` | `/v1/ciso` | CISO advisory: risk, compliance, board reports |
| `POST` | `/v1/sigma` | Sigma detection rule generator |
| `POST` | `/v1/yara` | YARA malware detection rule generator |
| `POST` | `/v1/ioc` | IOC threat intelligence enrichment |
| `POST` | `/v1/webhook` | Ingest alerts from Splunk/Elastic/Sentinel/CrowdStrike |

### Example: Automated Alert Triage

```bash
curl -X POST https://hancock.yourcompany.com/v1/triage \
  -H "Authorization: Bearer $HANCOCK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alert": "Mimikatz detected on DC01 at 03:14 UTC",
    "context": "Windows domain controller, production environment"
  }'
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "severity": "critical",
    "mitre_attack": ["T1003.001 — LSASS Memory"],
    "recommended_actions": ["Isolate DC01", "Reset krbtgt", "Review auth logs"],
    "response_playbook": "PICERL — Credential Theft"
  }
}
```

### Example: Incident Response Playbook

```bash
curl -X POST https://hancock.yourcompany.com/v1/respond \
  -H "Authorization: Bearer $HANCOCK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"incident": "ransomware"}'
```

### Example: Compliance Gap Analysis

```bash
curl -X POST https://hancock.yourcompany.com/v1/ciso \
  -H "Authorization: Bearer $HANCOCK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Identify gaps against NIST CSF for our AWS environment",
    "output": "gap-analysis",
    "context": "200-person SaaS company, AWS, SOC 2 Type II certified"
  }'
```

---

## SDKs

Official SDKs for integrating Hancock into your applications and automation workflows.

### Python SDK

```bash
pip install cyberviser-hancock
```

```python
from hancock import HancockClient

client = HancockClient(
    base_url="https://hancock.yourcompany.com",
    api_key="your-api-key"
)

# Triage an alert
result = client.triage("Mimikatz detected on DC01 at 03:14 UTC")

# Generate a Sigma rule
rule = client.sigma(
    description="Detect LSASS memory dump",
    logsource="windows sysmon",
    technique="T1003.001"
)
```

### Node.js SDK

```bash
npm install @cyberviser/hancock
```

```javascript
const { HancockClient } = require("@cyberviser/hancock");

const client = new HancockClient({
  baseUrl: "https://hancock.yourcompany.com",
  apiKey: "your-api-key",
});

// Triage an alert
const result = await client.triage("Mimikatz detected on DC01 at 03:14 UTC");

// Generate a YARA rule
const rule = await client.yara({
  description: "Cobalt Strike beacon default HTTP profile",
  fileType: "PE",
});
```

SDK source code: [`clients/python/`](clients/python/) · [`clients/nodejs/`](clients/nodejs/)

---

## Security & Compliance

### Compliance Certifications

| Framework | Status |
|-----------|--------|
| **SOC 2 Type II** | ✅ Certified |
| **ISO 27001** | ✅ Certified |
| **GDPR** | ✅ Compliant |
| **HIPAA** | ✅ BAA Available |
| **FedRAMP** | 🟡 In Progress |
| **CMMC Level 2** | 🟡 In Progress |
| **StateRAMP** | 📋 Planned |

### Data Security

- **Encryption at rest:** AES-256
- **Encryption in transit:** TLS 1.3
- **Data isolation:** Tenant-level encryption keys and network isolation
- **Data retention:** Configurable per customer (default: 90 days, or zero-retention mode)
- **No training on customer data:** Enterprise customer data is never used to train or improve models

### Vulnerability Disclosure

Report security issues to **security@cyberviser.ai** — see [SECURITY.md](SECURITY.md) for full policy. We acknowledge receipt within 48 hours and resolve critical issues within 7 days.

### Ethical AI Guardrails

All Hancock models include embedded ethical guardrails:
- Operates strictly within authorized scope and legal boundaries
- All training data sourced from public, legally obtained cybersecurity knowledge bases
- Built for defenders — the agent refuses to assist with unauthorized attacks

---

## Support & SLAs

### Support Tiers

| | Pro | Enterprise | Enterprise Premium |
|--|-----|------------|-------------------|
| **Channels** | Email, Community | Email, Slack, Phone | Dedicated TAM, 24/7 Phone |
| **Response — Critical** | 4 hours | 1 hour | 15 minutes |
| **Response — High** | 8 hours | 4 hours | 1 hour |
| **Response — Medium** | 24 hours | 8 hours | 4 hours |
| **Uptime SLA** | 99.5% | 99.9% | 99.99% |
| **Custom Fine-Tuning** | — | ✅ | ✅ + Dedicated ML Engineer |
| **Onboarding** | Self-serve | Guided | White-glove |
| **Quarterly Reviews** | — | ✅ | ✅ |

### Professional Services

- **Integration Engineering:** SIEM/SOAR/GRC integration implementation
- **Custom Model Training:** Fine-tune on your proprietary threat data, runbooks, and SOPs
- **Red Team Augmentation:** Hancock-assisted penetration testing engagements
- **Security Program Advisory:** CISO advisory services powered by Hancock intelligence

---

## Pricing

| Plan | Price | Best For |
|------|-------|----------|
| **Community** | Free | Individual researchers, students, small teams |
| **Pro** | $499/month per seat | Security teams, consultancies |
| **Enterprise** | $50K–$500K/year | Fortune 1000, government, critical infrastructure |
| **API Platform** | $0.008–$0.05/request | Developers embedding security intelligence |

Enterprise pricing is based on:
- Number of users and API volume
- Deployment model (managed vs. on-premise)
- Custom fine-tuning and professional services
- Support tier and SLA requirements

**[Request a Quote →](mailto:contact@cyberviser.ai?subject=Hancock%20Enterprise%20Quote)**

Full pricing details: [cyberviser.ai/pricing](https://cyberviser.ai/pricing)

---

## Getting Started

### 1. Request an Enterprise Trial

Contact [contact@cyberviser.ai](mailto:contact@cyberviser.ai) to set up a 30-day enterprise trial with:
- Dedicated tenant on managed cloud (or on-premise deployment assistance)
- Full API access across all endpoints
- Integration support for your SIEM/SOAR stack
- Onboarding call with solutions engineering

### 2. Quick Evaluation (Self-Hosted)

Run Hancock locally to evaluate capabilities before enterprise deployment:

```bash
git clone https://github.com/cyberviser/Hancock.git
cd Hancock
cp .env.example .env

# Option A: Use a free cloud LLM backend (fastest start)
export HANCOCK_LLM_BACKEND=groq
export GROQ_API_KEY="gsk_..."

# Option B: Fully local with Docker + Ollama (no API keys)
docker compose up -d

# Start the API server
python hancock_agent.py --server --port 5000

# Test
curl http://localhost:5000/health
```

### 3. Configuration

Key environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `HANCOCK_LLM_BACKEND` | LLM provider: `nvidia`, `groq`, `together`, `openrouter`, `ollama` | `nvidia` |
| `NVIDIA_API_KEY` | NVIDIA NIM API key | — |
| `GROQ_API_KEY` | Groq API key | — |
| `HANCOCK_API_KEY` | Bearer token for API authentication | — (disabled) |
| `OLLAMA_BASE_URL` | Ollama server URL (for self-hosted) | `http://localhost:11434` |
| `OLLAMA_MODEL` | Default model for Ollama backend | `llama3.1:8b` |

See `.env.example` for the complete list of configuration options.

---

## Contact

| | |
|--|--|
| **Sales** | [contact@cyberviser.ai](mailto:contact@cyberviser.ai) |
| **Security** | [security@cyberviser.ai](mailto:security@cyberviser.ai) |
| **Support** | [support@cyberviser.ai](mailto:support@cyberviser.ai) |
| **Website** | [cyberviser.ai](https://cyberviser.ai) |
| **GitHub** | [github.com/cyberviser/Hancock](https://github.com/cyberviser/Hancock) |
| **API Docs** | [cyberviser.ai/api](https://cyberviser.ai/api) |

---

## License

**CyberViser Proprietary License** — see [LICENSE](LICENSE) for full terms.

Enterprise customers receive a separate commercial license agreement. Contact [contact@cyberviser.ai](mailto:contact@cyberviser.ai) for details.

---

<div align="center">

Built by [CyberViser](https://github.com/cyberviser) · Fine-Tuned Mistral 7B · LoRA · NVIDIA NIM

*© 2025 CyberViser. All rights reserved.*

</div>
