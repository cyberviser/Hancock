# CyberViser — Launch Announcement Posts
# Mission: Build the defining AI cybersecurity platform. Fortune 500 trajectory.
# Copy-paste ready for each platform. Adapt and post.

---

## 🟠 Hacker News — "Show HN" Post

**Title:**
Show HN: Hancock – AI cybersecurity platform with 12 security endpoints (MITRE ATT&CK + CVE + CISA KEV)

**Body:**
I've been building Hancock — a full-stack AI cybersecurity platform, not a ChatGPT wrapper with a security prompt.

It's fine-tuned on MITRE ATT&CK, 200k+ CVEs, CISA Known Exploited Vulnerabilities, Atomic Red Team, and GitHub Security Advisories. Ships as a REST API with 12 security-specific endpoints:

- /v1/triage — SOC alert triage with MITRE mapping + TP/FP verdict
- /v1/hunt — SIEM query generator (Splunk SPL / Elastic KQL / Sentinel KQL)
- /v1/respond — PICERL incident response playbooks
- /v1/sigma — Sigma detection rule generator with ATT&CK tagging
- /v1/yara — YARA malware detection rule generator
- /v1/ioc — IOC threat intelligence enrichment (IP, domain, hash, email)
- /v1/ciso — CISO advisory (risk, compliance, board reports, gap analysis)
- /v1/code — Security code generation (YARA/Sigma/KQL/SPL/Python/Bash)
- /v1/chat — Conversational mode with history + streaming
- /v1/ask — Single-shot security Q&A
- /v1/webhook — Ingest alerts from Splunk/Elastic/Sentinel/CrowdStrike

Deploys anywhere: your laptop, air-gapped network, sovereign cloud, or our managed platform. Multi-backend inference (NVIDIA NIM, Groq, Together AI, Ollama).

Python + Node.js SDKs included. Fine-tuning pipeline is open source.

The goal: replace the 15–30 disconnected security tools enterprises juggle today with a single AI-native intelligence layer. The cybersecurity talent gap (3.5M unfilled jobs) isn't closing — AI is the only thing that scales.

Live demo: https://cyberviser.ai/demo
GitHub: https://github.com/cyberviser/Hancock
Full mission: https://github.com/cyberviser/Hancock/blob/main/BUSINESS_PROPOSAL.md

Happy to answer questions about architecture, fine-tuning approach, or the market thesis.

---

## 💼 LinkedIn Post

🛡️ We're building the future of cybersecurity. Here's the mission.

CyberViser is building Hancock — an AI cybersecurity platform that replaces the repetitive 80% of SOC, pentest, and compliance work with purpose-built AI agents.

This is not ChatGPT with a security prompt. Hancock is fine-tuned on real threat intelligence:
→ MITRE ATT&CK (TTPs, tactics, procedures)
→ 200,000+ CVEs from the National Vulnerability Database
→ CISA Known Exploited Vulnerabilities catalog
→ Atomic Red Team test cases
→ GitHub Security Advisories

What it does — 12 production API endpoints:
→ SOC alert triage with autonomous MITRE mapping
→ SIEM query generation (Splunk, Elastic, Sentinel)
→ PICERL incident response playbooks on demand
→ Sigma + YARA detection rule authoring
→ IOC threat intelligence enrichment
→ CISO advisory: compliance, risk, board reports
→ Pentest: recon, CVE analysis, exploitation paths, report generation

The problem we're solving:
• 3.5 million cybersecurity jobs unfilled globally
• $10.5 trillion in annual cybercrime damage
• 45% of SOC alerts go uninvestigated
• Average data breach costs $4.88M

There will never be enough human analysts. AI is the only path that scales.

We're onboarding enterprise design partners now. If your team is drowning in alerts, spending weeks on pentest reports, or struggling with compliance — let's talk.

🔗 https://cyberviser.ai
📦 https://github.com/cyberviser/Hancock
📧 contact@cyberviser.ai

#cybersecurity #AI #infosec #pentesting #SOC #CISO #threatintel #MITRE #startup #enterprise

---

## 🔴 Reddit — r/netsec

**Title:** Hancock – AI cybersecurity platform: 12 endpoints for SOC triage, threat hunting, Sigma/YARA rules, IR playbooks, and pentest work

**Body:**
Hey r/netsec,

I've been building Hancock for the past year — wanted to share where it's at and get feedback from production security teams.

**What it is:**
An AI cybersecurity platform fine-tuned on MITRE ATT&CK, NVD/CVE, CISA KEV, Atomic Red Team, and GHSA. REST API with 12 security-specific endpoints. Not a wrapper — purpose-built.

**What it does:**
- Alert triage with MITRE mapping + TP/FP verdict + containment actions
- SIEM query generation: production Splunk SPL, Elastic KQL, Sentinel KQL
- Sigma + YARA rule generation with ATT&CK tagging
- IOC enrichment (IP, domain, URL, hash, email)
- Full PICERL incident response playbooks
- CISO advisory: compliance automation, risk reporting, gap analysis
- Pentest: recon, CVE analysis, exploitation guidance, report writing

**Technical details:**
- Multi-backend: NVIDIA NIM, Groq, Together AI, OpenRouter, Ollama
- Deploys anywhere: Docker, bare metal, air-gapped
- Python + Node.js SDKs
- Fine-tuning pipeline is open source (5,670 training samples in v3)

**What I'm looking for:**
Honest feedback from people doing real SOC/MSSP/pentest work. What would make this actually useful in your daily workflow? What's missing? What's wrong?

Enterprise pilot program is open — free, no strings.

**Try it:** https://cyberviser.ai/demo
**Code:** https://github.com/cyberviser/Hancock

---

## 🟣 Reddit — r/AskNetsec

**Title:** We built an AI that autonomously triages SOC alerts and generates Sigma/YARA rules — looking for real-world feedback

**Body:**
My team is building CyberViser — an AI platform for security operations.

Here's what we've deployed so far:
- Feed it any security alert → get severity, MITRE ATT&CK mapping, TP/FP verdict, containment actions
- Describe a threat → get production Splunk/Elastic/Sentinel hunt queries
- Describe a detection → get a complete Sigma rule with ATT&CK tags
- Submit an IOC → get threat intel enrichment
- Give it an incident type → get a full PICERL playbook

Not a ChatGPT wrapper. Fine-tuned on MITRE ATT&CK, 200k+ CVEs, CISA KEV, Atomic Red Team.

**Real question:** If you could have an AI handle ONE part of your daily workflow, what would it be? We're prioritizing our roadmap based on real operator needs.

Demo: https://cyberviser.ai/demo

---

## 🐦 Twitter/X Thread

Tweet 1:
We're building the operating system for cybersecurity. Meet Hancock.

An AI platform with 12 security endpoints — fine-tuned on MITRE ATT&CK, 200k+ CVEs, CISA KEV, and real threat intel.

Not a chatbot. A weapon for defenders.

🔗 https://cyberviser.ai

Tweet 2:
What it does:

→ /v1/triage: autonomous alert triage with MITRE mapping
→ /v1/hunt: production Splunk/Elastic/Sentinel queries
→ /v1/sigma: detection rule generation with ATT&CK tags
→ /v1/yara: malware detection rules
→ /v1/ioc: threat intel enrichment
→ /v1/respond: PICERL playbooks

Tweet 3:
→ /v1/ciso: board-ready risk reports + compliance automation
→ /v1/code: security code gen (YARA/Sigma/KQL/SPL)
→ /v1/chat: conversational + streaming
→ /v1/webhook: ingest from Splunk/Elastic/Sentinel/CrowdStrike

12 endpoints. One platform. Deploy anywhere.

Tweet 4:
The cybersecurity talent gap is 3.5M unfilled jobs.
Annual cybercrime damage: $10.5 trillion.
Average breach cost: $4.88M.

There will never be enough humans. AI is the only solution that scales.

We're building it. Come help.

🔗 https://github.com/cyberviser/Hancock

#infosec #cybersecurity #AI #SOC #pentesting #blueteam #MITRE #startup

Tweet 5:
Enterprise design partners wanted.

If you run a SOC, MSSP, pentest firm, or security consultancy — we want 10 teams to pilot Hancock.

Free. No commitment. Just deploy and measure.

DM or → contact@cyberviser.ai

---

## 🎯 ProductHunt Submission

**Name:** CyberViser Hancock

**Tagline:** AI cybersecurity platform — 12 endpoints for SOC triage, threat hunting, Sigma/YARA rules, IR playbooks, and pentest

**Description:**
CyberViser is building the platform that replaces 15–30 disconnected security tools with a single AI-native intelligence layer.

Hancock is fine-tuned on MITRE ATT&CK, 200,000+ CVEs, CISA KEV, Atomic Red Team, and GitHub Security Advisories — not a generic LLM with a security prompt.

12 production API endpoints:
• Alert triage → autonomous MITRE-mapped severity + TP/FP + containment
• Threat hunting → production Splunk/Elastic/Sentinel queries
• Detection engineering → Sigma + YARA rules with ATT&CK tagging
• IOC enrichment → threat intel for IPs, domains, hashes, emails
• Incident response → full PICERL playbooks
• CISO advisory → compliance, risk, board summaries, gap analysis
• Pentest → recon, CVE analysis, exploitation paths, report generation

Deploys anywhere: managed cloud, on-premise, air-gapped, or local with Ollama.
Python + Node.js SDKs included. Enterprise pilots available.

**Website:** https://cyberviser.ai
**GitHub:** https://github.com/cyberviser/Hancock

**Topics:** Cybersecurity, Artificial Intelligence, Developer Tools, SaaS, Enterprise

---

## 📋 AlternativeTo Submission

**Product Name:** CyberViser Hancock
**URL:** https://cyberviser.ai
**Description:** AI-powered cybersecurity platform with 12 specialized endpoints. Fine-tuned on MITRE ATT&CK, CVE, CISA KEV, and Atomic Red Team. Autonomous SOC alert triage, SIEM query generation, Sigma/YARA rule authoring, incident response playbooks, and CISO advisory. Deploys on-premise or managed cloud. Enterprise-ready alternative to fragmented security tooling.
**Tags:** cybersecurity, AI, pentest, SOC, SIEM, incident-response, LLM, threat-intelligence, compliance, detection-engineering
**Alternatives to:** Microsoft Security Copilot, CrowdStrike Charlotte AI, Google Security AI Workbench, Darktrace (AI-native, deployable anywhere, open-source core)
