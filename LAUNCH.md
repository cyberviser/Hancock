# CyberViser — Launch Announcement Posts
# Copy-paste ready for each platform. Post today.

---

## 🟠 Hacker News — "Show HN" Post

**Title:**
Show HN: Hancock – fine-tuned LLM for pentest and SOC work (MITRE ATT&CK + CVE)

**Body:**
I've been building Hancock — a Mistral 7B model fine-tuned specifically on MITRE ATT&CK, NVD/CVE data, and pentest/SOC knowledge bases.

It ships as a REST API with 12 security-specific endpoints, including:
- /v1/triage — SOC alert triage with MITRE mapping + TP/FP verdict
- /v1/hunt   — SIEM query generator (Splunk SPL / Elastic KQL / Sentinel)
- /v1/respond — PICERL incident response playbooks
- /v1/ask    — single-shot security Q&A
- /v1/chat   — conversational mode with history

v0.4.0 adds CISO advisory, Sigma/YARA rule generation, IOC enrichment, API key auth, rate limiting, and auto-deploy.

The model is purpose-built — not ChatGPT with a security system prompt.
Fine-tuning pipeline is open source if you want to train your own variant.

Live demo: https://cyberviser.netlify.app/demo
GitHub: https://github.com/cyberviser/Hancock
Pricing (Community tier is free/self-hosted): https://cyberviser.netlify.app/pricing

Happy to answer questions about the fine-tuning approach or architecture.

---

## 💼 LinkedIn Post

🛡️ Launching Hancock v0.4.0 — AI Security Agent by CyberViser

After months of building, I'm releasing Hancock publicly.

Hancock is a fine-tuned LLM (Mistral 7B) trained on MITRE ATT&CK, 200k+ CVEs, and real pentest/SOC knowledge bases. Not ChatGPT with a security prompt — purpose-built for security operators.

What it does via REST API:
→ SOC alert triage with MITRE mapping + TP/FP verdict
→ SIEM query generation (Splunk, Elastic, Sentinel)
→ PICERL incident response playbooks on demand
→ CVE analysis and exploitation guidance
→ Pentest recon, methodology, and report writing

v0.4.0 ships with:
✅ 12 REST API endpoints (triage, hunt, respond, code, ciso, sigma, yara, ioc, webhook)
✅ Bearer token auth + rate limiting
✅ Auto-deploy CI/CD pipeline
✅ Interactive demo (no signup)
✅ Python + Node.js SDKs
✅ Community tier — free, self-hosted

If you're an MSSP, pentest firm, or SOC analyst drowning in alerts and report writing — this was built for you.

🔗 Try the demo: https://cyberviser.netlify.app/demo
📦 GitHub: https://github.com/cyberviser/Hancock
📧 Enterprise/trial: cyberviser@proton.me

#cybersecurity #infosec #AI #pentesting #SOC #blueTeam #redTeam #LLM #MachineLearning #MITRE

---

## 🔴 Reddit — r/netsec

**Title:** Hancock – fine-tuned LLM for pentest + SOC work. Generates SIEM queries, triages alerts, writes IR playbooks. v0.4.0

**Body:**
Hey r/netsec,

I've been building Hancock — a Mistral 7B model fine-tuned on MITRE ATT&CK, NVD/CVE, and pentest/SOC knowledge. Wanted to share v0.4.0 here.

**What it does:**
- REST API: triage alerts, generate Splunk/Elastic/Sentinel queries, write PICERL playbooks
- CLI mode for interactive pentest assistance
- Runs against NVIDIA NIM (or bring your own inference)

**v0.4.0 adds:**
- CISO advisory, Sigma/YARA rule generation, IOC enrichment
- API key auth + per-IP rate limiting
- Interactive browser demo (no signup needed)
- Python + Node.js SDKs
- Auto-deploy pipeline

**Try it:** https://cyberviser.netlify.app/demo  
**Code:** https://github.com/cyberviser/Hancock  

The fine-tuning pipeline is all open source if you want to extend it with your own data.

Happy to answer questions about the training approach, data sources, or architecture. Feedback welcome — especially from anyone doing production SOC/MSSP work.

---

## 🟣 Reddit — r/AskNetsec cross-post

**Title:** Built an AI that writes your Splunk queries and triages SOC alerts — honest feedback wanted

**Body:**
I'm a developer who got tired of watching SOC analysts waste time on repetitive SIEM query writing and alert triage. So I built Hancock.

It's a fine-tuned LLM that you can hit with a security alert and get back:
- Severity classification
- MITRE ATT&CK technique mapping  
- TP/FP assessment
- Containment actions
- A production-ready SIEM query for hunting the same thing

**Honest question for the community:** What would actually make this useful in your workflow? What's missing?

Demo (no account needed): https://cyberviser.netlify.app/demo

---

## 🐦 Twitter/X Thread

Tweet 1:
Shipping Hancock v0.4.0 — AI security agent fine-tuned on MITRE ATT&CK + 200k CVEs

Not another "ChatGPT with a security prompt." Purpose-built for pentesters and SOC analysts.

🔗 https://cyberviser.netlify.app/demo

Tweet 2:
What it actually does:

→ /v1/triage: feed it an alert, get MITRE mapping + TP/FP verdict
→ /v1/hunt: describe a TTP, get production Splunk/Elastic/Sentinel queries
→ /v1/respond: incident type → full PICERL playbook
→ /v1/ask: security Q&A with context

Tweet 3:
v0.4.0 ships with:
✅ 12 API endpoints
✅ Bearer token auth
✅ Per-IP rate limiting  
✅ Interactive demo — no signup
✅ Auto-deploy pipeline
✅ Python + Node.js SDKs
✅ Community tier free/self-hosted

Code: https://github.com/cyberviser/Hancock

Tweet 4:
If you run a MSSP, pentest firm, or SOC and want a trial — DM me or hit:
https://cyberviser.netlify.app/contact

cyberviser@proton.me

#infosec #pentesting #blueteam #SOC #AI #LLM #MITRE

---

## 🎯 ProductHunt Submission

**Name:** Hancock by CyberViser

**Tagline:** AI security agent fine-tuned on MITRE ATT&CK — triage alerts, generate SIEM queries, write IR playbooks

**Description:**
Hancock is a fine-tuned Mistral 7B model built specifically for pentesters and SOC analysts. Unlike general-purpose AI, it's trained on MITRE ATT&CK, 200,000+ CVEs, and real pentest/SOC knowledge bases.

Deploy it as a REST API and hit it with:
• Security alerts → MITRE-mapped triage with TP/FP verdict
• TTP descriptions → production Splunk/Elastic/Sentinel queries  
• Incident types → full PICERL response playbooks
• CVE IDs → exploitation analysis and detection guidance

Community tier is free and self-hosted. Pro tier at $299/mo adds managed hosting and priority support.

**Website:** https://cyberviser.netlify.app
**GitHub:** https://github.com/cyberviser/Hancock

**Topics:** Cybersecurity, Artificial Intelligence, Developer Tools, SaaS

---

## 📋 AlternativeTo Submission

**Product Name:** Hancock by CyberViser
**URL:** https://cyberviser.netlify.app
**Description:** AI-powered cybersecurity agent fine-tuned on MITRE ATT&CK and CVE data. REST API for SOC alert triage, SIEM query generation, and incident response playbooks. Alternative to manual SIEM work and generic AI security tools.
**Tags:** cybersecurity, AI, pentest, SOC, SIEM, incident-response, LLM
**Alternatives to:** Darktrace, CrowdStrike Falcon AI, Microsoft Security Copilot (open-source/self-hosted alternative)
