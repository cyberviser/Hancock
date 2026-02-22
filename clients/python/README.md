# Hancock Python SDK

## Setup

```bash
pip install openai python-dotenv
```

Set one backend API key:

```bash
export HANCOCK_LLM_BACKEND=groq    && export GROQ_API_KEY=gsk_xxx        # Free 14,400 req/day
export HANCOCK_LLM_BACKEND=nvidia  && export NVIDIA_API_KEY=nvapi-xxx     # Free 1,000 req/day
export HANCOCK_LLM_BACKEND=together && export TOGETHER_API_KEY=xxx        # Free credits
export HANCOCK_LLM_BACKEND=openrouter && export OPENROUTER_API_KEY=xxx    # Free rotating models
export HANCOCK_LLM_BACKEND=ollama                                         # Local, no key needed
```

## Quick Start

```python
from hancock_client import HancockClient

h = HancockClient()

# Security Q&A
print(h.ask("Explain CVE-2021-44228 Log4Shell"))

# Alert triage
print(h.triage("Mimikatz.exe detected on DC01 at 03:14 UTC. lsass dump."))

# Threat hunting query
print(h.hunt("lateral movement via PsExec", siem="splunk"))

# Incident response playbook
print(h.respond("ransomware"))

# Security code generation (Qwen 2.5 Coder 32B)
print(h.code("YARA rule for Emotet dropper", language="yara"))
print(h.code("KQL query to detect Pass-the-Hash attacks", language="kql"))

# CISO advisory
print(h.ciso("What controls for ISO 27001?", output="gap-analysis"))

# Sigma detection rules
print(h.sigma("Detect PowerShell encoded command", logsource="windows sysmon"))

# YARA malware rules
print(h.yara("Cobalt Strike beacon HTTP profile", file_type="PE"))

# IOC enrichment
print(h.ioc("185.220.101.35", ioc_type="ip"))
```

## CLI

```bash
# Interactive security mode
python hancock_cli.py

# Interactive code mode
python hancock_cli.py --mode code

# One-shot
python hancock_cli.py --task "explain Kerberoasting"
python hancock_cli.py --mode code --task "write a Sigma rule for Kerberoasting"
python hancock_cli.py --model mixtral-8x7b --task "CISO risk framework"
```

## Models

| Alias | Model | Best For |
|-------|-------|----------|
| `mistral-7b` | mistralai/mistral-7b-instruct-v0.3 | Security Q&A, triage, IR |
| `qwen-coder` | qwen/qwen2.5-coder-32b-instruct | YARA, Sigma, KQL, exploit code |
| `llama-8b` | meta/llama-3.1-8b-instruct | Fast general queries |
| `mixtral-8x7b` | mistralai/mixtral-8x7b-instruct-v0.1 | Long-form CISO strategy |

## API Reference

| Method | Description |
|--------|-------------|
| `h.ask(question, mode="auto")` | Security Q&A — pentest / soc / auto |
| `h.code(task, language=None)` | Code gen via Qwen 2.5 Coder 32B |
| `h.triage(alert)` | SOC alert triage + MITRE mapping |
| `h.hunt(target, siem="splunk")` | Threat hunting query generation |
| `h.respond(incident)` | Full PICERL IR playbook |
| `h.ciso(question, output, context)` | CISO advisory — compliance, risk, board reports |
| `h.sigma(description, logsource, technique)` | Sigma detection rule generation |
| `h.yara(description, file_type, hash)` | YARA malware detection rule generation |
| `h.ioc(indicator, ioc_type, context)` | IOC enrichment — IPs, domains, hashes, emails |
| `h.chat(message, history=[])` | Multi-turn conversation |
