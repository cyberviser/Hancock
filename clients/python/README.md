# Hancock Python SDK

## Setup

```bash
pip install openai python-dotenv
export NVIDIA_API_KEY=nvapi-YOUR_KEY_HERE
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
| `h.chat(message, history=[])` | Multi-turn conversation |
