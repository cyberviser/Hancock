# Copilot Instructions — Hancock

## Project Overview

Hancock is CyberViser's AI-powered cybersecurity agent. It fine-tunes Mistral 7B (via LoRA) on curated cybersecurity datasets (MITRE ATT&CK, NVD/CVE, CISA KEV, Atomic Red Team, GHSA) and exposes the model through a Flask REST API and interactive CLI. The agent supports multiple personas: pentest specialist, SOC analyst, CISO advisor, code security, YARA/Sigma rule generation, and IOC enrichment.

## Commands

```bash
make setup          # Create venv, install deps, copy .env
make dev-install    # Install runtime + dev deps (flake8, pytest, black)

make test           # Run pytest with short traceback
make test-cov       # Run pytest with HTML coverage report
make lint           # flake8 (E9, F63, F7, F82 only — no style checks)

make run            # Start interactive CLI
make server         # Start REST API server on port 5000

make pipeline       # Collect + format training data (v1+v2)
make pipeline-v3    # Collect + format training data (v1+v2+KEV+Atomic+GHSA)
make finetune       # Run LoRA fine-tuning on Mistral 7B
```

**Run a single test file or test:**
```bash
pytest tests/test_hancock_api.py -v
pytest tests/test_hancock_api.py::TestHealth::test_health_ok -v
```

## Architecture

```
hancock_agent.py        # Core: Flask REST API + interactive CLI + all persona system prompts
hancock_pipeline.py     # Orchestrates the full data collection pipeline
collectors/             # One module per data source (MITRE, NVD, CISA KEV, Atomic, GHSA, etc.)
formatter/              # Converts raw collector output → Mistral instruct JSONL (v1/v2/v3)
data/                   # Generated JSONL training datasets (hancock_v3.jsonl = 5,670 samples)
hancock_finetune*.py    # LoRA fine-tuning scripts (GPU variants + CPU via cpuhancockai/)
clients/                # Python SDK (clients/python/) and Node.js SDK (clients/nodejs/)
tests/                  # pytest test suite for Flask API and SDK client
docs/openapi.yaml       # OpenAPI 3.1.0 spec
```

**Data flow:** `collectors/` → raw JSON → `formatter/` → JSONL → `hancock_finetune*.py` → fine-tuned model → `hancock_agent.py` serves it.

## Key Conventions

### LLM Integration
- All persona system prompts are module-level string constants in `hancock_agent.py` (e.g., `PENTEST_SYSTEM`, `SOC_SYSTEM`).
- Mode dispatch uses a dict: `SYSTEMS = {"pentest": PENTEST_SYSTEM, "soc": SOC_SYSTEM, ...}`.
- The OpenAI client (`openai>=1.0.0`) is used with `base_url` overridden to support Ollama, NVIDIA NIM, or OpenAI: `OpenAI(base_url=url, api_key=key)`.

### Training Data Format
Mistral instruct JSONL — one JSON object per line:
```json
{"messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}
```

### Collectors
- Each collector defines `OUTPUT_FILE = Path(__file__).parent.parent / "data" / "filename.json"` at module top.
- Soft failures: if a data source is unavailable, log and skip; do not abort the pipeline.
- Fallback chains are expected (e.g., TAXII → GitHub for MITRE data).

### Flask API
- Success responses: `{"status": "ok", "data": {...}}` or plain JSON payload.
- Error responses: `{"error": "message"}` with appropriate HTTP status code.
- `/v1/chat` uses streaming responses.

### Testing
- Fixtures: `app` (Flask app with mocked OpenAI client) and `client` (Flask test client).
- Mock OpenAI responses with `unittest.mock.patch` + `MagicMock`:
  ```python
  mock_resp.choices[0].message.content = "expected response"
  ```
- Related tests grouped in classes: `class TestHealth:`, `class TestAsk:`, `class TestTriage:`.

### Commit Style (Conventional Commits)
```
feat: add new endpoint
fix: handle empty input
docs: update API reference
refactor: clean up logic
```

### Branching
`feat/your-feature-name`

## Configuration

Copy `.env.example` → `.env` and set `NVIDIA_API_KEY=nvapi-...`. The agent defaults to NVIDIA NIM (`https://integrate.api.nvidia.com/v1`) but works with any OpenAI-compatible endpoint.

## Ethical Guardrails

All training data must come from publicly sourced, legally obtained cybersecurity knowledge bases. Do not remove or weaken the ethical/legal guardrails embedded in system prompts.
