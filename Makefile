# ─── CyberViser — Hancock Makefile ───────────────────────────
.DEFAULT_GOAL := help
PYTHON        := .venv/bin/python
PIP           := .venv/bin/pip

.PHONY: help setup install dev-install finetune-install run server pipeline pipeline-v3 finetune run-0ai run-0ai-verify run-0ai-logs run-0ai-debug lint test test-cov fuzz fuzz-target clean docker docker-up fly-deploy client-python client-node

help:
	@echo ""
	@echo "  ██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ██████╗  ██████╗██╗"
	@echo "  ██║  ██║██╔══██╗████╗  ██║██╔════╝██╔═══██╗██╔════╝██║"
	@echo "  ███████║███████║██╔██╗ ██║██║     ██║   ██║██║     ██║"
	@echo "  ██╔══██║██╔══██║██║╚██╗██║██║     ██║   ██║██║     ██╚"
	@echo "  ██║  ██║██║  ██║██║ ╚████║╚██████╗╚██████╔╝╚██████╗╚═╝"
	@echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝  ╚═════╝  "
	@echo "              CyberViser — Hancock AI Agent"
	@echo ""
	@echo "  Usage: make <target>"
	@echo ""
	@echo "  Setup:"
	@echo "    setup          Create virtualenv and install all dependencies"
	@echo "    install        Install runtime dependencies only"
	@echo "    dev-install    Install runtime + dev dependencies"
	@echo "    finetune-install Install CPU fine-tuning dependencies"
	@echo ""
	@echo "  Run:"
	@echo "    run            Start Hancock CLI (interactive)"
	@echo "    server         Start Hancock REST API server (port 5000)"
	@echo "    pipeline       Run data collection pipeline (all phases)"
	@echo "    pipeline-v3    Run v3 data collection only (KEV + Atomic + GHSA)"
	@echo "    finetune       Run LoRA fine-tuning on Mistral 7B"
	@echo "    run-0ai        Start the local 0AI CLI via script/build_and_run.sh"
	@echo "    run-0ai-verify Verify Python, Ollama, and model preflight for 0AI"
	@echo "    run-0ai-logs   Start 0AI with tee'd log capture"
	@echo "    run-0ai-debug  Start 0AI under pdb"
	@echo ""
	@echo "  Clients:"
	@echo "    client-python  Run Python SDK CLI (interactive)"
	@echo "    client-node    Run Node.js SDK CLI (interactive)"
	@echo ""
	@echo "  Dev:"
	@echo "    lint           Run flake8 linter"
	@echo "    test           Run test suite"
	@echo "    test-cov       Run test suite with HTML coverage report"
	@echo "    fuzz           Run all fuzz targets (quick, 60s each)"
	@echo "    fuzz-target    Run a single fuzz target: make fuzz-target TARGET=fuzz_nvd_parser"
	@echo "    clean          Remove build artifacts and cache"
	@echo ""
	@echo "  Docker:"
	@echo "    docker         Build Docker image"
	@echo "    docker-up      Start with docker-compose"
	@echo ""
	@echo "  Deploy:"
	@echo "    fly-deploy     Deploy to Fly.io (requires flyctl + fly auth login)"
	@echo ""

# ─── Setup ───────────────────────────────────────────────────
setup:
	@echo "[Hancock] Creating virtualenv..."
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@[ -f .env ] || cp .env.example .env
	@echo "[Hancock] Setup complete. Edit .env with your NVIDIA_API_KEY."

install:
	$(PIP) install -r requirements.txt

dev-install:
	$(PIP) install -r requirements.txt -r requirements-dev.txt

finetune-install:
	$(PIP) install -r requirements-finetune.txt

# ─── Run ─────────────────────────────────────────────────────
run:
	$(PYTHON) hancock_agent.py

server:
	$(PYTHON) hancock_agent.py --server --port 5000

pipeline:
	$(PYTHON) hancock_pipeline.py --phase all

pipeline-v3:
	$(PYTHON) hancock_pipeline.py --phase 3

finetune:
	$(PYTHON) hancock_finetune.py

run-0ai:
	./script/build_and_run.sh

run-0ai-verify:
	./script/build_and_run.sh --verify

run-0ai-logs:
	./script/build_and_run.sh --logs

run-0ai-debug:
	./script/build_and_run.sh --debug

# ─── Dev ─────────────────────────────────────────────────────
lint:
	.venv/bin/flake8 . --count --select=E9,F63,F7,F82 \
	  --exclude=.venv,__pycache__,data,docs --show-source --statistics

test:
	.venv/bin/pytest tests/ -v --tb=short

test-cov:
	.venv/bin/pytest tests/ -v --tb=short --cov=. --cov-report=html --cov-report=term-missing \
	  --cov-omit=".venv/*,data/*,docs/*,tests/*"
	@echo "[Hancock] Coverage report: htmlcov/index.html"

fuzz:
	@echo "[Hancock] Running all fuzz targets (quick, 60s each)..."
	@for target in fuzz/fuzz_*.py; do \
	  name=$$(basename $$target .py); \
	  corpus_name=$${name#fuzz_}; \
	  echo "[Hancock] Fuzzing $$name ..."; \
	  $(PYTHON) $$target -atheris_runs=5000 -max_total_time=60 fuzz/corpus/$$corpus_name 2>&1 | tail -5; \
	done
	@echo "[Hancock] Fuzzing complete."

fuzz-target:
	@test -n "$(TARGET)" || (echo "Usage: make fuzz-target TARGET=fuzz_nvd_parser" && exit 1)
	@echo "[Hancock] Fuzzing $(TARGET)..."
	@corpus_name=$${TARGET#fuzz_}; \
	$(PYTHON) fuzz/$(TARGET).py -atheris_runs=50000 -max_total_time=300 fuzz/corpus/$$corpus_name

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "[Hancock] Clean complete."

# ─── Docker ──────────────────────────────────────────────────
docker:
	docker build -t cyberviser/hancock:latest .

docker-up:
	docker-compose up -d

# ─── Deploy ──────────────────────────────────────────────────
fly-deploy:
	@which flyctl >/dev/null 2>&1 || (echo "[Hancock] Install flyctl: curl -L https://fly.io/install.sh | sh" && exit 1)
	flyctl deploy --config fly.toml

# ─── Clients ─────────────────────────────────────────────────
client-python:
	@$(PIP) install openai python-dotenv -q
	$(PYTHON) clients/python/hancock_cli.py

client-node:
	@cd clients/nodejs && npm install --silent
	node clients/nodejs/hancock.js
