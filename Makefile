# ─── CyberViser — Hancock Makefile ───────────────────────────
.DEFAULT_GOAL := help
PYTHON        := .venv/bin/python
PIP           := .venv/bin/pip

.PHONY: help setup install dev-install run server pipeline pipeline-v3 finetune lint test test-cov clean docker docker-up fly-deploy client-python client-node

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
	@echo ""
	@echo "  Run:"
	@echo "    run            Start Hancock CLI (interactive)"
	@echo "    server         Start Hancock REST API server (port 5000)"
	@echo "    pipeline       Run data collection pipeline (all phases)"
	@echo "    pipeline-v3    Run v3 data collection only (KEV + Atomic + GHSA)"
	@echo "    finetune       Run LoRA fine-tuning on Mistral 7B"
	@echo ""
	@echo "  Clients:"
	@echo "    client-python  Run Python SDK CLI (interactive)"
	@echo "    client-node    Run Node.js SDK CLI (interactive)"
	@echo ""
	@echo "  Dev:"
	@echo "    lint           Run flake8 linter"
	@echo "    test           Run test suite"
	@echo "    test-cov       Run test suite with HTML coverage report"
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
