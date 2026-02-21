# ─── CyberViser — Hancock Makefile ───────────────────────────
.DEFAULT_GOAL := help
PYTHON        := .venv/bin/python
PIP           := .venv/bin/pip

.PHONY: help setup install dev-install run server pipeline finetune lint clean docker docker-up

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
	@echo "    pipeline       Run data collection pipeline"
	@echo "    finetune       Run LoRA fine-tuning on Mistral 7B"
	@echo ""
	@echo "  Dev:"
	@echo "    lint           Run flake8 linter"
	@echo "    clean          Remove build artifacts and cache"
	@echo ""
	@echo "  Docker:"
	@echo "    docker         Build Docker image"
	@echo "    docker-up      Start with docker-compose"
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
	$(PYTHON) hancock_pipeline.py

finetune:
	$(PYTHON) hancock_finetune.py

# ─── Dev ─────────────────────────────────────────────────────
lint:
	.venv/bin/flake8 . --count --select=E9,F63,F7,F82 \
	  --exclude=.venv,__pycache__,data,docs --show-source --statistics

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
