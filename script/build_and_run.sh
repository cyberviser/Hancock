#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="0ai"
PROC_PATTERN="ai_agent.py"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOG_DIR/ai_agent.log"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

build() {
  mkdir -p "$LOG_DIR"
  "$PYTHON_BIN" -m py_compile "$ROOT_DIR/ai_agent.py"
  "$PYTHON_BIN" -c "import openai" >/dev/null
  curl -sf "http://localhost:11434/api/tags" >/dev/null
  "$PYTHON_BIN" - <<'PY'
import json
import sys
import urllib.request

with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as response:
    payload = json.load(response)

models = {item.get("name", "") for item in payload.get("models", [])}
if "0ai" not in models and "0ai:latest" not in models:
    raise SystemExit("Required Ollama model '0ai' is not installed")
PY
}

stop_existing() {
  pkill -f "$PROC_PATTERN" >/dev/null 2>&1 || true
}

run_app() {
  cd "$ROOT_DIR"
  exec -a "$APP_NAME" "$PYTHON_BIN" "$ROOT_DIR/ai_agent.py"
}

case "$MODE" in
  run)
    stop_existing
    build
    run_app
    ;;
  --debug|debug)
    stop_existing
    build
    cd "$ROOT_DIR"
    exec -a "$APP_NAME" "$PYTHON_BIN" -m pdb "$ROOT_DIR/ai_agent.py"
    ;;
  --logs|logs)
    stop_existing
    build
    cd "$ROOT_DIR"
    exec -a "$APP_NAME" "$PYTHON_BIN" "$ROOT_DIR/ai_agent.py" 2>&1 | tee "$LOG_FILE"
    ;;
  --telemetry|telemetry)
    stop_existing
    build
    cd "$ROOT_DIR"
    {
      echo "[telemetry] $(date -u +"%Y-%m-%dT%H:%M:%SZ") starting $APP_NAME"
      exec -a "$APP_NAME" "$PYTHON_BIN" "$ROOT_DIR/ai_agent.py"
    } 2>&1 | tee "$LOG_FILE"
    ;;
  --verify|verify)
    stop_existing
    build
    echo "verify-ok: python, openai, ollama endpoint, and model '0ai' are available"
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
