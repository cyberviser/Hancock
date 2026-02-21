#!/usr/bin/env bash
# Hancock launcher — loads .env and starts the agent
# Usage:
#   ./hancock.sh          → interactive CLI
#   ./hancock.sh --server → REST API server

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
VENV="$SCRIPT_DIR/.venv/bin/python"

if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
fi

if [ -z "$NVIDIA_API_KEY" ]; then
    echo "ERROR: NVIDIA_API_KEY not set. Edit .env or export it."
    exit 1
fi

exec "$VENV" "$SCRIPT_DIR/hancock_agent.py" "$@"
