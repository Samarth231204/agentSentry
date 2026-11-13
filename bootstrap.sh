#!/usr/bin/env bash
# One-time setup for AgentGuard inside your project.
#   1) git clone <this repo> into a folder inside your project (for example ./agentguard)
#   2) cd into your project and run:  ./agentguard/bootstrap.sh
#   3) start the dashboard:           ./agentguard/.venv/bin/agentguard up
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
"$PY" -m venv "$HERE/.venv"
"$HERE/.venv/bin/pip" install --quiet --upgrade pip
"$HERE/.venv/bin/pip" install --quiet -e "$HERE"
"$HERE/.venv/bin/agentguard" bootstrap --project "$PWD"
"$HERE/.venv/bin/agentguard" doctor || true
echo
echo "Ready. Start the dashboard from your project folder with:"
echo "  $HERE/.venv/bin/agentguard up"
