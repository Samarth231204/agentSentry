#!/usr/bin/env bash
# Builds the dashboard as static files and copies them into the Python package.
# Run from anywhere. Needs Node 20+ (only for building; users do not need Node).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/dashboard"
npm install --no-audit --no-fund
# Same-origin API: the static bundle calls the backend that serves it.
NEXT_PUBLIC_AGENTGUARD_API="" npm run build
rm -rf "$ROOT/agentguard/server/static"
cp -R out "$ROOT/agentguard/server/static"
echo "Dashboard copied to agentguard/server/static"
