#!/usr/bin/env bash
# Kept for older instructions. Use ./AgentGuard/run instead: it sets up and starts AgentGuard.
exec "$(cd "$(dirname "$0")" && pwd)/run" "$@"
