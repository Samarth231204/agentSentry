# Changelog

## Unreleased

- **Dashboard redesign**: white and blue theme. Opening the app takes a first-time visitor to a four-step setup guide
  (welcome, project, model key, first run). `?step=N` keeps the step on reload.
- **Live progress**: the run page shows each step and the attack category in progress, with attempts so far. The
  attack phase no longer looks stuck.
- **Demo check**: a mock run is labelled as a demo in the run list and on the run page, and skips the rate-limit
  cooldown between attack categories (a demo finishes in seconds instead of about a minute).
- **New test page**: automatic target and plan review by default; replay, A2A, budgets and canaries are under
  Advanced options.

## 0.2.0

Dashboard-first AgentGuard, built in six phases.

- **Dashboard** (Next.js, served by the backend): runs, plan review, live progress, findings, report, trace, MCP usage,
  settings, onboarding (paste-once API key, never stored in the browser).
- **Backend**: `agentguard up` serves the API, the live trace (SSE), the A2A agents and the static dashboard on
  127.0.0.1. Runs are started from the dashboard or the API, one at a time, with cancel.
- **Automatic instrumentation**: deterministic AST discovery, a reviewed plan, and an import hook that wraps the approved
  functions without editing your files. Destructive tools are sandboxed by default.
- **MCP**: two servers of ours (code intelligence, security knowledge) over Streamable HTTP, a traced client, and Semgrep's
  official server (pinned) for sink evidence.
- **Models**: a fallback chain (Groq, then Gemini by default), ADK memory shared across attack categories, a seeded probe
  library, and replay of an earlier run's probes.
- **Oracles**: PII, system-prompt fingerprint and retrieval injection, each gated to its category.
- **A2A**: discovery, attacker and reporter as agents with cards and JSON-RPC (in-house implementation).
- **Packaging**: `bootstrap.sh`, `agentguard bootstrap`, `agentguard doctor`, `agentguard --version`.

Known gaps: the CrewAI reporter's own calls are not budgeted; the memory-write oracle is not implemented; live (provider)
runs of the fallback, the model-driven MCP uses and the new oracles are not yet verified.

## 0.1.0

- Hackathon CLI: `init`, `test`, `report`; manual `@expose` / `@watch`; ADK attackers; CrewAI reporter; trace file.
