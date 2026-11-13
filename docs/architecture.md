# Architecture

AgentGuard red-teams an AI agent that lives in a Python project. You run it from the project folder, a local dashboard
shows every step, and nothing leaves your machine except the calls you allow to model providers.

## Pipeline

```
 agentguard up  (backend 127.0.0.1:8787, serves the dashboard, the A2A agents and the API)
   |
   |  Run (dashboard or API)
   v
 1. discover   deterministic AST scan of the project (no code is run)       -> discovery.json
              + Semgrep sink evidence (external MCP server, optional)
 2. plan       candidates auto-accepted at confidence >= 0.8; the ADK          -> plan.json
              discovery agent reviews 0.4-0.8 (it may only include/exclude)
              you review and approve in the dashboard
 3. instrument import hook applies the approved wrappers; a generated target   -> agentguard_target.py
              app serves POST /invoke. Your files are not edited.
 4. target     the generated app starts on a free loopback port               -> target.log
 5. scan       manifest from the plan (tools, destructive flags, RAG, memory) -> manifest.yaml
 6. attack     one ADK attacker per category; deterministic oracles decide;   -> findings.json
              the judge may only add SUSPECTED
 7. report     CrewAI analyst, engineer and writer (or a rule-based fallback), -> report.md/json
              enriched with OWASP ids and code references
   all steps   TraceEvents on one event bus, written to trace.jsonl and streamed to the dashboard
```

## Components

| Area | Modules | Role |
|---|---|---|
| Discovery | `agentguard/discovery/` | AST extraction (`symbols.py`), file walker and cache (`walker.py`), scored candidates (`candidates.py`), plan model and validation (`plan.py`), ADK discovery agent (`agent.py`), Semgrep sink rules (`rules/sinks.yaml`) |
| Instrumentation | `agentguard/instrument/` | Recording wrappers and sandbox (`wrappers.py`), import hook (`hook.py`), generated target app (`target.py`) |
| Attack | `agentguard/attackers.py`, `classifier.py`, `oracles.py`, `judge.py`, `probes/` | ADK attacker loop, outcome classifier, deterministic oracles, judge, seeded probe library |
| Models | `llm.py`, `llm_fallback.py`, `llm_mock.py`, `budget.py` | LiteLLM calls with retries and the fallback chain, ADK fallback model, mock layer, budgets |
| Reporting | `reporters.py`, `schemas.py` | CrewAI reporter (or the fallback), `Report` and `Finding` contracts |
| MCP | `agentguard/mcp/` | Code-intelligence and security-knowledge servers, traced client, Semgrep bridge, launcher |
| A2A | `agentguard/a2a/` | Agent cards, JSON-RPC `message/send`, the three agent handlers, client |
| Backend | `agentguard/server/` | FastAPI app (API, SSE trace, A2A routes, static dashboard), run manager, key and settings stores, run store |
| Dashboard | `dashboard/` (Next.js), `agentguard/server/static/` (built) | Runs, plan review, live progress, findings, report, trace, MCP usage, settings, onboarding |
| CLI | `agentguard/cli.py` | `up`, `bootstrap`, `doctor`, `init`, `test`, `report`, `mcp list/serve` |
| Target side | `agentguard/adapter.py` | `@expose`, `@watch`, `/invoke`, `/health` (the manual path, still supported) |

## Files written per run

`.agentguard/runs/<run>/`: `trace.jsonl`, `discovery.json`, `plan.json`, `agentguard_target.py` (automatic runs),
`manifest.yaml`, `findings.json`, `report.md`, `report.json`, `target.log`.

Keys live in `.agentguard/.env` (mode 600). Settings live in `.agentguard/config.yaml`. The dashboard never stores either.

## Trace events

Monitoring is one event bus. Events in `trace.jsonl`:

- Runs: `run_started`, `run_phase` (phase and state), `run_finished`, `error`
- Discovery: `discovery_progress`, `discovery_done`, `plan_built`, `instrumented`
- Attack and models: `state_update`, `before_model`, `after_model`, `before_tool`, `after_tool`, `llm_usage`,
  `budget_exceeded`, `category_skipped`, `oracle_signal_not_confirming`, `model_fallback`
- MCP and A2A: `mcp_tool_call`, `mcp_tool_result`, `mcp_error`, `mcp_unavailable`, `a2a_call`, `a2a_handled`
- Reporting: `crew_step`, `crew_task`, `report_enriched`

## Safety defaults

- Discovery never imports or runs your code. It reads source as text.
- Destructive tools are sandboxed by default: they are recorded but not executed.
- Attack targets must be on localhost or 127.0.0.1. Remote targets are refused.
- The attacker never receives the target's system prompt; it only receives capabilities and the entrypoint's purpose.
- Keys are never logged, never placed in trace events, and never returned unmasked.
