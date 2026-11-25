# AgentGuard

AgentGuard finds the parts of an AI agent that an attacker would target, and (in later steps) tests them.

## Run it

```bash
cd your-project
git clone <AgentGuard repo> AgentGuard
cp AgentGuard/.env.example AgentGuard/.env   # then put your ANTHROPIC_API_KEY in it
./AgentGuard/run                              # opens the dashboard at http://127.0.0.1:8765
```

Click **Run Search agent**. To run in the terminal only, without the dashboard: `AGENTGUARD_CMD=scan ./AgentGuard/run`.

## What happens in a run

```
SearchFlow  (CrewAI Flow, checkpointed to SQLite after every step)
  1. scan    agentguard-scan MCP server → scan_project      deterministic, reads code with ast
  2. search  Search agent (CrewAI, ReAct)                   Thought → Action → Observation, repeated
               tools: search_code, read_code, list_files    our MCP server (agentguard-scan)
                      semgrep_search                        external MCP server (official semgrep-mcp)
             output: SearchResult (Pydantic)                main LLM call, risky tools, safe tools, other LLM calls
  3. save    search.json
```

Each run is stored in `your-project/.agentguard/runs/<run-id>/`:
- `run.json`
- `scan.json`
- `search.json`
- `trace.jsonl`, with every thought, action, observation and MCP call
- `checkpoints.db`, the CrewAI checkpoints

A failed or stopped run can be resumed from its last checkpoint from the dashboard, and the steps already finished are not repeated.

## Code map

| File | What it does |
|---|---|
| `agentguard/scanner.py` | Deterministic scan: LLM calls, tools (decorators, JSON schemas, `tools=[...]`, name-to-function tables across files), prompts, entry points |
| `agentguard/mcp/scan_server.py` | Our MCP server (FastMCP, stdio): `scan_project`, `search_code`, `read_code`, `list_files`. Confined to the project; never reads `.env` or key files |
| `agentguard/mcp/semgrep.py` | External MCP: official `semgrep-mcp`, started with `uvx` |
| `agentguard/mcp/client.py` | One MCP client. Every call is traced |
| `agentguard/agents/search.py` | Search agent, its tools, ReAct monitoring, `SearchFlow`, checkpoint and resume |
| `agentguard/schemas.py` | Pydantic models: `ScanReport`, `SearchResult`, `TraceEvent` |
| `agentguard/llm.py` | Model (`AGENTGUARD_MODEL`, default `anthropic/claude-sonnet-5-5`) and the CrewAI LLM object |
| `agentguard/runs.py`, `server.py`, `static/index.html` | Run storage, the local API with live SSE trace, and the dashboard |

## Requirements

- Python 3.10+
- An Anthropic API key
- For Semgrep: [uv](https://docs.astral.sh/uv/) and `uv tool install semgrep`. Without them the agent uses `search_code` only.

Only Python projects are supported for now.
