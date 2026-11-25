# AgentGuard

AgentGuard finds the parts of an AI agent that an attacker would target, then attacks them in a sandbox.

## Run it

```bash
cd your-project
git clone <AgentGuard repo> AgentGuard
cp AgentGuard/.env.example AgentGuard/.env   # then put your ANTHROPIC_API_KEY in it
./AgentGuard/run                              # opens the dashboard at http://127.0.0.1:8765
```

Click **Run AgentGuard**. To run in the terminal only, without the dashboard: `AGENTGUARD_CMD=scan ./AgentGuard/run`.

## What happens in a run

```
AgentGuard flow  (CrewAI Flow, checkpointed to SQLite after every step)
  1. scan    agentguard-scan MCP server → scan_project      deterministic, reads code with ast
  2. search  Search agent (CrewAI, ReAct, Sonnet 5.5)       Thought → Action → Observation
               tools: search_code, read_code, list_files    our MCP server (agentguard-scan)
                      semgrep_search                        external MCP server (official semgrep-mcp)
             guardrail: every file:line and entry point must exist, or the agent must fix its answer
             output: SearchResult (Pydantic) → search.json  entry points, main LLM call, risky tools
  3. attack  11 ADK attack agents (Haiku 5.5), one per attack type, one after another
               tools: get_payloads, disguise               our MCP server (agentguard-payloads): proven
                                                           techniques + disguises (base64, homoglyphs, ...)
                      plant_web_page, preview_page          trap web server + external MCP server (official
                                                           mcp-server-fetch, locked to the trap server)
               each talks to a SANDBOX: a throwaway copy of the project in its own process, whose model
               calls are redirected to AgentGuard's model and key and whose acting tools (pay, send,
               grant, run, SQL) are intercepted in memory: recorded, faked, never really run
               an ORACLE (plain code) confirms a hit from what really happened; the agent can only
               say "suspected"
             output: AttackReport (Pydantic) → attacks.json
```

Attack types: prompt injection, secret extraction, tool misuse, data exfiltration, privilege escalation,
RAG poisoning, memory persistence, unsafe command execution, SQL injection, insecure output handling, and
indirect prompt injection through a web page (only when the app has a tool that reads web pages).

Each run lives in `your-project/.agentguard/runs/<run-id>/`:
- `search.json`, the Search agent's result
- `attacks.json`, the attack results
- `trace.jsonl`, every thought, action, observation, probe, guardrail hit and MCP call
- `checkpoints.db`, the CrewAI checkpoints
- `adk_sessions.db`, the ADK attack agents' sessions (every event saved)
- `sandbox/`, the project copy and its log
- `trap_pages/`, the web pages planted for indirect injection

A failed or stopped run resumes from its last checkpoint.

**Monitoring and safety.**
- CrewAI event listeners and ADK callbacks (before/after model, before/after tool, tool errors) send every step to the trace and the live dashboard.
- Guardrails:
  - The target's replies are fenced as untrusted, and checked for prompt injection.
  - Our attackers' messages are checked for abusive language.
  - Tool arguments and return types are validated.
  - The Search agent's tool output is checked for injections planted in code.
- LangFuse tracing switches on when `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY` are set.

## Code map

| File | What it does |
|---|---|
| `agentguard/scanner.py` | Deterministic scan: LLM calls, tools, prompts, entry points |
| `agentguard/mcp/scan_server.py` | Our MCP server: `scan_project`, `search_code`, `read_code`, `list_files` |
| `agentguard/mcp/semgrep.py`, `mcp/client.py` | External Semgrep MCP server; one traced MCP client |
| `agentguard/agents/search.py` | Search agent, its guardrail, ReAct monitoring, the run's Flow, resume |
| `agentguard/sandbox/harness.py`, `runner.py` | Runs the project copy; model redirection; tool interception |
| `agentguard/attack/categories.py`, `team.py` | The 10 attack types; the ADK attack agents, callbacks and checkpoints |
| `agentguard/attack/oracles.py` | Code that confirms each attack type |
| `agentguard/attack/payloads.py`, `mcp/payload_server.py` | The payload library and its MCP server |
| `agentguard/attack/trap.py`, `mcp/fetch.py` | Trap web server for planted pages; the official Fetch MCP server |
| `agentguard/guardrails.py` | Injection and toxicity checks, untrusted fencing, type checks |
| `agentguard/observability.py` | LangFuse tracing (optional) |
| `agentguard/schemas.py` | Pydantic models: `ScanReport`, `SearchResult`, `AttackReport`, `TraceEvent` |
| `agentguard/runs.py`, `server.py`, `static/index.html` | Runs, the API and live event stream, the dashboard |

## Requirements

- Python 3.10+
- An Anthropic API key
- [uv](https://docs.astral.sh/uv/), for the external MCP servers (started with `uvx`):
  - Semgrep: also `uv tool install semgrep`. Without it the Search agent uses `search_code` only.
  - Fetch (`mcp-server-fetch`): downloaded by `uvx` on first use.

Only Python projects are supported for now. The project's agent must call its model through LiteLLM or the
OpenAI SDK (so AgentGuard can give it its own key), or read a key from the environment.
