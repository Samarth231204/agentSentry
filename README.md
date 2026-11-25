# AgentGuard

AgentGuard finds the parts of an AI agent that an attacker would target, attacks them in a sandbox, and
writes an evidence-backed report with cost and running time.

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
  3. attack  A2A task to the ADK attack service (Agent Card at :8771/.well-known/agent-card.json)
             11 ADK attack agents (Haiku 5.5), one per attack type, one after another
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
  4. review  ADK hands the results to the CrewAI review service over A2A (ADK RemoteA2aAgent → :8772)
             Security Lead   plans; re-tests suspected findings by calling the ADK service back over A2A
             Triage Analyst  dedupes, rates severity (OWASP-based), ranks
             Report Writer   writes the prose; every claim cites probe ids
             QA Reviewer     checks every claim against the evidence; a rejected draft is revised once
             task guardrails reject statuses or probe ids the data does not support
  5. report  report.json + report.md: findings, evidence, re-tests, QA, cost per agent and model,
             time per step, A2A calls; on a known test project (VulnLab) an eval against known answers
```

Design patterns used, and why: [docs/DESIGN_PATTERNS.md](docs/DESIGN_PATTERNS.md).

Attack types: prompt injection, secret extraction, tool misuse, data exfiltration, privilege escalation,
RAG poisoning, memory persistence, unsafe command execution, SQL injection, insecure output handling, and
indirect prompt injection through a web page (only when the app has a tool that reads web pages).

Each run lives in `your-project/.agentguard/runs/<run-id>/`:
- `search.json`, the Search agent's result
- `attacks.json`, the attack results (including re-tests)
- `report.json`, `report.md`, the final report; `eval.json` on a test project
- `trace.jsonl`, every thought, action, observation, probe, guardrail hit and MCP call
- `checkpoints.db`, `review_checkpoints.db`, the CrewAI checkpoints (main flow, review crew)
- `adk_sessions.db`, the ADK attack agents' sessions (every event saved)
- `sandbox/`, the project copy and its log
- `trap_pages/`, the web pages planted for indirect injection
- `retests/`, the re-tests the Security Lead asked for

A failed or stopped run resumes from its last checkpoint.

**Monitoring and safety.**
- CrewAI event listeners and ADK callbacks (before/after model, before/after tool, tool errors) send every step to the trace and the live dashboard.
- Guardrails:
  - The target's replies are fenced as untrusted, and checked for prompt injection.
  - Our attackers' messages are checked for abusive language.
  - Tool arguments and return types are validated.
  - The Search agent's tool output is checked for injections planted in code.
- LangFuse switches on when `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY` are set: one trace per run with
  a span per step, every model call as a generation with tokens and cost, A2A calls, guardrail events, and
  scores (confirmed, suspected, probes, cost_usd, seconds, qa_approved; on VulnLab detection_rate and
  false_alarms, plus a dataset run).

**A2A services.** `agentguard up` starts both inside its own process, each on its own port. In the cloud
run them separately with `agentguard a2a-attack` and `agentguard a2a-review`, and point
`AGENTGUARD_A2A_ATTACK_URL` / `AGENTGUARD_A2A_REVIEW_URL` at them. `AGENTGUARD_A2A=0` runs the same agents
in-process without A2A.

## Deploy on AWS

One EC2 instance (`m7i-flex.large`, Mumbai by default) runs the Docker image: the dashboard, the Search agent and
both A2A services (ADK attack, CrewAI review). The demo target, VulnLab, sits next to AgentGuard and is mounted
into the container.

```
your laptop ── deploy/aws/deploy.sh ──▶ S3 (release + run results, private, encrypted)
                                       SSM Parameter Store (/agentguard/*, SecureString: keys from .env)
                                       IAM role (read those keys, read/write that bucket, Session Manager)
                                       EC2 ── docker: agentguard up --host 0.0.0.0 ──▶ :8765, your IP only
```

```bash
aws login                         # or aws sso login
deploy/aws/deploy.sh up           # first time: creates everything, prints the dashboard URL
deploy/aws/deploy.sh update       # ship new code
deploy/aws/deploy.sh keys         # .env changed: copy it to SSM and restart
deploy/aws/deploy.sh allow-ip     # your IP changed (the dashboard has no login, so it is IP-restricted)
deploy/aws/deploy.sh stop|start   # stop when not in use: only the disk is billed
deploy/aws/deploy.sh status|logs
```

There is no SSH port; for a shell use `aws ssm start-session --target <instance id>`. Run results are copied to
`s3://agentguard-<account>-<region>/runs/` every 5 minutes. The image also runs anywhere else:
`docker build -t agentguard . && docker run --env-file .env -p 8765:8765 -v "$PWD/../your-project:/project" agentguard`.

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
| `agentguard/a2a/` | Agent Cards, the ADK attack service, the CrewAI review service, the A2A client |
| `agentguard/review/crew.py`, `review/report.py` | The review crew (Flow, guardrails, fallbacks); the final report |
| `agentguard/costs.py`, `agentguard/evals.py`, `evals/` | Prices and cost; run scores and test sets with known answers |
| `agentguard/observability.py` | LangFuse tracing (optional) |
| `Dockerfile`, `deploy/aws/` | The image; the AWS deploy (S3, SSM, IAM, EC2) |
| `agentguard/schemas.py` | Pydantic models: `ScanReport`, `SearchResult`, `AttackReport`, `LeadPlan`, `TriageResult`, `ReportDraft`, `QAReview`, `FinalReport` |
| `agentguard/runs.py`, `server.py`, `static/index.html` | Runs, the API and live event stream, the dashboard |

## Requirements

- Python 3.10+
- An Anthropic API key
- [uv](https://docs.astral.sh/uv/), for the external MCP servers (started with `uvx`):
  - Semgrep: also `uv tool install semgrep`. Without it the Search agent uses `search_code` only.
  - Fetch (`mcp-server-fetch`): downloaded by `uvx` on first use.

Only Python projects are supported for now. The project's agent must call its model through LiteLLM or the
OpenAI SDK (so AgentGuard can give it its own key), or read a key from the environment.
