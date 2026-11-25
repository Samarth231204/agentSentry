# AgentGuard: agentic design patterns

AgentGuard tests an AI agent the way an attacker would, then writes a report. Each part uses the pattern
that fits its job. This page lists every pattern, where it lives in the code, and why it was chosen.

```
                 CrewAI Flow (checkpointed after every step)
 scan ──▶ Search agent ──▶ ── A2A ──▶ ADK attack service ── A2A ──▶ CrewAI review service ──▶ report
 (MCP)    (CrewAI ReAct)              11 attack agents              Lead · Triage · Writer · QA
                                      sandbox + oracles   ◀── A2A ── (Lead asks for re-tests)
```

| # | Pattern | Where | Why |
|---|---|---|---|
| 1 | **Sequential pipeline (workflow)** | `agents/search.py` `SearchFlow`: scan → search → attack → report | The order never changes, so code controls it, not a model. Each step's output is the next step's input, saved in Flow state. |
| 2 | **ReAct (reason + act)** | Search agent, `agents/search.py` | Finding the main LLM call and risky tools needs exploration: think, call a tool, read the result, repeat. Text ReAct gives a visible Thought before every action. |
| 3 | **Tool use through MCP** | `mcp/scan_server.py` (ours), `mcp/semgrep.py`, `mcp/fetch.py` (official servers), `mcp/payload_server.py` (ours) | Tools sit behind a standard protocol, so any agent framework can use them, and every call is traced. |
| 4 | **Specialist agents (one per attack type)** | `attack/team.py`, one ADK `LlmAgent` per category | A focused agent with one goal and one oracle does better than one agent juggling eleven attacks. |
| 5 | **Plain code checks the model (oracles)** | `attack/oracles.py` | A finding is "confirmed" only when code sees it happen in the sandbox. Models can only say "suspected". This removes model judgement from the verdict. |
| 6 | **Sandbox with intercepted side effects** | `sandbox/harness.py`, `sandbox/runner.py` | Attacks run against a copy of the project in its own process; acting tools are recorded and faked, so nothing real happens. |
| 7 | **Orchestrator** | Security Lead, `review/crew.py` | One agent plans the review and decides what needs another look. |
| 8 | **Agent-to-agent delegation (A2A)** | `a2a/`: ADK attack service and CrewAI review service, each with an Agent Card | The two frameworks talk over the official A2A protocol (JSON-RPC over HTTP). ADK hands results to CrewAI (`RemoteA2aAgent`); the Security Lead asks ADK for re-tests (a2a-sdk client). |
| 9 | **Evaluator–optimizer (re-test loop)** | `RetestTool` in `review/crew.py` | A suspected finding goes back to the attack agent with a hint; if the oracle now confirms it, the finding is upgraded. |
| 10 | **Step-by-step specialists (triage)** | Triage Analyst | Dedupe, rate severity (OWASP-based), rank: one clear job with a structured output. |
| 11 | **Structured output** | Pydantic models in `schemas.py`, `output_pydantic` on every task | Every agent's output is validated data (`SearchResult`, `AttackReport`, `TriageResult`, `ReportDraft`, `QAReview`, `FinalReport`), not free text. |
| 12 | **Reflection (critic)** | QA Reviewer, with one revision round (`ReviewFlow.check` → `revise`) | A second agent checks every claim against the evidence; a rejected draft goes back to the writer. |
| 13 | **Guardrails** | `guardrails.py`, CrewAI task guardrails, ADK before/after callbacks | Untrusted text is fenced and scanned for injections; attack messages are checked for abuse; tool inputs and outputs are type-checked; task guardrails reject statuses or evidence the data does not support. |
| 14 | **Facts from code, words from models** | `review/crew.py` `assemble()`, `review/report.py` | Tables, statuses, evidence, cost and time come from the data; agents supply ranking and prose only. |
| 15 | **Graceful fallback** | `code_triage`, `code_draft`, Lead fallback in `review/crew.py` | If a model declines or fails, code finishes that step from the data, and the report says so. |
| 16 | **Checkpointing and resume** | CrewAI `CheckpointConfig` (`checkpoints.db`, `review_checkpoints.db`); ADK `DatabaseSessionService` (`adk_sessions.db`) | Every step and every agent turn is saved; a stopped run continues where it stopped. |
| 17 | **Observability by events** | `events.py` bus → `trace.jsonl`, dashboard (SSE), LangFuse (`observability.py`) | One event stream feeds the local trace, the live dashboard and LangFuse spans, generations (with cost), A2A spans and scores. |
| 18 | **Evaluation against known answers** | `evals.py`, `evals/vulnlab.json` | VulnLab's 11 apps have known weaknesses; each run on it is scored (detection rate, false alarms) and recorded as a LangFuse dataset run. |

## Why two frameworks

- **CrewAI** suits role-based work: the Search agent (ReAct) and the review crew (Lead, Triage, Writer, QA),
  with Flows for ordering and checkpoints.
- **Google ADK** suits many small tool-using agents driven by code: callbacks on every model and tool call,
  and a database session per agent that saves every event.
- **A2A** joins them without either knowing the other's internals: each side only reads the other's Agent Card.
