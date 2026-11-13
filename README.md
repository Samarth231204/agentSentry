# AgentGuard

Red-team the AI agent in your Python project, from a local dashboard.

AgentGuard finds the agent's entrypoint and tools by reading your code (it never runs it), shows you what it plans to
watch, and waits for your approval. Then it starts your agent with recording wrappers applied (your files are not
edited), attacks it with an LLM attacker, and writes a report. Every step is in the dashboard.

## Quick start

Requirements: Python 3.10+, `git`, and [uv](https://docs.astral.sh/uv/) (for Semgrep's MCP server). Node is optional.

```bash
cd your-project
git clone <this repository> agentguard           # one folder inside your project
./agentguard/bootstrap.sh                        # venv, install, keep AgentGuard out of git
./agentguard/.venv/bin/agentguard doctor         # what is set up, what is missing
./agentguard/.venv/bin/agentguard up             # starts the backend and opens the dashboard
```

In the dashboard:

1. **Set up key** — paste an API key once (Groq, OpenAI, Anthropic, Gemini or OpenRouter). It is saved to
   `<your-project>/.agentguard/.env` with mode 600, and the browser never keeps it. Test it with one tiny request.
2. **New run** — leave "Automatic" selected and keep "Review the plan" ticked. Click **Run**.
3. **Plan** — untick anything that should not be watched. Tools that change state are sandboxed (recorded, not executed).
   Approve.
4. **Watch the run** — progress, the live trace, and the MCP panel. When it finishes, open the findings and the report.

Want no spend while you look around? Tick **Mock mode** on the New run page. It runs the whole pipeline with no provider
calls. Mock results prove plumbing only, not vulnerability.

## What you get

- Findings with status (confirmed, suspected, failed, error), the oracle that decided, and the verbatim transcript.
- A report with severity, remediation, OWASP LLM Top 10 mapping and `file:line` code references.
- A trace of every model call, tool call, MCP call, A2A call and phase, with token usage and budgets.

## Safety

- Discovery never runs your code. The plan is applied by an import hook, so your files stay as they are.
- Destructive tools are sandboxed by default: they are recorded but not executed.
- Targets must be on localhost or 127.0.0.1. Remote targets are refused.
- Keys stay in `.agentguard/.env` (mode 600). They are never logged, never in trace events, and never returned unmasked.
- The attacker never sees your system prompt.

## Setup checklist

| Needed | For | How |
|---|---|---|
| Python 3.10+ | everything | system or pyenv |
| `uv` | Semgrep's MCP server (optional but recommended) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Semgrep binary | sink evidence (optional) | `uv tool install "semgrep==1.135.0" --with setuptools` |
| An API key | live runs (not mock mode) | paste it in **Set up key** |
| Node 20+ | only to develop the dashboard | `scripts/build_dashboard.sh` rebuilds the bundle |
| Free ports 8787, 8790, 8791 | backend and MCP servers | `agentguard doctor` checks them |

## Developer notes

- Dashboard: `dashboard/` (Next.js, TypeScript). `npm run dev` runs it against `NEXT_PUBLIC_AGENTGUARD_API`.
  The built bundle is committed under `agentguard/server/static/`; rebuild it with `scripts/build_dashboard.sh`
  after dashboard changes.
- Tests: `python -m pytest -q` (about 250 tests, mock-based and no network, except the Semgrep test which is skipped when
  Semgrep is missing).
- Docs: [architecture](docs/architecture.md), [design patterns](docs/design-patterns.md), [MCP](docs/mcp.md),
  [A2A](docs/a2a.md), [implementation plan](IMPLEMENTATION_PLAN.md) (local only).

## Command line (manual path)

The CLI still works without the dashboard. Use `@expose` and `@watch` from `agentguard.adapter` in your app, then:

```bash
agentguard init PROJECT              # static scan -> manifest.yaml
agentguard test PROJECT --target-url http://127.0.0.1:8000 --max-probes 3
agentguard report PROJECT --findings findings.json
agentguard mcp list PROJECT          # starts both MCP servers, prints their tools, stops them
```

See [USER_MANUAL.md](USER_MANUAL.md) for the full CLI reference.

## License

MIT. See [LICENSE](LICENSE).
