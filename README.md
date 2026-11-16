# AgentGuard

Red-team the AI agent in your Python project, from a local dashboard.

AgentGuard finds the agent's entrypoint and tools by reading your code (it never runs it), shows you what it plans to
watch, and waits for your approval. Then it starts your agent with recording wrappers applied (your files are not
edited), attacks it with an LLM attacker, and writes a report. Every step is in the dashboard.

## Quick start

Requirements: Python 3.10+, `git`, and [uv](https://docs.astral.sh/uv/) (for Semgrep's MCP server). Node is optional.

```bash
cd your-project
git clone <this repository> AgentGuard           # one folder inside your project
./AgentGuard/run                                 # sets up on first run, then opens the dashboard
```

`run` does everything: the first time, it creates AgentGuard's own Python environment, installs AgentGuard and your
project's `requirements.txt` (your agent runs inside that environment), and adds `AgentGuard/` and `.agentguard/` to
your project's `.gitignore`. Later runs skip what is already done and start straight away. Stop it with Ctrl+C.
To test one sub-folder of a larger repo, pass it: `./AgentGuard/run path/to/agent`.

In the dashboard:

1. **Get started** — paste an API key once (Anthropic is recommended; add the Workspace ID if your key needs one). It is
   saved to `<your-project>/.agentguard/.env` with mode 600, and the browser never keeps it. Test it with one tiny request.
2. **New test** — keep "Review the plan" ticked and click **Start test**.
3. **Plan** — untick anything that should not be watched. Tools that change state are sandboxed (recorded, not executed).
   Approve.
4. **Evidence** — when the run finishes, this tab shows each attack that got through, the part of your agent it got
   through (a tool, the system prompt, retrieval, memory), the attack conversation, and the vulnerable lines of your code.

## What you get

- Evidence: the vulnerable parts of your agent per attack, the attack logs that prove it, and the real code behind it.
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
| An API key | every test | paste it in **Get started** or **Settings** |
| Node 20+ | only to develop the dashboard | `scripts/build_dashboard.sh` rebuilds the bundle |
| Free ports 8787, 8790, 8791 | backend and MCP servers | `agentguard doctor` checks them |

## Developer notes

- Dashboard: `dashboard/` (Next.js, TypeScript). `npm run dev` runs it against `NEXT_PUBLIC_AGENTGUARD_API`.
  The built bundle is committed under `agentguard/server/static/`; rebuild it with `scripts/build_dashboard.sh`
  after dashboard changes.
- Tests: `python -m pytest -q` (about 300 tests, mock-based and no network, except the Semgrep test which is skipped when
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
