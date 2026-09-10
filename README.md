# AgentGuard

Automated red-teaming for AI agent applications. Two frameworks split by
role:

- **ADK** (`agentguard/attackers.py`) attacks a live target over HTTP —
  stateful, adaptive, one `LlmAgent` per attack category, escalating
  through refusal.
- **CrewAI** (`agentguard/reporters.py`) turns the resulting
  `findings.json` into `report.md` — offline, deterministic,
  re-runnable, no network access to any target.

`findings.json` is the only thing that crosses between them. ADK writes it
and exits; CrewAI reads it and never opens a socket.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Add `.env` (gitignored) with:
```
GROQ_API_KEY=your-key-here
```

## Quickstart

```bash
# 1. Instrument your target (see below), then run it:
uvicorn your_app:app --host 127.0.0.1 --port 8000

# 2. Scan it statically (safe, never executes the target):
agentguard init path/to/your_app

# 3. Attack the running target and generate a report:
agentguard test path/to/your_app --target-url http://127.0.0.1:8000
```

Output: `findings.json` (raw attack transcripts) and `report.md`
(scorecard, per-finding severity + remediation, failed-attempts appendix).

## Instrumenting a target

```python
from agentguard import expose, watch

@expose
def run(input_text, session_id=None):
    return my_agent.run(input_text)

@watch
def transfer_funds(to, amount):
    return bank.send(to, amount)
```

`@expose` marks your entrypoint, served at `POST /invoke`. `@watch` marks
any function worth observing — its calls are recorded per-request (safe
under concurrent requests) and show up in `findings.json`'s `tool_calls`.

## Known limitations

- **Canary detection needs an instrumented target.** The canary oracle
  looks for known strings in target responses — it works perfectly
  against the three vulnerable samples in `samples/` (each has a known
  planted secret/marker, documented in `samples/README.md`), but is
  useless against a stranger's repo with no known canary. On an
  unfamiliar target, findings rely on the side-effect oracle (destructive
  tool calls) and the LLM judge fallback instead.
- **Groq's free tier rate-limits hard**, both per-minute and per-model
  per-day. `AGENTGUARD_ATTACKER_MODEL` and `AGENTGUARD_REPORTER_MODEL`
  env vars let you switch models when one's quota is exhausted (see
  `implementation_phase4.md` / `implementation_phase5.md` for the
  specific caps hit during development).
- **`_source_snippets()` in `reporters.py` truncates each file to ~1200
  chars** rather than using real retrieval — fine for the small samples
  here, not a general solution for large target codebases (Phase 3's
  Chroma index exists but isn't wired into the reporter yet).

## Samples

Three deliberately vulnerable agents in `samples/`, each hand-exploited
and documented as an answer key in `samples/README.md`:
`rag_leaky`, `unsafe_tool`, `prompt_leak`.

## Development history

Each implementation phase has its own summary doc at the repo root
(`implementation_phase1.md` through `implementation_phase6.md`) covering
what was built, how it was validated, and every bug hit along the way.
