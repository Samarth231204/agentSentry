# Phase 1 — Adapter + Target Client

## 1. Summary

Phase 1 built the foundation every later phase calls into: a way to turn any
Python agent entrypoint into a uniform HTTP surface (`adapter.py`), and a
client to drive it (`target.py`). Nothing about attacking or reporting lives
here — this phase only answers "how do we talk to an arbitrary target and
see what it did internally."

Two artifacts, ~150 lines total:

- **`agentguard/adapter.py`** — lives inside the target process. `@expose`
  registers the entrypoint as `POST /invoke`; `@watch` wraps any function so
  its calls are recorded per-request via a `contextvars.ContextVar`, not a
  shared list, so concurrent requests don't bleed into each other's logs.
  `GET /health` reports whether an entrypoint is registered.
- **`agentguard/target.py`** — the attacker/CLI-side client. `Target.invoke()`
  posts to `/invoke` and returns the parsed JSON; `Target.health()` checks
  the server is up; `new_session_id()` generates a UUID per attempt.

Supporting scaffolding added to make this runnable and testable: a minimal
`pyproject.toml`, package skeleton, and `tests/dummy_app.py` — a fixture app
with one normal `@watch`-ed tool (`lookup_balance`) and one that deliberately
raises on a specific input (`"boom"`), used to exercise the error path.

## 2. Pipeline (what actually runs)

```
target process                          attacker/CLI process
───────────────                          ─────────────────────
tests/dummy_app.py
  @watch lookup_balance(account)
  @expose run(input_text, session_id)
        │
        ▼
agentguard.adapter.app  (FastAPI)
  GET  /health   → {status, entrypoint_registered}
  POST /invoke   → {output, tool_calls, error, latency_ms}
        │  contextvars.ContextVar isolates
        │  each request's tool_calls list
        ▼
uvicorn tests.dummy_app:app --port 8000
                                                  │
                                                  ▼
                                          agentguard.target.Target
                                            .health()
                                            .invoke(text, session_id)
                                            (never raises on target-side
                                             errors — returns them as data)
```

Request lifecycle inside `/invoke`:

1. `contextvars.ContextVar` is seeded with an empty list, token saved.
2. Entrypoint is called (with `session_id=` only if the function accepts it).
3. Any `@watch`-ed function called along the way appends
   `{name, args, ts}` to that request's list via `inspect.signature`
   argument binding.
4. Exceptions from the entrypoint are caught and returned as
   `{"type": ..., "detail": ...}` — never a raw 500 traceback, never a
   crashed server.
5. The contextvar is reset (`token`) before the response is built, so the
   next request starts clean regardless of what happened.

## 3. Validation performed

All five checks from `implementation_plan.md`'s Phase 1 gate were run and
passed — both as an automated script and manually via `curl`:

| Check | Result |
|---|---|
| Clean venv install (`pip install -e .`) + `import agentguard` | pass |
| `GET /health` → 200 with entrypoint flag | pass |
| `POST /invoke` returns real output **and** non-empty `tool_calls` | pass |
| Forced exception (`input_text="boom"`) returns structured JSON; server stays alive for the next request | pass |
| 5 concurrent `/invoke` calls, distinct session IDs → zero cross-contamination in `tool_calls` | pass |

## 4. Problems and bugs faced

None surfaced during this phase's implementation — Phase 1 was built,
installed, and validated cleanly on the first pass (install succeeded,
imports succeeded, all curl/concurrency checks passed without a failing run
or a code fix in between).

That said, three specific failure modes were designed against up front,
precisely because they're the ones that bite this kind of shim in practice.
Recording them here since they were live risks during design, verified
closed during validation rather than genuine bugs hit-and-fixed:

- **Shared mutable state across concurrent requests.** A naive
  implementation of `@watch` (a plain module-level list) would let two
  simultaneous `/invoke` calls interleave their tool-call logs. Using
  `contextvars.ContextVar` instead of a global list was the deliberate
  fix-in-advance; the 5-way concurrent curl test in the validation table
  above exists specifically to prove this doesn't happen.
- **A target-side exception killing the whole server or attack run.**
  Wrapping the entrypoint call in `try/except` and returning the exception
  as `{"type", "detail"}` data (rather than letting FastAPI's default
  500-with-traceback behavior take over) was necessary because an attacker
  loop that crashes on the first exploited crash would be useless — a
  crash *is* a finding, not a reason to stop. Verified by the `"boom"` test
  case and the follow-up health check.
- **Argument binding breaking on functions with unusual signatures.**
  `_bind()` uses `inspect.signature(...).bind_partial()` to map positional
  and keyword args to names for the tool-call log, but wraps it in a
  `try/except TypeError` fallback to `{"args": [...], "kwargs": {...}}` in
  case a `@watch`-ed function uses `*args`/`**kwargs` and can't be bound
  cleanly. Not exercised by the current dummy app (its signature is plain),
  so this remains a designed-for edge case to watch when Phase 2's sample
  agents introduce real tool signatures — flagging it here rather than
  claiming it as validated.
