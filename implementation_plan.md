# AgentGuard — Implementation Plan

Red-teams AI agent applications automatically. Two frameworks split by role:
**ADK** attacks a live target over HTTP (stateful, adaptive); **CrewAI** turns
the resulting findings into a report offline (deterministic, re-runnable).
`findings.json` is the only thing that crosses between them.

Guiding rules, unchanged for the whole build:
- ADK is the only half that talks to the target. CrewAI never opens a socket.
- Attacks run to completion and serialize to disk *before* the crew starts —
  never interleave the two event loops.
- Every phase ends with a validation step. Do not start the next phase until
  that step passes.

---

## Phase 0 — Repo scaffolding

**Build:**
- `pyproject.toml` (package name `agentguard`, deps: fastapi, uvicorn,
  pydantic, google-adk, litellm, crewai, chromadb, pyyaml, click, httpx)
- Package skeleton: `agentguard/{adapter,target,manifest,attackers,reporters,cli}.py`
- `samples/` directory (empty, populated in Phase 2)
- `.gitignore`, `README.md` stub, `git init` + first commit

**Validate:**
- `pip install -e .` succeeds in a clean venv
- `python -c "import agentguard"` succeeds
- `agentguard --help` (empty CLI stub is fine) runs without error

---

## Phase 1 — `adapter.py` + `target.py` (the target-side shim + client)

This is the foundation everything else calls — build it first, per the
system design.

**Build (`adapter.py`):**
- `@expose` decorator wrapping a user entrypoint as `POST /invoke`
- `@watch` decorator recording tool calls via a `contextvars.ContextVar` list
  (concurrency-safe — no shared mutable state across requests)
- `POST /invoke {input_text, session_id}` →
  `{output, tool_calls, error, latency_ms}`
- `GET /health`
- Exceptions inside the entrypoint are caught and returned as
  `{"type": ..., "detail": ...}`, never allowed to crash the server
- Binds `127.0.0.1` only

**Build (`target.py`):**
- `Target` class: wraps `httpx` client, generates session IDs, exposes
  `.invoke(text, session_id=None)` and `.health()`

**Validate:**
- Write one dummy target app (`@expose def run(...)`, one `@watch`-decorated
  fake tool) inline in a test file
- Start it with uvicorn, `curl /health` → 200
- `curl /invoke` with a text payload → response contains **both** real text
  output **and** a non-empty, correctly-shaped `tool_calls` list
- Trigger an exception path deliberately → confirm it comes back as
  structured JSON, not a 500 with a raw traceback, and the server stays up
- Fire two concurrent `/invoke` calls with different session IDs → confirm
  `tool_calls` logs don't cross-contaminate (proves the contextvar isolation)

---

## Phase 2 — Vulnerable sample agents

Build these *before* the attackers, per the plan — they're both the test
fixtures for Phase 4 and the demo material.

**Build**, each using the Phase 1 adapter:
1. **`samples/rag_leaky/`** — RAG agent that obeys instructions embedded in
   retrieved documents (prompt injection via retrieval)
2. **`samples/unsafe_tool/`** — agent with an unguarded destructive
   `@watch`-decorated tool (e.g. `transfer_funds`) reachable with no
   confirmation step
3. **`samples/prompt_leak/`** — agent with a system prompt containing a
   canary string, vulnerable to direct/indirect exfiltration

For each sample, write down (in a comment or short doc) the *expected*
finding: what should be discoverable and how.

**Validate:**
- Manually exploit each sample by hand (raw `curl` against `/invoke`) and
  confirm the expected vulnerability actually fires — e.g. the destructive
  tool executes with no gate, the canary appears verbatim in a response
- Confirm all three run under the Phase 1 adapter/target client with no
  adapter-level errors
- This gives you a written "answer key" — the set of true positives Phase 4
  attackers must find, and the false-negative baseline to measure against

---

## Phase 3 — `manifest.py` (static analysis)

**Build, in this order — ship the escape hatch first so nothing downstream
blocks on discovery:**
1. `Manifest.from_yaml()` / `Manifest.to_yaml()` — load/save a manifest by
   hand-authored YAML. This unblocks Phase 4 development immediately.
2. AST scanner: `ast.parse` target source, walk for `@tool`-decorated
   functions, `Agent(...)`/`Task(...)` calls, vectorstore imports, memory
   objects — structural detection, not regex
3. Chroma indexing of the scanned source; retrieve context around each
   candidate
4. LLM synthesis step: given AST candidates + retrieved context, emit the
   final `manifest.yaml` (tools with `destructive` flags, `rag.present`,
   `memory.present`, `multi_agent`)

**Validate:**
- Hand-write a `manifest.yaml` for each of the 3 Phase 2 samples and confirm
  `from_yaml`/`to_yaml` round-trips losslessly
- Run the full AST+Chroma+LLM pipeline against each of the 3 samples;
  compare the generated manifest against the hand-written one — confirm it
  correctly flags: the destructive tool as `destructive: true`, `rag.present`
  for the RAG sample, and doesn't false-positive `rag`/`memory` on the
  samples that lack them
- Confirm routing keys are correct (this manifest would trigger exactly the
  right attacker categories per the routing table in Phase 4)
- Timebox this phase — if AST+Chroma synthesis stalls, fall back to
  YAML-authored manifests and keep moving; note it as a known limitation

---

## Phase 4 — `attackers.py` (ADK, live probing)

**Build:**
- `findings.json` schema finalized first (target info, manifest summary,
  per-attempt: id, category, capability_targeted, turns, oracle,
  oracle_detail, success) — write a hand-crafted fake `findings.json`
  matching this schema before writing any attacker code, so Phase 5 can
  start against a fixture without waiting on live attacks to work
- `make_attacker(category, playbook, target, sink)` factory: one `LlmAgent`
  per category, two tools (`send_probe`, `record_finding`), playbook carries
  tactics + escalation ladder but agent chooses the sequence
- Runner loop (`InMemorySessionService` + ADK `Runner`), turn cap, stop on
  `record_finding`
- Category routing table driven by the Phase 3 manifest (prompt_injection /
  secret_extraction always; tool_misuse if any destructive tool;
  rag_poisoning if rag.present; memory_persistence if memory.present)
- Fresh `session_id` per attempt, except memory_persistence (deliberately
  reused)
- Three oracles, in priority order:
  1. **Canary** — per-location unique strings (system prompt, fake env var,
     each RAG doc), substring + truncated-prefix + base64 match
  2. **Side-effect** — destructive tool call in `tool_calls` with no
     intervening confirmation turn
  3. **LLM judge** — fallback only, stores raw request/response beside
     verdict
- Manifest-vs-observed diff: flag any tool name seen in `tool_calls` that
  isn't in the manifest as its own finding (undeclared capability)
- Shared LLM wrapper (single client) with response caching + backoff to
  stay under Groq rate limits; smallest model for judge calls; stop probing
  a category immediately on a proven hit

**Validate:**
- Run all attacker categories against all 3 Phase 2 samples
- Confirm **at least one true positive per sample**, matching the answer key
  written in Phase 2
- Inspect at least one transcript and confirm visible adaptation — a
  reformulated attempt after an earlier turn was refused (this is the actual
  proof ADK's statefulness is doing something, not cosmetic)
- Confirm canary and side-effect oracles fire correctly with zero LLM judge
  calls where proof is available (spot check `oracle` field in output)
- Confirm the manifest-diff check correctly catches an undeclared tool call
  if you temporarily strip a tool from the manifest
- Run the full suite twice against `rag_leaky` and confirm no rate-limit
  failures / crashes; if there are, tune caching/backoff before proceeding
- Resulting `findings.json` files become the fixtures for Phase 5

---

## Phase 5 — `reporters.py` (CrewAI, offline reporting)

**Build:**
- Three agents: severity analyst, remediation engineer, report writer
  (roles/backstories as specified), sequential `Process`
- Analyst receives manifest `destructive` context; engineer receives
  matching source snippet from Chroma for concrete fixes; writer quotes
  transcripts verbatim, no paraphrase
- Scorecard (counts, pass/fail table, category coverage) computed in plain
  Python, fed to the writer as data — not delegated to the LLM
- `report.md` assembly: scorecard → per-finding section (verbatim
  transcript, oracle proof line, severity, fix) → attempted-but-failed
  appendix

**Validate:**
- **Stop the target server entirely.** Regenerate `report.md` from the
  Phase 4 `findings.json` fixtures with zero network calls to the target —
  confirms the ADK/CrewAI boundary is real, not accidental
- Confirm every finding in `report.md` traces back to a real transcript
  excerpt in `findings.json` — no invented evidence
- Confirm remediation text names actual functions/files from the sample
  (e.g. "add a confirmation turn before `transfer_funds` in
  `samples/unsafe_tool/tools.py`"), not generic advice like "improve
  validation"
- Run report generation twice from the same fixed `findings.json` — confirm
  the scorecard numbers are identical both times (proves determinism; prose
  may vary, numbers must not)

---

## Phase 6 — `cli.py` + docs + end-to-end validation

**Build:**
- `agentguard init <path>` — scaffolds/generates a manifest for a target
  project
- `agentguard test <path>` — runs manifest → attackers → findings.json →
  reporters → report.md, end to end
- Scorecard arithmetic surfaced in CLI output
- README: install steps, quickstart, one-line defense-architecture summary,
  explicit callout of the canary/instrumentation limitation on
  uninstrumented targets

**Validate (final gate — full clean-room run):**
- From a fresh clone (or fresh checkout) with no local state:
  `pip install -e .` → `agentguard init ./samples/rag_leaky` →
  `agentguard test ./samples/rag_leaky` → confirm `report.md` is produced
  with at least one confirmed finding
- Repeat for `unsafe_tool` and `prompt_leak`
- Confirm total wall-clock time and Groq call count are reasonable for a
  live demo (no rate-limit failures across all three samples run back to
  back)
- Confirm the two frameworks never run concurrently at any point (check
  logs/timestamps — attacker phase fully completes and writes
  `findings.json` before the CrewAI phase starts)
- Sanity-read one full `report.md` top to bottom as if seeing it for the
  first time — scorecard, findings, fixes, failed-attempts appendix all
  present and coherent

---

## Cross-cutting risks to watch during the above phases

- **Groq rate limits** — mitigated in Phase 4 (shared client, caching,
  backoff, early-stop). Re-check at Phase 6's full run.
- **Two event loops** — enforced structurally by the `findings.json`
  boundary; verified explicitly in Phase 5 and Phase 6.
- **Static analysis time sink** — mitigated by shipping `from_yaml` first
  in Phase 3; timebox the AST+Chroma+LLM synthesis work.
- **Canaries require an instrumented target** — real on any target outside
  `samples/`; documented as a known limitation in the Phase 6 README rather
  than solved.
