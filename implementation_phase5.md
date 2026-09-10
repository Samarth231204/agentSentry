# Phase 5 — `reporters.py` (CrewAI, offline reporting)

## 1. Summary

Phase 5 is the reflecting half: a one-shot, offline, deterministic
transform over `findings.json` (already written by Phase 4) into
`report.md`. Three CrewAI agents in a sequential process — severity
analyst, remediation engineer, report writer — never open a network
connection to any target; `agentguard/reporters.py` has no import of
`agentguard.target`.

- **`compute_scorecard()`** — plain Python arithmetic (counts, success
  rate, per-category breakdown), never delegated to the LLM.
- **`_source_snippets()`** — reads real source files for each
  manifest-declared tool, so remediation cites actual function signatures
  instead of inventing plausible-looking ones.
- **`build_crew()`** — three `Agent`s + three sequential `Task`s (rate →
  fix → write), the fix task fed real source, the write task fed the
  scorecard verbatim plus both confirmed and failed attempts.
- **`generate_report()`** — findings.json (+ optional manifest.yaml) in,
  report.md out, with manual retry/backoff around `crew.kickoff()` for
  Groq's rate limits.

## 2. Pipeline

```
findings.json (written by Phase 4, attackers.py)
manifest.yaml (optional, for real source)
        │
        ▼
compute_scorecard()          -- pure Python, no LLM
_source_snippets(manifest)   -- reads real .py files for declared tools
        │
        ▼
Crew(process=Process.sequential):
  rate_task  (severity analyst)   -> severity + justification per finding id
  fix_task   (remediation engineer, sees real source) -> concrete fix per id
  write_task (report writer, sees scorecard + fixes + failures) -> report.md
        │
        ▼
report.md written to disk — zero calls to agentguard.target at any point
```

## 3. Validation performed

| Check | Result |
|---|---|
| Target server **stopped entirely** (verified via `lsof`/`ps` before running) before report generation | confirmed — report generated with zero live target |
| Every finding in `report.md` traces to a real transcript in `findings.json` | confirmed — transcripts quoted, not summarized (French-translation leak, `transfer_funds` execution) |
| Remediation names real functions/files, not generic advice | confirmed after the source-snippet fix — cites `transfer_funds(to: str, amount: float)` and `samples/unsafe_tool/app.py` exactly, including the real `@watch` decorator convention |
| Scorecard numbers used verbatim, not recomputed by the LLM | confirmed — `compute_scorecard()` output appears unchanged in the report's JSON block |
| `compute_scorecard()` determinism (same input twice) | confirmed — byte-identical dict across repeated calls, tested in Phase 4/5 validation |
| Zero-findings case doesn't fabricate a finding | not separately exercised this phase — the write task's instruction explicitly handles it ("state that plainly... instead of fabricating one"), but no sample produced zero confirmed findings to test against; flagged as an untested path, not claimed as verified |

## 4. Problems and bugs faced

- **CrewAI's generic (litellm-backed) `LLM` path adds an Anthropic-style
  `cache_breakpoint` flag to every message for prompt caching, but only
  its Anthropic-specific completion class strips it back out before
  sending — the litellm/Groq path never does.** First report-generation
  attempt crashed immediately: `property 'cache_breakpoint' is
  unsupported`. Same class of bug as Phase 4's `reasoning_content` issue —
  a framework feature leaking a provider-specific field into a request the
  target provider rejects outright. Fix: monkeypatched
  `crewai.llms.cache.mark_cache_breakpoint` to a no-op at import time in
  `reporters.py`, since the call sites re-import it fresh from the module
  on each use (a local `from crewai.llms.cache import
  mark_cache_breakpoint` inside the calling function), so patching the
  module attribute is picked up correctly without needing to patch every
  call site.

- **CrewAI's generic `LLM` class has no built-in retry-on-429**, unlike
  ADK's `LiteLlm` (which took `num_retries` directly as a kwarg in Phase
  4). The first full-report attempt with the manifest-informed source
  snippets added hit Groq's per-minute TPM cap repeatedly — CrewAI's own
  internal retry logic printed the error and retried immediately without
  honoring the provider's suggested wait time, burning through the same
  minute's budget four times before giving up. Fix: added a manual
  retry/backoff loop around `crew.kickoff()` in `generate_report()`
  (`time.sleep(25 * (attempt + 1))`, up to 4 attempts) that only catches
  rate-limit errors and re-raises anything else.

- **Switching to `qwen/qwen3.6-27b` to dodge `gpt-oss-120b`'s exhausted
  minute-budget ran into a different, tighter cap: 1000 output-tokens-per-
  minute (OTPM), separate from the total-token cap.** `qwen` is a heavy
  reasoning model whose hidden reasoning tokens count against output
  budget, so even a single task blew past 1000 OTPM on its own. This
  attempt was abandoned (killed) rather than fixed — noted as a dead end,
  not a solved problem: `qwen` is not a viable reporter model on this
  account's free tier regardless of retry logic, because a single
  response can exceed the per-minute ceiling outright ("Request too large
  ... expected output tokens exceed the enforced limit"). Reverted to
  `gpt-oss-120b`, which succeeded once the backoff fix above was in place.

- **The first successful report cited an invented `transfer_funds`
  signature — `transfer_funds(amount, destination_account)` — when the
  real signature is `transfer_funds(to, amount)`.** This is exactly the
  design doc's stated risk for this task ("you never write 'improve input
  validation'... you write the real function/file"), and it happened
  because the fix task was never actually given real source, only the
  manifest's tool-name list and the findings JSON — a gap between what the
  design specified ("feed the engineer the matching source snippet from
  Chroma") and what the first implementation did. Fix: added
  `_source_snippets()`, which reads the actual file for each
  manifest-declared tool (using `ToolInfo.file`, already populated by
  Phase 3's AST scan) and feeds real source into the fix task's prompt,
  plus a `generate_report(..., manifest_path=...)` parameter to wire a
  manifest in. Re-ran after the fix — the same finding's remediation now
  cites the exact real signature and file path, including the sample's
  actual `@watch` decorator convention, and explicitly avoids inventing
  a plausible-but-wrong signature.

- **Rate-limit pressure was compounded by the fix task now including a
  file's full source alongside the full findings JSON**, pushing single
  requests close to the account's 8000 TPM ceiling on `gpt-oss-120b` when
  combined with the model's own reasoning-token overhead. Mitigated by
  capping `_source_snippets()` at 1200 characters per file (`max_chars`
  parameter) — enough for a small sample app, not a general solution for
  a large real-world target's tool implementation. Flagged as a known
  scaling limit rather than solved: a genuinely large target file would
  need real chunking/retrieval (the Chroma index Phase 3 already builds)
  rather than a flat character truncation, which is future work beyond
  what Phase 5's own validation gate required.
