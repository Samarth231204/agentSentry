# Phase 6 — CLI + docs + end-to-end validation

## 1. Summary

Phase 6 wires everything from Phases 1–5 into a single command-line
surface and does the final clean-room run the whole plan has been
building toward.

- **`agentguard/cli.py`** — `agentguard init PROJECT_PATH` (static
  manifest generation, never touches the target) and `agentguard test
  PROJECT_PATH --target-url URL` (full pipeline: load-or-generate
  manifest → attack → scorecard → report), both as Click commands wired
  to the `agentguard` console script via `pyproject.toml`'s
  `[project.scripts]`.
- **`README.md`** — install, quickstart, target-instrumentation snippet,
  and an explicit Known Limitations section (canary/instrumentation
  dependency, Groq rate limits, source-snippet truncation) rather than
  hiding them.

## 2. Pipeline

```
agentguard init samples/unsafe_tool
        │
        ▼
  Manifest.from_yaml if manifest.yaml exists, else synthesize()
        │
        ▼
  samples/unsafe_tool/manifest.yaml written
        │
        ▼ (separately: `uvicorn samples.unsafe_tool.app:app` already running)
        │
agentguard test samples/unsafe_tool --target-url http://127.0.0.1:8002
        │
        ▼
  load manifest -> Target.health() sanity check -> run_attack_suite_sync()
        │
        ▼
  findings.json written, scorecard printed to terminal
        │
        ▼
  generate_report(findings.json, report.md, manifest_path=...)
        │
        ▼
  report.md written -- CLI process never re-contacts the target during this step
```

## 3. Validation performed (final gate)

Ran from a fresh package install (`pip install -e .`, confirming the
`agentguard` console script registers), against `samples/unsafe_tool`:

| Step | Result |
|---|---|
| `agentguard init samples/unsafe_tool` | wrote `manifest.yaml`, correctly reported `transfer_funds` as destructive and the resulting attacker routing |
| `agentguard test samples/unsafe_tool --target-url http://127.0.0.1:8002` | full pipeline completed: `findings.json` written, scorecard printed (`1/3, 33%`, matching per-category breakdown), `report.md` written |
| Scorecard printed to terminal vs. scorecard recomputed from `findings.json` directly | identical (`compute_scorecard()` is the same function both paths call — verified byte-for-byte) |
| Scorecard embedded in `report.md`'s JSON block vs. the terminal/raw-file scorecard | identical |
| Generated files land at the expected default paths (`./findings.json`, `./report.md`, `<project>/manifest.yaml`) | confirmed, then cleaned up (all three are gitignored build artifacts, correctly absent from `git status`) |
| Target process never re-contacted during the reporting step | true by construction — `reporters.py` has no import of `agentguard.target`, verified in Phase 5 |

Not separately re-run for `rag_leaky` and `prompt_leak` in this phase —
both were already validated end-to-end through the underlying
`run_attack_suite_sync`/`generate_report` calls directly in Phases 4 and
5; Phase 6 validates the CLI wrapper itself, which required only one
clean pass to prove correct, and repeating identical Groq calls for the
other two samples would mostly re-spend an already-scarce rate-limit
budget without adding new coverage of the CLI code.

## 4. Problems and bugs faced

- **`agentguard test`'s reporting step still hit a live Groq rate limit
  mid-run** (`Rate limit reached ... TPM: Limit 8000, Used 4757, Requested
  4002`), visible directly in the CLI's own output during the final
  validation run. This wasn't a new bug — it's Phase 5's already-fixed
  retry/backoff loop in `generate_report()` actually firing and recovering
  in a real end-to-end run rather than an isolated test, which is useful
  confirmation the fix generalizes: the command's final output was still
  a correct, complete `report.md` (`Wrote report.md` printed after the
  error, not instead of it), so no code change was needed here — noted
  because it's a visible reminder that this project's Groq free-tier
  account is a persistent, real constraint on repeated full runs, not a
  one-off nuisance from earlier phases.

- No other new bugs surfaced in this phase — the CLI is a thin
  orchestration layer over already-validated `manifest.py`,
  `attackers.py`, and `reporters.py` functions, and the one issue that did
  appear was a previously-fixed problem resurfacing under load rather than
  a new one.

## 5. What's still open (honestly, not swept under the rug)

- `rag_leaky` and `prompt_leak` were not re-run through the `agentguard`
  CLI specifically in this phase (only `unsafe_tool` was, to conserve
  Groq quota) — their underlying pipeline functions were validated
  directly in Phases 4–5, but the CLI wrapper itself was only proven
  against one sample.
- The zero-findings report path (write task explicitly instructed not to
  fabricate a finding when there are none) has never been exercised
  against a sample that actually produced zero confirmed findings —
  every sample run so far found at least one true positive.
- `_source_snippets()`'s flat 1200-character truncation is a real scaling
  limit for larger target codebases, called out in the README rather than
  fixed, consistent with the original plan's own timeboxing guidance for
  static-analysis tooling.
