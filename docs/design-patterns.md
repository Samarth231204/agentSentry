# Agentic design patterns (rubric requirement 4)

Each pattern below names where it lives in the code, so it can be checked.

1. **Planner and executor (playbooks).** `attackers.PLAYBOOKS` gives each category a plan; the ADK attacker executes it turn
   by turn. Seeds come from `agentguard/probes/*.yaml`.
2. **Tool-use loop.** The attacker is an ADK `LlmAgent` with four tools (`send_probe`, `record_finding`, `give_up`,
   `finish_attempt`) plus `load_memory`. The model chooses the next tool call after each result.
3. **Reflection and verification.** A separate judge (`judge.py`) reviews the transcript. It can only return SUSPECTED or FAILED.
4. **Oracle-gated success.** Only deterministic oracles confirm (`attackers.py`, `oracles.py`): canary, side effect,
   manifest diff, PII, system-prompt fingerprint, retrieval injection. Each oracle is gated to the categories where it applies.
   The model's own claims never confirm.
5. **Shared state.** Each category runs in a fresh ADK session seeded with `target_profile` and prior findings. One
   `InMemoryMemoryService` is shared across categories, so earlier results are recallable with `load_memory`.
6. **Sequential crew with a typed output.** CrewAI analyst, engineer and writer run in order and produce a Pydantic
   `Report` (`reporters.py`, `schemas.py`).
7. **Fallback chain.** `llm_fallback.FallbackLlm` and `llm.chat` try the next model on a retryable error, carrying the
   session context with them (`model_fallback` events).
8. **Human in the loop.** The plan is reviewed before anything is instrumented or attacked (`server/runner.py`, the plan tab).
9. **Sandbox guard.** Sandboxed tools are recorded but not executed (`instrument/wrappers.py`).
10. **Agents as services.** Discovery, attacker and reporter are exposed as A2A agents with cards and JSON-RPC (`a2a/`).
11. **Budgeted execution.** Every model call, including discovery, is charged to a `BudgetTracker`; runs stop cleanly
    when a limit is reached.
12. **Monitoring callbacks.** ADK `before_model`, `after_model`, `before_tool` and `after_tool` callbacks write trace events,
    and the event bus carries every component's events to `trace.jsonl`.

Not yet implemented: a memory-write oracle (memory operations are recorded but nothing confirms from them).
