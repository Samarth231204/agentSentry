"""LangFuse tracing (optional): mirrors AgentGuard's event stream into one LangFuse trace per run.

On when LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are set in AgentGuard/.env (LANGFUSE_HOST defaults
to https://cloud.langfuse.com). trace.jsonl stays the local record either way.

Trace layout:  run  ->  one span per step (scan, search, attack)
                        -> generations for model calls (with token usage)
                        -> spans for tool calls and probes, events for guardrail hits and errors
"""

from __future__ import annotations

import os
from typing import Any, Optional

from agentguard.schemas import TraceEvent


def enabled() -> bool:
    return bool(os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY"))


class LangfuseSink:
    """EventBus subscriber. Every failure is swallowed: tracing must never break a run."""

    def __init__(self, run_id: str, project: str):
        from langfuse import Langfuse

        self.client = Langfuse()
        self.root = self.client.start_span(name="agentguard-run", input={"project": project},
                                           metadata={"run_id": run_id})
        self.root.update_trace(name=f"AgentGuard {run_id}", session_id=run_id, tags=["agentguard"])
        self.steps: dict[str, Any] = {}
        self.current: Optional[Any] = None
        self.pending_tool: dict[str, Any] = {}

    def _parent(self):
        return self.current or self.root

    def __call__(self, event: TraceEvent) -> None:
        try:
            self._handle(event)
        except Exception:  # noqa: BLE001
            pass

    def _handle(self, e: TraceEvent) -> None:
        p, t = e.payload, e.event_type
        if t == "step_started":
            if self.current is not None:
                self.current.end()
            self.current = self.root.start_span(name=f"step:{p.get('step')}", input={"detail": p.get("detail")})
            self.steps[p.get("step")] = self.current
        elif t == "step_done" and self.current is not None:
            self.current.update(output=p)
        elif t == "llm_call":
            gen = self._parent().start_generation(
                name=f"{e.source}:{p.get('category', 'search')}", model=p.get("model"),
                usage_details={"input": p.get("prompt_tokens") or 0, "output": p.get("completion_tokens") or 0})
            gen.end()
        elif t == "action":
            key = f"{e.source}:{p.get('category', '')}:{p.get('tool')}"
            self.pending_tool[key] = self._parent().start_span(name=f"tool:{p.get('tool')}", input=p.get("input"),
                                                               metadata={"agent": e.source, "category": p.get("category")})
        elif t == "observation":
            key = f"{e.source}:{p.get('category', '')}:{p.get('tool')}"
            span = self.pending_tool.pop(key, None)
            if span is not None:
                span.update(output=(p.get("text") or p.get("error") or "")[:4000])
                span.end()
        elif t == "probe":
            span = self._parent().start_span(name=f"probe:{p.get('category')}", input=p.get("message"),
                                             metadata={"entry_point": p.get("entry_point"), "session": p.get("session")})
            span.update(output={"reply": p.get("reply"), "tool_calls": p.get("tool_calls"),
                                "confirmed": p.get("confirmed"), "detail": p.get("detail")})
            span.end()
        elif t in ("blocked", "injection_in_observation", "bad_tool_output", "search_result_check", "error",
                   "category_done", "thought"):
            self._parent().create_event(name=f"{e.source}:{t}", metadata=p)
        elif t in ("run_done",):
            self.close(p)

    def close(self, output: Any = None) -> None:
        try:
            if self.current is not None:
                self.current.end()
                self.current = None
            self.root.update(output=output)
            self.root.end()
            self.client.flush()
        except Exception:  # noqa: BLE001
            pass


def make_sink(run_id: str, project: str) -> Optional[LangfuseSink]:
    if not enabled():
        return None
    try:
        return LangfuseSink(run_id, project)
    except Exception as exc:  # noqa: BLE001  (package missing, bad keys)
        from agentguard.events import emit
        emit("observability", "langfuse_unavailable", error=f"{type(exc).__name__}: {exc}"[:300])
        return None
