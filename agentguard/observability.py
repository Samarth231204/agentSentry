"""LangFuse tracing (optional): mirrors AgentGuard's event stream into one LangFuse trace per run.

On when LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are set in AgentGuard/.env (LANGFUSE_HOST defaults
to https://cloud.langfuse.com). trace.jsonl stays the local record either way.

Trace layout:  run  ->  one span per step (scan, search, attack, review, report)
                          -> one span per agent ("agent: Search agent", "agent: Attack agent: tool_misuse",
                             "agent: Security Lead", ...), whose output is that agent's calls, tokens and cost
                             -> one generation per model call ("Security Lead · call 3"), tokens and cost
                        -> spans for tool calls, probes and A2A calls; events for guardrail hits and errors
                        -> output: the cost per agent, most expensive first, and the total
                        -> scores: confirmed, suspected, probes, cost_usd (and per group: cost_usd_search_agent,
                           cost_usd_attack_agents, cost_usd_review_crew, cost_usd_app_under_attack), seconds,
                           qa_approved, and on a test project detection_rate and false_alarms (agentguard/evals.py)

Spans that libraries create on their own (FastAPI requests such as the health check, A2A internals) are
not sent, so the trace list holds only AgentGuard runs.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from agentguard.schemas import TraceEvent

# OpenTelemetry scopes of libraries that trace themselves; LangFuse would otherwise get one trace per
# dashboard request and health check.
NOISY_SCOPES = ["fastapi", "a2a-python-sdk", "opentelemetry.instrumentation.fastapi",
                "opentelemetry.instrumentation.httpx", "opentelemetry.instrumentation.requests", "httpx"]

# event source -> (framework, cost group)
SOURCES = {"search_agent": ("CrewAI", "search_agent"), "review_agent": ("CrewAI", "review_crew"),
           "attack_agent": ("ADK", "attack_agents"), "target": ("sandbox", "app_under_attack")}


def agent_label(source: str, payload: dict) -> str:
    """The name each agent has in LangFuse: one span per agent, its calls numbered inside it."""
    cat = payload.get("category")
    if source == "attack_agent":
        return f"Attack agent: {cat}"
    if source == "target":
        return f"App under attack: {cat}"
    return payload.get("agent") or ("Search agent" if source == "search_agent" else source)


def enabled() -> bool:
    return bool(os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY"))


class LangfuseSink:
    """EventBus subscriber. Every failure is swallowed: tracing must never break a run."""

    def __init__(self, run_id: str, project: str):
        from langfuse import Langfuse

        self.client = Langfuse(blocked_instrumentation_scopes=NOISY_SCOPES)
        self.root = self.client.start_span(name="agentguard-run", input={"project": project},
                                           metadata={"run_id": run_id})
        self.root.update_trace(name=f"AgentGuard {run_id}", session_id=run_id, tags=["agentguard"])
        self.steps: dict[str, Any] = {}
        self.current: Optional[Any] = None
        self.pending_tool: dict[str, Any] = {}
        self.agent_spans: dict[str, Any] = {}     # label -> open span in the current step
        self.costs: dict[str, dict] = {}          # label -> calls, tokens, usd (whole run)

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
            self._end_agent_spans()
            if self.current is not None:
                self.current.end()
            self.current = self.root.start_span(name=f"step:{p.get('step')}", input={"detail": p.get("detail")})
            self.steps[p.get("step")] = self.current
        elif t == "step_done" and self.current is not None:
            self.current.update(output=p)
        elif t == "llm_call":
            self._llm_call(e.source, p)
        elif t == "a2a_call":
            key = f"a2a:{p.get('url')}:{p.get('skill')}"
            self.pending_tool[key] = self._parent().start_span(name=f"a2a:{p.get('skill')}", input=p)
        elif t == "a2a_result":
            span = self.pending_tool.pop(f"a2a:{p.get('url')}:{p.get('skill')}", None)
            if span is not None:
                span.update(output=p)
                span.end()
        elif t == "eval_scores":
            for name, value in (p.get("scores") or {}).items():
                if value is not None:
                    self.root.score_trace(name=name, value=float(value))
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
                   "category_done", "thought", "retest_requested", "retest_done", "qa_result", "trap_hit",
                   "page_planted", "eval_dataset"):
            self._parent().create_event(name=f"{e.source}:{t}", metadata=p)
        elif t in ("run_done",):
            self.close(p)

    def _llm_call(self, source: str, p: dict) -> None:
        from agentguard.costs import price_of
        framework, group = SOURCES.get(source, ("", source))
        label, model = agent_label(source, p), p.get("model") or ""
        pin, pout = price_of(model)
        tin, tout = p.get("prompt_tokens") or 0, p.get("completion_tokens") or 0
        usd_in, usd_out = tin / 1e6 * pin, tout / 1e6 * pout
        c = self.costs.setdefault(label, {"agent": label, "framework": framework, "group": group, "model": model,
                                          "calls": 0, "input_tokens": 0, "output_tokens": 0, "usd": 0.0})
        c["calls"] += 1
        c["input_tokens"] += tin
        c["output_tokens"] += tout
        c["usd"] += usd_in + usd_out
        span = self.agent_spans.get(label)
        if span is None:
            span = self._parent().start_span(name=f"agent: {label}",
                                             metadata={"agent": label, "framework": framework, "model": model})
            self.agent_spans[label] = span
        gen = span.start_generation(
            name=f"{label} · call {c['calls']}", model=model,
            usage_details={"input": tin, "output": tout}, cost_details={"input": usd_in, "output": usd_out},
            metadata={"agent": label, "framework": framework, "call": c["calls"],
                      "cost_usd": round(usd_in + usd_out, 6)})
        gen.end()

    def _end_agent_spans(self) -> None:
        for label, span in self.agent_spans.items():
            c = self.costs.get(label, {})
            span.update(output={"agent": label, "calls": c.get("calls"), "input_tokens": c.get("input_tokens"),
                                "output_tokens": c.get("output_tokens"), "cost_usd": round(c.get("usd", 0), 6)})
            span.end()
        self.agent_spans = {}

    def cost_table(self) -> dict:
        rows = sorted(self.costs.values(), key=lambda r: -r["usd"])
        table = [{"agent": r["agent"], "framework": r["framework"], "model": r["model"], "calls": r["calls"],
                  "input_tokens": r["input_tokens"], "output_tokens": r["output_tokens"],
                  "cost_usd": round(r["usd"], 6)} for r in rows]
        groups: dict[str, float] = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0.0) + r["usd"]
        return {"cost_per_agent": table, "cost_per_group": {k: round(v, 6) for k, v in groups.items()},
                "total_cost_usd": round(sum(r["usd"] for r in rows), 6)}

    def close(self, output: Any = None) -> None:
        try:
            self._end_agent_spans()
            if self.current is not None:
                self.current.end()
                self.current = None
            costs = self.cost_table()
            for group, usd in costs["cost_per_group"].items():
                self.root.score_trace(name=f"cost_usd_{group}", value=usd)
            output = {**costs, "run": output}
            self.root.update(output=output)
            self.root.update_trace(output=output)
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
