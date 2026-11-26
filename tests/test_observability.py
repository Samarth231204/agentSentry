"""LangFuse layout: one span per agent with numbered, costed calls; cost per agent in the trace output."""

from agentguard import observability
from agentguard.schemas import TraceEvent


class FakeObs:
    def __init__(self, log, name, parent=None, **kw):
        self.log, self.name, self.parent, self.kw, self.updates = log, name, parent, kw, []
        log.append(self)

    def start_span(self, name, **kw):
        return FakeObs(self.log, name, self, kind="span", **kw)

    def start_generation(self, name, **kw):
        return FakeObs(self.log, name, self, kind="generation", **kw)

    def create_event(self, name, **kw):
        return FakeObs(self.log, name, self, kind="event", **kw)

    def update(self, **kw):
        self.updates.append(kw)

    def update_trace(self, **kw):
        self.updates.append({"trace": kw})

    def score_trace(self, name, value):
        self.log.append(("score", name, value))

    def end(self):
        pass


class FakeClient:
    def __init__(self, **kw):
        self.kw, self.log = kw, []

    def start_span(self, name, **kw):
        return FakeObs(self.log, name, None, kind="span", **kw)

    def flush(self):
        pass


def _ev(source, event_type, **payload):
    return TraceEvent(source=source, event_type=event_type, payload=payload)


def test_per_agent_spans_numbered_calls_and_cost_table(monkeypatch):
    import langfuse
    made = {}
    monkeypatch.setattr(langfuse, "Langfuse", lambda **kw: made.setdefault("c", FakeClient(**kw)))
    sink = observability.LangfuseSink("run-1", "/p")
    client = made["c"]
    assert "fastapi" in client.kw["blocked_instrumentation_scopes"]   # no health-check traces

    sonnet, haiku = "anthropic/claude-sonnet-5-5", "anthropic/claude-haiku-5-5"
    for e in [_ev("flow", "step_started", step="search"),
              _ev("search_agent", "llm_call", agent="Search agent", model=sonnet, prompt_tokens=1_000_000, completion_tokens=0),
              _ev("search_agent", "llm_call", agent="Search agent", model=sonnet, prompt_tokens=0, completion_tokens=100_000),
              _ev("flow", "step_started", step="attack"),
              _ev("attack_agent", "llm_call", category="tool_misuse", model=haiku, prompt_tokens=1_000_000, completion_tokens=0),
              _ev("target", "llm_call", category="tool_misuse", model="groq/openai/gpt-oss-120b", prompt_tokens=10, completion_tokens=10),
              _ev("flow", "step_started", step="review"),
              _ev("review_agent", "llm_call", agent="Security Lead", model=sonnet, prompt_tokens=500_000, completion_tokens=0),
              _ev("flow", "run_done", run_id="run-1")]:
        sink(e)

    spans = {o.name: o for o in client.log if isinstance(o, FakeObs) and o.name.startswith("agent: ")}
    assert set(spans) == {"agent: Search agent", "agent: Attack agent: tool_misuse",
                          "agent: App under attack: tool_misuse", "agent: Security Lead"}
    assert spans["agent: Search agent"].parent.name == "step:search"          # grouped under its step
    gens = [o for o in client.log if isinstance(o, FakeObs) and o.kw.get("kind") == "generation"]
    assert [g.name for g in gens][:2] == ["Search agent · call 1", "Search agent · call 2"]
    assert gens[0].parent is spans["agent: Search agent"]
    assert gens[0].kw["metadata"]["cost_usd"] == 2.0 and gens[1].kw["metadata"]["cost_usd"] == 1.0
    assert spans["agent: Search agent"].updates[-1]["output"]["cost_usd"] == 3.0       # the agent's total on its span

    root = client.log[0]
    out = root.updates[-1]["trace"]["output"]
    assert [r["agent"] for r in out["cost_per_agent"]][:2] == ["Search agent", "Security Lead"]  # most expensive first
    assert out["cost_per_group"]["search_agent"] == 3.0 and out["cost_per_group"]["attack_agents"] == 0.1
    assert out["total_cost_usd"] > 4.1
    scores = {s[1]: s[2] for s in client.log if isinstance(s, tuple)}
    assert scores["cost_usd_search_agent"] == 3.0 and scores["cost_usd_review_crew"] == 1.0
