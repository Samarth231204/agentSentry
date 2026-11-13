"""The discovery agent: an ADK LlmAgent that resolves ambiguous candidates.

It sees only the candidates discovery produced (id, role, location, signals and a
short snippet) and answers with include/exclude and sandbox per id. Any id it
invents, and any malformed answer, is dropped. If it fails, the deterministic
plan stands. It is never asked to write code or to name a location.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Optional

from pydantic import BaseModel, Field
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from agentguard.config import normalize_model
from agentguard.discovery.candidates import Candidate
from agentguard.llm_mock import ScriptedDiscoveryModel, mock_enabled
from agentguard.logging import get_logger

logger = get_logger("discovery.agent")

INSTRUCTION = (
    "You are reviewing code locations that a security tool may instrument in an AI agent project. "
    "For each candidate_id you receive, decide whether it is part of the agent's behaviour that should be "
    "observed during a red-team test (a tool the agent can call, a retrieval step, a memory access, an outbound "
    "request, or an LLM call). Set include to false for helpers, logging, tests or anything unrelated. "
    "Set sandbox to true for any tool that changes state outside the process. "
    "Reply with JSON only, in exactly this shape: "
    '{"decisions": [{"candidate_id": "c-...", "include": true, "sandbox": false, "reason": "short reason"}]}. '
    "Use only candidate_ids you were given."
)

_ID_RE = re.compile(r"^c-[0-9a-f]{8}$")
MAX_AGENT_CANDIDATES = 40  # the agent reviews the most confident ambiguous candidates; the rest stay unreviewed


class AgentDecision(BaseModel):
    candidate_id: str
    include: bool
    sandbox: Optional[bool] = None
    reason: str = Field(default="", max_length=300)


class AgentDecisions(BaseModel):
    decisions: list[AgentDecision] = Field(default_factory=list)


def _prompt(candidates: list[Candidate]) -> str:
    payload = [
        {
            "candidate_id": c.id,
            "role": c.role,
            "file": c.file,
            "function": c.qualname,
            "line": c.line,
            "confidence": c.confidence,
            "signals": c.signals,
            "snippet": c.snippet,
        }
        for c in candidates
    ]
    return "Candidates:\n" + json.dumps(payload, indent=2)


def parse_decisions(text: str, known_ids: set[str]) -> dict[str, AgentDecision]:
    """Accepts only JSON that matches the schema and names known ids. Anything else is ignored."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return {}
    try:
        parsed = AgentDecisions.model_validate(json.loads(text[start:end + 1]))
    except (ValueError, json.JSONDecodeError):
        return {}
    out: dict[str, AgentDecision] = {}
    for decision in parsed.decisions:
        if decision.candidate_id in known_ids and _ID_RE.match(decision.candidate_id):
            out[decision.candidate_id] = decision
    return out


def _budget_callback(budget):
    """Charges each discovery model call to the run budget. A raised BudgetExceededError ends the agent call."""
    def after_model(callback_context, llm_response):
        if budget is None:
            return None
        usage = getattr(llm_response, "usage_metadata", None)
        budget.record(
            role="discovery",
            prompt_tokens=int(getattr(usage, "prompt_token_count", 0) or 0),
            completion_tokens=int(getattr(usage, "candidates_token_count", 0) or 0),
        )
        return None
    return after_model


async def _run_agent(candidates: list[Candidate], model_name: str, budget=None) -> str:
    import os
    model = ScriptedDiscoveryModel(model="mock") if mock_enabled() else None
    if model is None:
        from google.adk.models.lite_llm import LiteLlm
        model = LiteLlm(model=normalize_model(model_name))
    tools: list = []
    url = os.environ.get("AGENTGUARD_CODEINTEL_URL")
    if url and not mock_enabled():
        from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StreamableHTTPConnectionParams
        tools.append(McpToolset(
            connection_params=StreamableHTTPConnectionParams(url=url),
            tool_filter=["read_span", "callers", "callees", "get_symbol"],
        ))
    agent = LlmAgent(name="discovery", model=model, instruction=INSTRUCTION, tools=tools,
                     after_model_callback=_budget_callback(budget))
    sessions = InMemorySessionService()
    session = await sessions.create_session(app_name="agentguard", user_id="ag")
    runner = Runner(agent=agent, app_name="agentguard", session_service=sessions)
    message = genai_types.Content(role="user", parts=[genai_types.Part(text=_prompt(candidates))])
    final = ""
    async for event in runner.run_async(user_id="ag", session_id=session.id, new_message=message):
        if event.is_final_response() and event.content and event.content.parts:
            final = "".join(p.text or "" for p in event.content.parts)
    return final


def resolve_ambiguous(candidates: list[Candidate], model_name: str,
                      budget=None) -> dict[str, tuple[bool, Optional[bool], str]]:
    """Returns {candidate_id: (include, sandbox, reason)}. Empty dict on any failure."""
    if not candidates:
        return {}
    ranked = sorted(candidates, key=lambda c: (-c.confidence, c.file, c.line))[:MAX_AGENT_CANDIDATES]
    try:
        text = asyncio.run(_run_agent(ranked, model_name, budget))
    except Exception as exc:  # noqa: BLE001 - the deterministic plan still stands
        logger.warning("Discovery agent failed, using deterministic plan only: %s", exc)
        return {}
    decisions = parse_decisions(text, {c.id for c in candidates})
    if not decisions:
        logger.warning("Discovery agent returned no usable decisions")
    return {cid: (d.include, d.sandbox, d.reason or "agent decision") for cid, d in decisions.items()}
