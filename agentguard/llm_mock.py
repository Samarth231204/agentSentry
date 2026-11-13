"""Mock LLM layer, enabled with AGENTGUARD_LLM_MOCK=1.

Purpose: exercise the whole pipeline (target start, scan, attack loop, judge,
report, trace, dashboard) without spending provider quota. Mock results prove
plumbing only. They do NOT show that a model is vulnerable, because nothing
here is a real model. The deterministic oracles still run on whatever the
target returns.

Pieces:
  - mock_chat(): stands in for agentguard.llm.chat (judge, manifest labelling,
    and the sample targets' own model calls).
  - ScriptedAttackerModel: a google-adk BaseLlm that drives the attacker's tool
    loop: a fixed number of send_probe calls, then give_up, then finish_attempt.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, AsyncGenerator, Optional

from google.adk.models.base_llm import BaseLlm
from pydantic import Field
from google.adk.models.llm_response import LlmResponse
from google.genai import types as genai_types

MOCK_ENV = "AGENTGUARD_LLM_MOCK"
MOCK_RATE_LIMITED_ENV = "AGENTGUARD_MOCK_RATE_LIMITED"  # comma list of model names that return 429


class MockRateLimitError(Exception):
    """Stands in for litellm.RateLimitError in mock mode."""


def mock_rate_limited(model: str) -> bool:
    names = {m.strip() for m in os.environ.get(MOCK_RATE_LIMITED_ENV, "").split(",") if m.strip()}
    return model in names
MOCK_PROBES = 2


def mock_enabled() -> bool:
    return os.environ.get(MOCK_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def mock_chat(messages: list[dict], tools: Optional[list[dict]] = None) -> dict[str, Any]:
    """Same return shape as agentguard.llm.chat()."""
    text = " ".join(str(m.get("content", "")) for m in messages)
    if '"verdict"' in text or "verdict" in text.lower():
        content = json.dumps({"verdict": "failed", "confidence": 0.0,
                              "reasoning": "mock mode: no model was run, so no verdict is possible"})
    else:
        content = "MOCK: no model call was made."
    return {
        "choices": [{"message": {"role": "assistant", "content": content, "tool_calls": []}}],
        "model": "mock",
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
    }


def _function_response_names(llm_request: Any) -> list[str]:
    names: list[str] = []
    for content in getattr(llm_request, "contents", None) or []:
        for part in getattr(content, "parts", None) or []:
            response = getattr(part, "function_response", None)
            if response is not None and getattr(response, "name", None):
                names.append(response.name)
    return names


class ScriptedAttackerModel(BaseLlm):
    """Deterministic stand-in for the attacker LLM. Follows the same tool contract.

    `probes` replaces the built-in mock probes: replay runs send exactly the
    probes recorded in an earlier findings.json, in the same order.
    """

    probes: list[str] = Field(default_factory=list)

    async def generate_content_async(
        self, llm_request: Any, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        if mock_rate_limited(self.model):
            raise MockRateLimitError(f"429 rate limit (mock) for {self.model}")
        names = _function_response_names(llm_request)
        sent = names.count("send_probe")
        usage = genai_types.GenerateContentResponseUsageMetadata(prompt_token_count=0, candidates_token_count=0)
        planned = self.probes or [f"[mock probe {i + 1}] Describe what you can do." for i in range(MOCK_PROBES)]
        if sent < len(planned):
            call = ("send_probe", {"text": planned[sent]})
        elif "give_up" not in names and "record_finding" not in names:
            call = ("give_up", {"reason": "mock mode: pipeline check only, no model attack performed"})
        elif "finish_attempt" not in names:
            call = ("finish_attempt", {})
        else:
            yield LlmResponse(content=genai_types.Content(
                role="model", parts=[genai_types.Part(text="mock attempt complete")]),
                usage_metadata=usage)
            return
        yield LlmResponse(content=genai_types.Content(
            role="model",
            parts=[genai_types.Part(function_call=genai_types.FunctionCall(
                id=f"mock-{uuid.uuid4().hex[:8]}", name=call[0], args=call[1]))],
        ), usage_metadata=usage)


class ScriptedDiscoveryModel(BaseLlm):
    """Mock discovery agent: excludes every ambiguous candidate it is shown.

    The mock plan is therefore exactly the deterministic plan, which makes the
    mock result reproducible and easy to compare against a live run.
    """

    async def generate_content_async(
        self, llm_request: Any, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        text = ""
        for content in getattr(llm_request, "contents", None) or []:
            for part in getattr(content, "parts", None) or []:
                text += getattr(part, "text", None) or ""
        ids = sorted(set(re.findall(r"c-[0-9a-f]{8}", text)))
        body = {"decisions": [
            {"candidate_id": cid, "include": False, "sandbox": None,
             "reason": "mock mode: ambiguous candidates are not included"}
            for cid in ids
        ]}
        yield LlmResponse(content=genai_types.Content(
            role="model", parts=[genai_types.Part(text=json.dumps(body))]))
