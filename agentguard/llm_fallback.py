"""Model fallback chain for ADK agents.

Context is not lost when a provider throttles, because it lives in the ADK
Session (the conversation so far) and not in the model. The same LlmRequest is
replayed against the next model in the chain. Each switch is a model_fallback
trace event.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from pydantic import Field

from agentguard.config import normalize_model, usable_fallbacks
from agentguard.events import get_event_bus
from agentguard.llm import (MAX_HINTED_WAIT, RETRYABLE_ERRORS, is_malformed_tool_call, mark_cooling,
                            output_limit_hint, retry_after_seconds, skip_cooling)
from agentguard.llm_mock import MockRateLimitError, ScriptedAttackerModel, mock_enabled
from agentguard.logging import get_logger
from agentguard.schemas import TraceEvent

logger = get_logger("llm.fallback")
RETRYABLE = (*RETRYABLE_ERRORS, MockRateLimitError)
HINTED_RETRIES = 3  # same-model retries when the provider says how long to wait


def _model_for(name: str, retries: int) -> BaseLlm:
    if mock_enabled():
        return ScriptedAttackerModel(model=name)
    from google.adk.models.lite_llm import LiteLlm
    return LiteLlm(model=normalize_model(name), num_retries=retries)


def _with_model(llm_request: Any, model: str) -> Any:
    if getattr(llm_request, "model", None) in (None, model):
        return llm_request
    try:
        return llm_request.model_copy(update={"model": model})
    except AttributeError:  # not a pydantic request (tests): leave it unchanged
        return llm_request


def _with_max_output(llm_request: Any, max_tokens: int) -> Any:
    try:
        from google.genai import types as genai_types
        config = llm_request.config or genai_types.GenerateContentConfig()
        return llm_request.model_copy(update={"config": config.model_copy(update={"max_output_tokens": max_tokens})})
    except AttributeError:
        return llm_request


class FallbackLlm(BaseLlm):
    """BaseLlm that tries each model in `chain` in order on retryable provider errors."""

    chain: list[str] = Field(default_factory=list)
    retries: int = 2
    probes: list[str] = Field(default_factory=list)  # replay: scripted probes (mock/replay only)
    role: str = "attacker"

    async def generate_content_async(
        self, llm_request: Any, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        names = self.chain or [self.model]
        if not self.probes and not mock_enabled():
            names = skip_cooling([names[0]] + usable_fallbacks(names[0], names[1:]))
        last: Exception | None = None
        for index, name in enumerate(names):
            if self.probes:  # replay: exactly the recorded probes, no provider call
                model = ScriptedAttackerModel(model=name, probes=list(self.probes))
            else:
                model = _model_for(name, self.retries)
            # ADK's LiteLlm calls `llm_request.model or self.model`, and the request carries the
            # primary model's name. Without a per-candidate copy every "fallback" re-sends the request
            # to the same throttled model.
            request = _with_model(llm_request, normalize_model(name))
            for wait_round in range(HINTED_RETRIES + 1):
                try:
                    async for response in model.generate_content_async(request, stream=stream):
                        yield response
                    if index > 0:
                        self._emit(names[0], name, "fallback after provider error")
                    return
                except RETRYABLE as exc:
                    last = exc
                    fits = output_limit_hint(exc)
                    if fits is not None and wait_round < HINTED_RETRIES:
                        # Too large for this provider's output limit: ask for fewer tokens, right away.
                        request = _with_max_output(request, fits)
                        continue
                    mark_cooling(name, exc)
                    # A short wait the provider asked for is cheaper than switching models.
                    hint = retry_after_seconds(exc)
                    if hint is not None and hint <= MAX_HINTED_WAIT and wait_round < HINTED_RETRIES:
                        await asyncio.sleep(hint + 0.5)
                        continue
                    break
                except Exception as exc:  # noqa: BLE001
                    if is_malformed_tool_call(exc) and wait_round < HINTED_RETRIES:
                        last = exc
                        continue  # a broken tool call from the model: ask again
                    raise
            if index + 1 < len(names):
                self._emit(name, names[index + 1], type(last).__name__ if last else "error")
                continue
            if last is not None:
                raise last
        if last is not None:
            raise last

    def _emit(self, from_model: str, to_model: str, reason: str) -> None:
        get_event_bus().emit(TraceEvent(source="llm", event_type="model_fallback", payload={
            "role": self.role, "from": from_model, "to": to_model, "reason": reason}))
