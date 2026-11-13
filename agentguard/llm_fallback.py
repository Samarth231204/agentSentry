"""Model fallback chain for ADK agents.

Context is not lost when a provider throttles, because it lives in the ADK
Session (the conversation so far) and not in the model. The same LlmRequest is
replayed against the next model in the chain. Each switch is a model_fallback
trace event.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from pydantic import Field

from agentguard.config import normalize_model
from agentguard.events import get_event_bus
from agentguard.llm import RETRYABLE_ERRORS
from agentguard.llm_mock import MockRateLimitError, ScriptedAttackerModel, mock_enabled
from agentguard.logging import get_logger
from agentguard.schemas import TraceEvent

logger = get_logger("llm.fallback")
RETRYABLE = (*RETRYABLE_ERRORS, MockRateLimitError)


def _model_for(name: str, retries: int) -> BaseLlm:
    if mock_enabled():
        return ScriptedAttackerModel(model=name)
    from google.adk.models.lite_llm import LiteLlm
    return LiteLlm(model=normalize_model(name), num_retries=retries)


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
        last: Exception | None = None
        for index, name in enumerate(names):
            if self.probes:  # replay: exactly the recorded probes, no provider call
                model = ScriptedAttackerModel(model=name, probes=list(self.probes))
            else:
                model = _model_for(name, self.retries)
            try:
                async for response in model.generate_content_async(llm_request, stream=stream):
                    yield response
                if index > 0:
                    self._emit(names[0], name, "fallback after provider error")
                return
            except RETRYABLE as exc:
                last = exc
                if index + 1 < len(names):
                    self._emit(name, names[index + 1], type(exc).__name__)
                    continue
                raise
        if last is not None:
            raise last

    def _emit(self, from_model: str, to_model: str, reason: str) -> None:
        get_event_bus().emit(TraceEvent(source="llm", event_type="model_fallback", payload={
            "role": self.role, "from": from_model, "to": to_model, "reason": reason}))
