"""Universal multi-provider chat client using LiteLLM."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from agentguard.budget import BudgetTracker

from agentguard._env import load_env
from agentguard.llm_mock import mock_chat, mock_enabled

load_env()

import litellm
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from agentguard.config import get_config, normalize_model
from agentguard.logging import get_logger

logger = get_logger("llm")

# Suppress noisy LiteLLM startup/debugging logs
litellm.suppress_debug_info = True


RETRYABLE_ERRORS = (
    litellm.RateLimitError,
    litellm.ServiceUnavailableError,
    litellm.InternalServerError,
    litellm.Timeout,
    litellm.APIConnectionError,
)


def _record_llm_call(messages: list[dict], role: str) -> None:
    """Target-side monitoring: when a target calls agentguard.llm.chat inside /invoke, keep the messages."""
    from agentguard.instrument.wrappers import record_observation
    safe = [{"role": str(m.get("role", "")), "content": str(m.get("content", ""))[:4000]}
            for m in messages if isinstance(m, dict)]
    record_observation("llm", "chat", {"messages": safe, "role": role})


def _emit_fallback(role: str, from_model: str, to_model: str, reason: str) -> None:
    from agentguard.events import get_event_bus
    from agentguard.schemas import TraceEvent
    get_event_bus().emit(TraceEvent(source="llm", event_type="model_fallback", payload={
        "role": role, "from": from_model, "to": to_model, "reason": reason}))


def _is_retryable_error(exc: BaseException) -> bool:
    """Check if exception is a transient HTTP/network or rate limit error."""
    err_str = str(exc).lower()
    # Never retry on permanent daily quota exhaustion
    if any(q in err_str for q in ("quota exceeded", "resource_exhausted", "daily limit")):
        return False
    if any(k in err_str for k in ("rate_limit", "ratelimit", "429", "timeout", "timed out", "connection error", "503", "502")):
        return True
    return False


@retry(
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1.5, min=2, max=30),
    retry=retry_if_exception(_is_retryable_error),
    reraise=True,
)
def _completion_with_retry(model: str, messages: list[dict], **kwargs: Any) -> Any:
    logger.debug("Executing LiteLLM completion (model: %s)", model)
    return litellm.completion(model=model, messages=messages, **kwargs)


def chat(
    messages: list[dict],
    tools: Optional[list[dict]] = None,
    model: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 1024,
    api_key: Optional[str] = None,
    api_base: Optional[str] = None,
    timeout: float = 45.0,
    budget: Optional["BudgetTracker"] = None,
    role: str = "unspecified",
) -> dict[str, Any]:
    _record_llm_call(messages, role)
    if mock_enabled():
        if budget is not None:
            budget.record(role=role, prompt_tokens=0, completion_tokens=0)
        return mock_chat(messages, tools=tools)

    raw_model = model or get_config().chat_model
    target_model = normalize_model(raw_model)
    config = get_config()

    call_kwargs: dict[str, Any] = {
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": timeout,
    }
    if tools:
        call_kwargs["tools"] = tools
        call_kwargs["tool_choice"] = "auto"
    if api_key:
        call_kwargs["api_key"] = api_key
    if api_base or config.api_base:
        call_kwargs["api_base"] = api_base or config.api_base

    chain = [target_model]
    if model is None:  # only the default model falls back; an explicit model is respected
        chain += [normalize_model(m) for m in config.fallback_chain if normalize_model(m) != target_model]
    resp = None
    for index, candidate in enumerate(chain):
        try:
            resp = _completion_with_retry(model=candidate, messages=messages, **call_kwargs)
            target_model = candidate
            if index > 0:
                _emit_fallback(role, chain[0], candidate, "fallback after provider error")
            break
        except RETRYABLE_ERRORS as exc:
            if index == len(chain) - 1:
                raise
            _emit_fallback(role, candidate, chain[index + 1], f"{type(exc).__name__}")
            continue

    try:

        choice = resp.choices[0]
        msg = choice.message

        # Format tool calls into standard dictionary representation
        raw_tools = getattr(msg, "tool_calls", None)
        formatted_tool_calls = []
        if raw_tools:
            for tc in raw_tools:
                if isinstance(tc, dict):
                    formatted_tool_calls.append(tc)
                elif hasattr(tc, "function"):
                    fn_obj = tc.function
                    fn_dict = {
                        "name": getattr(fn_obj, "name", None) if not isinstance(fn_obj, dict) else fn_obj.get("name"),
                        "arguments": getattr(fn_obj, "arguments", None) if not isinstance(fn_obj, dict) else fn_obj.get("arguments"),
                    }
                    formatted_tool_calls.append({
                        "id": getattr(tc, "id", None),
                        "type": getattr(tc, "type", "function"),
                        "function": fn_dict,
                    })
                elif hasattr(tc, "model_dump") and callable(tc.model_dump):
                    formatted_tool_calls.append(tc.model_dump())

        content = getattr(msg, "content", "") or ""

        if budget is not None:
            usage_obj = getattr(resp, "usage", None)
            if isinstance(usage_obj, dict):
                prompt_tokens = usage_obj.get("prompt_tokens", 0)
                completion_tokens = usage_obj.get("completion_tokens", 0)
            else:
                prompt_tokens = getattr(usage_obj, "prompt_tokens", 0) if usage_obj else 0
                completion_tokens = getattr(usage_obj, "completion_tokens", 0) if usage_obj else 0
            budget.record(role=role, prompt_tokens=prompt_tokens or 0, completion_tokens=completion_tokens or 0)

        return {
            "choices": [
                {
                    "message": {
                        "role": getattr(msg, "role", "assistant"),
                        "content": content,
                        "tool_calls": formatted_tool_calls,
                    }
                }
            ],
            "model": getattr(resp, "model", target_model),
            "usage": getattr(resp, "usage", {}),
        }
    except Exception as exc:
        logger.error("Multi-provider chat completion failed for model '%s': %s", target_model, exc)
        raise
