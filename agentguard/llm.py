"""Universal multi-provider chat client using LiteLLM."""

from __future__ import annotations

import os
import re
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

from agentguard.config import get_config, litellm_kwargs, normalize_model, usable_fallbacks
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


_RETRY_IN_RE = re.compile(r"try again in\s+(?:(\d+(?:\.\d+)?)m(?!s))?\s*(?:(\d+(?:\.\d+)?)(ms|s))?", re.IGNORECASE)
MAX_HINTED_WAIT = 60.0


def retry_after_seconds(exc: BaseException) -> Optional[float]:
    """The wait a provider asked for in a rate-limit error ("try again in 1m2.5s", "in 727ms"), if any."""
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    try:
        value = headers.get("retry-after")
        if value is not None:
            return max(0.0, float(value))
    except (TypeError, ValueError, AttributeError):
        pass
    match = _RETRY_IN_RE.search(str(exc))
    if not match or not (match.group(1) or match.group(2)):
        return None
    seconds = float(match.group(1) or 0) * 60
    if match.group(2):
        seconds += float(match.group(2)) / (1000 if match.group(3).lower() == "ms" else 1)
    return seconds


# Models that asked for a wait longer than MAX_HINTED_WAIT (a per-day limit, usually), keyed to
# the time.monotonic() at which they may be tried again. Later calls go straight to a fallback.
_cooling_until: dict[str, float] = {}


def mark_cooling(model: str, exc: BaseException) -> None:
    hint = retry_after_seconds(exc)
    if hint is not None and hint > MAX_HINTED_WAIT:
        import time as _time
        _cooling_until[model] = _time.monotonic() + hint


def is_cooling(model: str) -> bool:
    import time as _time
    until = _cooling_until.get(model)
    if until is None:
        return False
    if _time.monotonic() >= until:
        _cooling_until.pop(model, None)
        return False
    return True


def skip_cooling(chain: list[str]) -> list[str]:
    """The chain without models that are waiting out a long limit; the whole chain if all are."""
    ready = [m for m in chain if not is_cooling(m)]
    return ready or chain


_TOO_LARGE_RE = re.compile(r"request too large.*?\b(?:output tokens|tokens)\b.*?limit\s+(\d+)", re.IGNORECASE | re.DOTALL)


def output_limit_hint(exc: BaseException) -> Optional[int]:
    """A provider refusing a request as too large for its token limit (Groq: "Request too large ...
    Limit 1000"). Waiting never helps; asking for fewer output tokens does. Returns a max_tokens
    that fits, or None."""
    text = str(exc)
    if "reduce max_tokens" not in text.lower() and "request too large" not in text.lower():
        return None
    match = _TOO_LARGE_RE.search(text)
    if not match:
        return None
    return max(64, int(int(match.group(1)) * 0.9))


def is_malformed_tool_call(exc: BaseException) -> bool:
    """The model produced an invalid tool call (Groq: tool_use_failed). Sending the request again usually works."""
    text = str(exc).lower()
    return "tool_use_failed" in text or "tool call validation failed" in text


def _is_retryable_error(exc: BaseException) -> bool:
    """Check if exception is a transient HTTP/network or rate limit error."""
    err_str = str(exc).lower()
    # Never retry on permanent daily quota exhaustion
    if any(q in err_str for q in ("quota exceeded", "resource_exhausted", "daily limit", "per day")):
        return False
    if is_malformed_tool_call(exc):
        return True
    if output_limit_hint(exc) is not None:
        return False  # waiting never helps; chat() retries with a smaller max_tokens
    if any(k in err_str for k in ("rate_limit", "ratelimit", "429", "timeout", "timed out", "connection error", "503", "502")):
        return True
    return False


def _wait_for_retry(retry_state: Any) -> float:
    """Wait as long as the provider asked (plus a margin), else back off exponentially."""
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    hint = retry_after_seconds(exc) if exc is not None else None
    if hint is not None and hint <= MAX_HINTED_WAIT:
        return hint + 0.5
    return _exponential(retry_state)


_exponential = wait_exponential(multiplier=1.5, min=2, max=30)


@retry(
    stop=stop_after_attempt(6),
    wait=_wait_for_retry,
    retry=retry_if_exception(_is_retryable_error),
    reraise=True,
)
def _completion_with_retry(model: str, messages: list[dict], **kwargs: Any) -> Any:
    logger.debug("Executing LiteLLM completion (model: %s)", model)
    defaults = litellm_kwargs(model)
    headers = {**defaults.pop("extra_headers", {}), **(kwargs.pop("extra_headers", None) or {})}
    if headers:
        kwargs["extra_headers"] = headers
    kwargs = {**defaults, **kwargs}
    return litellm.completion(model=model, messages=messages, **kwargs)


THINKING_ROOM = 4096  # max_tokens for the retry when reasoning used up a smaller cap


def thinking_used_the_budget(resp: Any) -> bool:
    """True when the reply was cut off by max_tokens before any visible text or tool call.

    Reasoning models (Claude Haiku 5.5, gpt-oss, o-series) count their thinking against max_tokens;
    with a small cap they stop with finish_reason=length and no content at all.
    """
    try:
        choice = resp.choices[0]
        msg = choice.message
    except (AttributeError, IndexError, TypeError):
        return False
    return (getattr(choice, "finish_reason", None) == "length"
            and not (getattr(msg, "content", None) or "").strip()
            and not getattr(msg, "tool_calls", None))


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
        chain += usable_fallbacks(target_model, config.fallback_chain)
    chain = skip_cooling(chain)
    resp = None
    for index, candidate in enumerate(chain):
        try:
            try:
                resp = _completion_with_retry(model=candidate, messages=messages, **call_kwargs)
            except RETRYABLE_ERRORS as exc:
                fits = output_limit_hint(exc)
                if fits is None or fits >= call_kwargs["max_tokens"]:
                    raise
                # Too large for this provider's output limit: the same request with a smaller cap fits.
                resp = _completion_with_retry(model=candidate, messages=messages, **{**call_kwargs, "max_tokens": fits})
            if thinking_used_the_budget(resp) and call_kwargs["max_tokens"] < THINKING_ROOM:
                # A reasoning model spent the whole cap thinking and wrote no answer: give it room once.
                resp = _completion_with_retry(model=candidate, messages=messages,
                                              **{**call_kwargs, "max_tokens": THINKING_ROOM})
            target_model = candidate
            if index > 0:
                _emit_fallback(role, chain[0], candidate, "fallback after provider error")
            break
        except RETRYABLE_ERRORS as exc:
            mark_cooling(candidate, exc)
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
