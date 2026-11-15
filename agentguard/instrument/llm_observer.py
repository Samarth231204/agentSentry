"""Records the prompts a target sends to its model, whatever client library it uses.

The system-prompt fingerprint and goal-hijack checks need to see the system prompt the
application gave its model. Projects rarely call AgentGuard's own chat(); they call litellm,
the OpenAI, Groq or Anthropic SDKs directly. install() wraps those clients' completion entry
points in the generated target process only (never in the user's own runs). Each call made
during an /invoke request is recorded as an "llm" observation; outside a request nothing is
recorded. The wrappers never change arguments or results.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
import inspect
from typing import Any, Callable

from agentguard.logging import get_logger

logger = get_logger("instrument.llm_observer")
MARK = "__agentguard_llm_observed__"

# (module, attribute path, client label). Classes are patched at the method, so clients created
# before or after install() are both covered.
TARGETS = (
    ("litellm", "completion", "litellm"),
    ("litellm", "acompletion", "litellm"),
    ("openai.resources.chat.completions", "Completions.create", "openai"),
    ("openai.resources.chat.completions", "AsyncCompletions.create", "openai"),
    ("openai.resources.responses", "Responses.create", "openai-responses"),
    ("openai.resources.responses", "AsyncResponses.create", "openai-responses"),
    ("groq.resources.chat.completions", "Completions.create", "groq"),
    ("groq.resources.chat.completions", "AsyncCompletions.create", "groq"),
    ("anthropic.resources.messages", "Messages.create", "anthropic"),
    ("anthropic.resources.messages", "AsyncMessages.create", "anthropic"),
)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # content parts: [{"type": "text", "text": ...}]
        return " ".join(str(p.get("text", "")) if isinstance(p, dict) else str(p) for p in content)
    return "" if content is None else str(content)


def _messages(kwargs: dict[str, Any], args: tuple) -> list[dict[str, str]]:
    msgs: list[dict[str, str]] = []
    system = kwargs.get("system") or kwargs.get("instructions")  # Anthropic / OpenAI Responses
    if system:
        msgs.append({"role": "system", "content": _text(system)[:4000]})
    raw = kwargs.get("messages")
    if raw is None:
        raw = kwargs.get("input")
    if raw is None:
        raw = next((a for a in args if isinstance(a, list)), None)
    if isinstance(raw, str):
        raw = [{"role": "user", "content": raw}]
    for m in raw or []:
        if isinstance(m, dict):
            msgs.append({"role": str(m.get("role", "")), "content": _text(m.get("content"))[:4000]})
        elif hasattr(m, "role"):
            msgs.append({"role": str(getattr(m, "role", "")), "content": _text(getattr(m, "content", ""))[:4000]})
    return msgs


def _record(label: str, args: tuple, kwargs: dict[str, Any]) -> None:
    try:
        from agentguard.instrument.wrappers import record_observation
        record_observation("llm", label, {"messages": _messages(kwargs, args), "model": str(kwargs.get("model", ""))})
    except Exception as exc:  # observing must never break the target
        logger.debug("could not record %s call: %s", label, exc)


def _wrap(fn: Callable[..., Any], label: str) -> Callable[..., Any]:
    if getattr(fn, MARK, False):
        return fn
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(*args: Any, **kwargs: Any) -> Any:
            _record(label, args, kwargs)
            return await fn(*args, **kwargs)
        setattr(awrapper, MARK, True)
        return awrapper

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        _record(label, args, kwargs)
        return fn(*args, **kwargs)
    setattr(wrapper, MARK, True)
    return wrapper


def install() -> list[str]:
    """Wraps every installed client entry point. Returns the ones wrapped."""
    wrapped = []
    for module_name, attr_path, label in TARGETS:
        root = module_name.split(".", 1)[0]
        if importlib.util.find_spec(root) is None:
            continue
        try:
            owner: Any = importlib.import_module(module_name)
        except Exception as exc:  # an optional client that fails to import is simply not observed
            logger.debug("skip %s: %s", module_name, exc)
            continue
        *parents, name = attr_path.split(".")
        for part in parents:
            owner = getattr(owner, part, None)
        fn = getattr(owner, name, None) if owner is not None else None
        if fn is None:
            continue
        setattr(owner, name, _wrap(fn, label))
        wrapped.append(f"{module_name}.{attr_path}")
    return wrapped
