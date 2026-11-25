"""The one model AgentGuard's own agents use, and the CrewAI LLM object for it.

AGENTGUARD_MODEL overrides the default. The key comes from ANTHROPIC_API_KEY in AgentGuard's .env.
"""

from __future__ import annotations

import os
from typing import Any

from agentguard._env import load_env

load_env()
# No usage data leaves this machine from CrewAI or LiteLLM.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
if not (os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY")):
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")  # LangFuse v3 is built on OpenTelemetry

DEFAULT_MODEL = "anthropic/claude-sonnet-5-5"


def model_name() -> str:
    name = os.environ.get("AGENTGUARD_MODEL", DEFAULT_MODEL).strip()
    return name if "/" in name else f"anthropic/{name}"


def has_key() -> bool:
    provider = model_name().split("/", 1)[0]
    return bool(os.environ.get(f"{provider.upper()}_API_KEY"))


def extra_headers() -> dict[str, str]:
    """Keys that are not scoped to a workspace must name one in a header."""
    ws = os.environ.get("ANTHROPIC_WORKSPACE_ID", "").strip()
    return {"anthropic-workspace-id": ws} if ws and model_name().startswith("anthropic/") else {}


def _patch_litellm_workspace_header() -> None:
    """Some calls reach LiteLLM without our headers (CrewAI's Instructor-based structured-output
    fallback). Every Anthropic call made in this process gets the workspace header."""
    ws = os.environ.get("ANTHROPIC_WORKSPACE_ID", "").strip()
    if not ws:
        return
    try:
        import litellm
    except ImportError:
        return
    if getattr(litellm, "_agentguard_ws", False):
        return

    def add(kwargs: dict) -> dict:
        model = str(kwargs.get("model", ""))
        if model.startswith("anthropic/") or model.startswith("claude-"):
            kwargs["extra_headers"] = {**(kwargs.get("extra_headers") or {}), "anthropic-workspace-id": ws}
        return kwargs

    sync, async_ = litellm.completion, litellm.acompletion

    def completion(*args: Any, **kwargs: Any):
        return sync(*args, **add(kwargs))

    async def acompletion(*args: Any, **kwargs: Any):
        return await async_(*args, **add(kwargs))

    litellm.completion, litellm.acompletion = completion, acompletion
    litellm._agentguard_ws = True


_patch_litellm_workspace_header()


def crew_llm(max_tokens: int = 4096, react_text: bool = True):
    """A CrewAI LLM that calls through LiteLLM.

    CrewAI's LLM() switches to a native Anthropic SDK class for anthropic/ models, which needs the
    anthropic package. Sonnet/Opus 5.x reject `temperature`, so none is sent. Skipping that dispatch keeps one client path (LiteLLM) for every provider.
    """
    from crewai import LLM

    try:  # CrewAI adds a 'cache_breakpoint' field to messages that LiteLLM rejects for Anthropic.
        import crewai.llms.cache as _cache
        _cache.mark_cache_breakpoint = lambda message: message
    except Exception:  # noqa: BLE001
        pass

    class _LiteLLMBacked(LLM):
        def __new__(cls, *args: Any, **kwargs: Any) -> "_LiteLLMBacked":
            return object.__new__(cls)

        # CrewAI sends response_model to Instructor, which forces a tool choice; Claude 5.5 models reject
        # forced tool use. Without it CrewAI asks for JSON in the text and validates it with Pydantic.
        def call(self, *args: Any, **kwargs: Any) -> Any:
            kwargs.pop("response_model", None)
            return super().call(*args, **kwargs)

        async def acall(self, *args: Any, **kwargs: Any) -> Any:
            kwargs.pop("response_model", None)
            return await super().acall(*args, **kwargs)

        def supports_function_calling(self) -> bool:
            # react_text: CrewAI then runs the classic text ReAct loop (Thought / Action /
            # Action Input / Observation), one tool per step, so every step has a visible thought.
            return not react_text

    kwargs: dict[str, Any] = {}
    if extra_headers():
        kwargs["extra_headers"] = extra_headers()
    return _LiteLLMBacked(model=model_name(), max_tokens=max_tokens, **kwargs)
