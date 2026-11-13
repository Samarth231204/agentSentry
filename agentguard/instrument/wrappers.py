"""Recording wrappers applied by the import hook (or by hand with @watch).

Each wrapper writes what happened to a per-request log that the adapter returns
in /invoke. `tool` calls are the only ones the oracles read today. Other roles
are recorded for the report and for later oracles (Phase 5).

Sandbox: a sandboxed tool is recorded but not executed. The model receives a
synthetic reply, so a red-team run never performs a real side effect.
"""

from __future__ import annotations

import functools
import inspect
import time
from typing import Any, Callable

from agentguard import adapter

ROLES = ("tool", "retrieval", "memory", "llm", "outbound")
SANDBOX_REPLY = "[AgentGuard sandbox] {name} was recorded but not executed."


def _observe(role: str, fn: Callable[..., Any], args: tuple, kwargs: dict, sandboxed: bool) -> None:
    log = adapter._calls.get()
    if log is None:
        return
    bound = adapter._bind(fn, args, kwargs)
    entry = {"name": fn.__name__, "args": bound, "ts": time.time()}
    if role == "tool":
        entry["sandboxed"] = sandboxed
        log.append(entry)
    else:
        adapter._observations.get().setdefault(role, []).append(entry)


def wrap(role: str, sandbox: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory used by the import hook: wrap(role, sandbox)(fn)."""
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                _observe(role, fn, args, kwargs, sandbox)
                if sandbox and role == "tool":
                    return SANDBOX_REPLY.format(name=fn.__name__)
                return await fn(*args, **kwargs)
            return awrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _observe(role, fn, args, kwargs, sandbox)
            if sandbox and role == "tool":
                return SANDBOX_REPLY.format(name=fn.__name__)
            return fn(*args, **kwargs)
        return wrapper

    return decorator


def watch_as(role: str, sandbox: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Alias kept for readability in generated code."""
    return wrap(role, sandbox)
