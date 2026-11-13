"""One MCP client for everything AgentGuard calls over MCP.

Every call writes two trace events, mcp_tool_call and mcp_tool_result (or
mcp_error), with the server, tool, transport, latency and a short preview. The
dashboard's MCP panel is built from these events.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from agentguard.events import get_event_bus
from agentguard.logging import get_logger
from agentguard.schemas import TraceEvent

logger = get_logger("mcp.client")
PREVIEW_CHARS = 300


class MCPError(RuntimeError):
    pass


@dataclass
class ServerSpec:
    name: str
    transport: str  # "http" or "stdio"
    url: Optional[str] = None
    command: list[str] = field(default_factory=list)
    env: Optional[dict[str, str]] = None

    def __post_init__(self) -> None:
        if self.transport not in ("http", "stdio"):
            raise ValueError("transport must be 'http' or 'stdio'")
        if self.transport == "http" and not self.url:
            raise ValueError("http servers need a url")
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio servers need a command")


def _emit(event_type: str, **payload: Any) -> None:
    get_event_bus().emit(TraceEvent(source="mcp", event_type=event_type, payload=payload))


def _text_of(result: Any) -> str:
    parts = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


async def _session(spec: ServerSpec):
    if spec.transport == "http":
        return streamablehttp_client(spec.url)
    params = StdioServerParameters(command=spec.command[0], args=spec.command[1:], env=spec.env)
    return stdio_client(params)


async def _with_session(spec: ServerSpec, fn, timeout: float):
    ctx = await _session(spec)
    async with ctx as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout)
            return await asyncio.wait_for(fn(session), timeout)


def list_tools(spec: ServerSpec, timeout: float = 20.0) -> list[str]:
    async def op(session: ClientSession) -> list[str]:
        listing = await session.list_tools()
        return [t.name for t in listing.tools]
    try:
        return asyncio.run(_with_session(spec, op, timeout))
    except Exception as exc:  # noqa: BLE001
        raise MCPError(f"{spec.name}: could not list tools: {type(exc).__name__}: {exc}") from exc


def call(spec: ServerSpec, tool: str, arguments: Optional[dict[str, Any]] = None,
         timeout: float = 30.0) -> dict[str, Any]:
    """Calls one tool. Returns {"text": str, "structured": Any, "is_error": bool, "latency_ms": float}."""
    arguments = arguments or {}
    _emit("mcp_tool_call", server=spec.name, transport=spec.transport, tool=tool,
          argument_names=sorted(arguments))
    started = time.perf_counter()

    async def op(session: ClientSession):
        return await session.call_tool(tool, arguments)

    try:
        result = asyncio.run(_with_session(spec, op, timeout))
    except Exception as exc:  # noqa: BLE001
        _emit("mcp_error", server=spec.name, tool=tool, error=f"{type(exc).__name__}: {exc}")
        raise MCPError(f"{spec.name}.{tool} failed: {type(exc).__name__}: {exc}") from exc

    latency = round((time.perf_counter() - started) * 1000, 1)
    text = _text_of(result)
    out = {
        "text": text,
        "structured": getattr(result, "structuredContent", None),
        "is_error": bool(getattr(result, "isError", False)),
        "latency_ms": latency,
    }
    _emit("mcp_tool_result", server=spec.name, tool=tool, ok=not out["is_error"],
          latency_ms=latency, preview=text[:PREVIEW_CHARS])
    return out
