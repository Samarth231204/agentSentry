"""Fetch, the external MCP server (official `mcp-server-fetch`, started with uvx over stdio).

The attack agents use it to preview a planted page exactly as a browsing AI agent would read it
(HTML turned into text). It is locked to AgentGuard's own trap server with --allowed-hosts, so our
agents can never use it to reach anything else.
"""

from __future__ import annotations

import shutil
from typing import Optional
from urllib.parse import urlparse

from agentguard.mcp.client import MCPError, ServerSpec, call

SERVER_PACKAGE = "mcp-server-fetch"


def fetch_spec(allowed_host: str = "127.0.0.1") -> tuple[Optional[ServerSpec], str]:
    uvx = shutil.which("uvx")
    if uvx is None:
        return None, "uvx is not installed (install uv: https://docs.astral.sh/uv/)"
    return ServerSpec(name="fetch", transport="stdio",
                      command=[uvx, SERVER_PACKAGE, "--ignore-robots-txt", "--allow-private-ips",
                               "--allowed-hosts", allowed_host]), "ok"


def fetch_page(url: str, timeout: float = 90.0) -> str:
    host = urlparse(url).hostname or ""
    if host != "127.0.0.1":
        return "Refused: only AgentGuard's own trap pages can be previewed."
    spec, reason = fetch_spec(host)
    if spec is None:
        return f"Fetch MCP is unavailable: {reason}"
    try:
        result = call(spec, "fetch", {"url": url, "max_length": 4000}, timeout=timeout)
    except MCPError as exc:
        return f"Fetch failed: {str(exc)[-300:]}"
    return result["text"]
