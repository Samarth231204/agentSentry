"""AgentGuard's payload library as an MCP server (stdio): proven attack techniques and disguises.

Run it as `python -m agentguard.mcp.payload_server`. The ADK attack agents reach it through
payload_spec() and the traced MCP client.

Tools: list_techniques, get_payload, transform, list_transforms.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from agentguard.attack import payloads

mcp = FastMCP("agentguard-payloads")


@mcp.tool()
def list_techniques(category: str) -> list[dict]:
    """Attack techniques for one attack type (id, name, why it works)."""
    return payloads.techniques(category)


@mcp.tool()
def get_payload(category: str, technique: str, values: dict[str, str] | None = None) -> dict:
    """One ready payload for a technique, with placeholders ({a}, {b}, {marker}, {email}, {url}) filled in."""
    return payloads.payload(category, technique, values or {})


@mcp.tool()
def transform(text: str, method: str) -> str:
    """Disguise a payload: base64, rot13, leetspeak, homoglyph, zero_width, reverse, split, code_block, json."""
    return payloads.transform(text, method)


@mcp.tool()
def list_transforms() -> list[str]:
    """The names of the disguises transform() knows."""
    return sorted(payloads.TRANSFORMS)


def payload_spec():
    from agentguard.mcp.client import ServerSpec

    repo = str(Path(__file__).resolve().parents[2])
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([repo, os.environ.get("PYTHONPATH", "")])}
    return ServerSpec(name="agentguard-payloads", transport="stdio",
                      command=[sys.executable, "-m", "agentguard.mcp.payload_server"], env=env)


if __name__ == "__main__":
    mcp.run()
