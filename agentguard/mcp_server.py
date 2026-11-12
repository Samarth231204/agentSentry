"""Local, read-only MCP tools for report generation."""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from agentguard.events import JSONLFileSink, get_event_bus
from agentguard.schemas import TraceEvent

mcp = FastMCP("agentguard")
_target_directory = Path(os.environ["AGENTGUARD_TARGET_DIRECTORY"]).resolve() if os.environ.get("AGENTGUARD_TARGET_DIRECTORY") else None
_MAX_CHARS = 4000

if trace_path := os.environ.get("AGENTGUARD_TRACE_PATH"):
    get_event_bus().subscribe(JSONLFileSink(trace_path))

_OWASP = {
    "prompt_injection": "LLM01: Prompt Injection — attacker input changes model behavior.",
    "secret_extraction": "LLM02: Sensitive Information Disclosure — secrets leak through model output.",
    "tool_misuse": "LLM06: Excessive Agency — tools act without sufficient controls.",
    "data_exfiltration": "LLM02: Sensitive Information Disclosure — sensitive data leaves the intended boundary.",
    "privilege_escalation": "LLM06: Excessive Agency — the agent gains or uses unauthorized authority.",
    "rag_poisoning": "LLM01: Prompt Injection — retrieved content controls the model.",
    "memory_persistence": "LLM01: Prompt Injection — persisted instructions alter later behavior.",
    "undeclared_capability": "LLM06: Excessive Agency — undeclared tool capability was observed.",
}


def configure_target_directory(path: str | Path) -> None:
    global _target_directory
    _target_directory = Path(path).resolve()


def _emit(event_type: str, **payload: object) -> None:
    get_event_bus().emit(TraceEvent(source="mcp", event_type=event_type, payload=payload))


def lookup_owasp(category: str) -> str:
    """Plain lookup shared by the MCP tool and the deterministic report fallback."""
    return _OWASP.get(category, f"unknown category: {category}")


def find_in_source(query: str, root: Path, max_results: int = 5) -> list[tuple[Path, int, str]]:
    """Case-insensitive line search over root/**/*.py. No path checks: callers
    decide which root is allowed. Returns (file, line_number, stripped_line)."""
    limit = max(1, min(max_results, 20))
    matches: list[tuple[Path, int, str]] = []
    for source in sorted(root.rglob("*.py")):
        try:
            for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
                if query.lower() in line.lower():
                    matches.append((source, number, line.strip()))
                    if len(matches) >= limit:
                        return matches
        except (OSError, UnicodeDecodeError):
            continue
    return matches


@mcp.tool()
def owasp_lookup(category: str) -> str:
    """Return the OWASP LLM Top 10 mapping for an AgentGuard category."""
    _emit("mcp_tool_call", tool="owasp_lookup", category=category)
    result = lookup_owasp(category)
    _emit("mcp_tool_result", tool="owasp_lookup", category=category, result=result)
    return result


@mcp.tool()
def search_code(query: str, repo_path: str, max_results: int = 5) -> str:
    """Search configured target Python source without escaping its root directory."""
    _emit("mcp_tool_call", tool="search_code", query=query)
    root = Path(repo_path).resolve()
    if _target_directory is None or root != _target_directory:
        result = "refused: repo_path is outside the configured target directory"
    elif not root.is_dir():
        result = "refused: configured target directory is unavailable"
    else:
        matches = [f"{source}:{number}:{line}" for source, number, line in find_in_source(query, root, max_results)]
        result = "\n".join(matches) or "no matches"
    result = result[:_MAX_CHARS]
    _emit("mcp_tool_result", tool="search_code", result=result)
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")
