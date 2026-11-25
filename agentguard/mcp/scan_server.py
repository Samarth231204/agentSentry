"""AgentGuard's own MCP server: lets an agent scan, search and read the user's project.

Run it as `python -m agentguard.mcp.scan_server` (stdio). The project folder comes from the
AGENTGUARD_PROJECT environment variable. Every path is confined to that folder, and secret
files (.env, keys) are never returned.

Tools: scan_project, list_files, search_code, read_code.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from agentguard.scanner import iter_python_files, scan_project as _scan

mcp = FastMCP("agentguard-scan")

SECRET_NAMES = {".env", ".env.local", ".env.production", "secrets.json", "credentials.json", "id_rsa"}
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
TEXT_SUFFIXES = (".py", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".html", ".jinja", ".j2")
MAX_READ_LINES = 200
MAX_MATCHES = 60


def root() -> Path:
    return Path(os.environ.get("AGENTGUARD_PROJECT", ".")).resolve()


def _safe(rel: str) -> Path:
    path = (root() / rel).resolve()
    if path != root() and root() not in path.parents:
        raise ValueError(f"{rel} is outside the project")
    if path.name in SECRET_NAMES or path.name.startswith(".env") or path.suffix in SECRET_SUFFIXES:
        raise ValueError(f"{rel} is a secrets file and is never read")
    return path


def _text_files() -> list[Path]:
    out = list(iter_python_files(root()))
    for p in root().rglob("*"):
        if (p.is_file() and p.suffix in TEXT_SUFFIXES and p.suffix != ".py"
                and not any(part.startswith(".") or part in {"node_modules", "venv", "AgentGuard", "build", "dist"}
                            for part in p.relative_to(root()).parts[:-1])
                and p.stat().st_size < 200_000):
            out.append(p)
    return out


@mcp.tool()
def scan_project() -> dict:
    """Scans every Python file without running it. Returns the LLM call sites, tool definitions
    (decorators, JSON schemas, tools=[...] lists, name-to-function tables, also across files),
    prompts and functions that take a user's message. Each item has file, line, code and signals."""
    return _scan(root()).model_dump()


@mcp.tool()
def list_files() -> list[str]:
    """Lists the project's source and text files (relative paths)."""
    return [p.relative_to(root()).as_posix() for p in _text_files()]


@mcp.tool()
def search_code(pattern: str, file_glob: str = "") -> str:
    """Regex search (case-insensitive) over the project's text files. Returns 'file:line: text' lines.
    file_glob optionally limits the files, e.g. '*.py' or 'tools/*.py'."""
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return f"invalid regex: {exc}"
    hits: list[str] = []
    for p in _text_files():
        rel = p.relative_to(root()).as_posix()
        if file_glob and not Path(rel).match(file_glob):
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if rx.search(line):
                hits.append(f"{rel}:{n}: {line.strip()[:200]}")
                if len(hits) >= MAX_MATCHES:
                    return "\n".join(hits) + f"\n... stopped at {MAX_MATCHES} matches, narrow the pattern"
    return "\n".join(hits) or "no matches"


@mcp.tool()
def read_code(file: str, start_line: int = 1, end_line: int = 80) -> str:
    """Reads lines start_line..end_line of a project file, numbered. At most 200 lines per call."""
    try:
        path = _safe(file)
    except ValueError as exc:
        return str(exc)
    if not path.is_file():
        return f"{file} does not exist"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start_line)
    end = min(len(lines), end_line, start + MAX_READ_LINES - 1)
    body = "\n".join(f"{n:>5}  {lines[n - 1]}" for n in range(start, end + 1))
    return f"{file} lines {start}-{end} of {len(lines)}\n{body}"


if __name__ == "__main__":
    mcp.run()
