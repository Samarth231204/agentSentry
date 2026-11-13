"""MCP server (ours): code intelligence for one project. Streamable HTTP on 127.0.0.1.

Tools: search_code, list_candidates, get_symbol, callers, callees, read_span, list_routes.
All paths are resolved inside the project root and must be .py files.
Run with: python -m agentguard.mcp.codeintel_server --project PATH --port 8790
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from agentguard.discovery import discover
from agentguard.discovery.walker import analyse_file, iter_python_files

MAX_SPAN_LINES = 200
MAX_RESULTS = 50

mcp = FastMCP("agentguard-codeintel")
_state: dict = {"root": None, "files": {}, "candidates": [], "functions": {}}


def _root() -> Path:
    if _state["root"] is None:
        raise RuntimeError("codeintel server has no project loaded")
    return _state["root"]


def load_project(root: Path) -> None:
    """Parses the project once at startup. Results are cached by content hash."""
    root = Path(root).resolve()
    cache = root / ".agentguard" / "cache" / "discovery"
    files = {}
    functions = {}
    for path in iter_python_files(root):
        info = analyse_file(path, root, cache)
        files[info.path] = info
        for fn in info.functions:
            functions[(info.path, fn.qualname)] = fn
    result = discover(root, cache_dir=cache)
    _state.update(root=root, files=files, functions=functions,
                  candidates=[vars(c) for c in result.candidates])


def _safe_py(rel: str) -> Path:
    root = _root()
    target = (root / rel).resolve()
    if root != target and root not in target.parents:
        raise ValueError("path is outside the project")
    if target.suffix != ".py" or not target.is_file():
        raise ValueError("only existing .py files inside the project can be read")
    return target


@mcp.tool()
def search_code(query: str, max_results: int = 10) -> list[str]:
    """Case-insensitive substring search over project Python files. Returns 'path:line: text'."""
    needle = query.strip().lower()
    if not needle:
        return []
    limit = max(1, min(max_results, MAX_RESULTS))
    hits: list[str] = []
    for rel in sorted(_state["files"]):
        lines = _safe_py(rel).read_text(encoding="utf-8", errors="replace").splitlines()
        for number, line in enumerate(lines, 1):
            if needle in line.lower():
                hits.append(f"{rel}:{number}: {line.strip()[:200]}")
                if len(hits) >= limit:
                    return hits
    return hits


@mcp.tool()
def list_candidates(role: Optional[str] = None) -> list[dict]:
    """Candidates found by deterministic discovery, optionally filtered by role."""
    rows = _state["candidates"]
    if role:
        rows = [c for c in rows if c["role"] == role]
    return [{k: c[k] for k in ("id", "role", "file", "qualname", "line", "confidence", "signals")} for c in rows]


@mcp.tool()
def get_symbol(file: str, qualname: str) -> dict:
    """Location, decorators, calls and framework signals of one function."""
    fn = _state["functions"].get((file, qualname))
    if fn is None:
        raise ValueError("no such function in that file")
    return {
        "file": file, "qualname": qualname, "line": fn.lineno, "end_line": fn.end_lineno,
        "args": fn.args, "decorators": fn.decorators, "calls": fn.calls,
        "has_llm_call": fn.has_llm_call, "sink_calls": fn.sink_calls, "is_async": fn.is_async,
    }


@mcp.tool()
def callers(name: str) -> list[str]:
    """Functions in the project that call a function with this name (matched on the last name segment)."""
    short = name.rsplit(".", 1)[-1]
    out = []
    for (file, qual), fn in _state["functions"].items():
        if any(c.rsplit(".", 1)[-1] == short for c in fn.calls):
            out.append(f"{file}:{qual}")
    return sorted(out)


@mcp.tool()
def callees(file: str, qualname: str) -> list[str]:
    """Calls made by one function, as written in the source."""
    fn = _state["functions"].get((file, qualname))
    if fn is None:
        raise ValueError("no such function in that file")
    return list(fn.calls)


@mcp.tool()
def read_span(file: str, start: int, end: int) -> str:
    """Numbered source lines start..end (inclusive). At most 200 lines per call."""
    path = _safe_py(file)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start)
    end = min(end, start + MAX_SPAN_LINES - 1, len(lines))
    return "\n".join(f"{n:5d}  {lines[n - 1]}" for n in range(start, end + 1))


@mcp.tool()
def list_routes() -> list[dict]:
    """HTTP route handlers found in the project (method path -> function)."""
    out = []
    for (file, qual), fn in _state["functions"].items():
        for path in fn.route_paths:
            out.append({"file": file, "qualname": qual, "path": path})
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentGuard code-intelligence MCP server")
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8790)
    args = parser.parse_args()
    load_project(args.project)
    mcp.settings.host = "127.0.0.1"
    mcp.settings.port = args.port
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
