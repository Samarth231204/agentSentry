"""Semgrep, the external MCP server (official `semgrep-mcp`, started with uvx over stdio).

The Search agent writes a Semgrep pattern (for example `$CLIENT.messages.create(...)` or
`subprocess.run(...)`) and this sends it, with the project's Python files, to the server's
semgrep_scan_with_custom_rule tool. Needs uv and the semgrep binary (`uv tool install semgrep`).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Optional

from agentguard.mcp.client import MCPError, ServerSpec, call
from agentguard.scanner import iter_python_files

SERVER_PACKAGE = "semgrep-mcp==0.8.1"  # 0.9+ only exposes a deprecation notice without the Pro Engine
EXTRA_PINS = ["--with", "pydantic>=2.6,<2.11"]  # the server's MCP import breaks on newer pydantic
MAX_FILES = 300


def semgrep_spec() -> tuple[Optional[ServerSpec], str]:
    """(spec, reason). spec is None when the server cannot be started here."""
    uvx = shutil.which("uvx")
    if uvx is None:
        return None, "uvx is not installed (install uv: https://docs.astral.sh/uv/)"
    binary = shutil.which("semgrep")
    if binary is None:
        return None, "semgrep is not installed (run: uv tool install semgrep)"
    return ServerSpec(name="semgrep", transport="stdio", command=[uvx, *EXTRA_PINS, SERVER_PACKAGE],
                      env={**os.environ, "SEMGREP_PATH": binary}), "ok"


def pattern_rule(pattern: str, message: str = "match") -> str:
    """A one-pattern Semgrep rule. JSON is valid YAML, so no quoting problems."""
    return json.dumps({"rules": [{"id": "agentguard-search", "languages": ["python"], "severity": "INFO",
                                  "message": message, "pattern": pattern}]})


def semgrep_search(root: str | Path, pattern: str, timeout: float = 180.0) -> str:
    spec, reason = semgrep_spec()
    if spec is None:
        return f"Semgrep is unavailable: {reason}. Use search_code instead."
    root = Path(root).resolve()
    files = [{"filename": p.relative_to(root).as_posix(), "content": p.read_text(encoding="utf-8", errors="replace")}
             for p in list(iter_python_files(root))[:MAX_FILES]]
    try:
        result = call(spec, "semgrep_scan_with_custom_rule", {"code_files": files, "rule": pattern_rule(pattern)},
                      timeout=timeout)
    except MCPError as exc:
        return f"Semgrep failed: {str(exc)[-300:]}"
    structured = result.get("structured") or {}
    if not structured and result.get("text"):
        try:
            structured = json.loads(result["text"])
        except ValueError:
            # Errors arrive as text after Semgrep's banner; the end has the reason.
            return "Semgrep error (check the pattern syntax): " + result["text"].strip()[-500:]
    rows = structured.get("results", []) if isinstance(structured, dict) else []
    errors = structured.get("errors", []) if isinstance(structured, dict) else []
    if not rows:
        if errors:
            return "Semgrep rejected the pattern: " + json.dumps(errors)[:600]
        return "no matches"
    text_of = {f["filename"]: f["content"].splitlines() for f in files}
    out = []
    for row in rows[:60]:
        path = row.get("path", "")
        rel = next((name for name in text_of if path == name or path.endswith("/" + name)), path)
        line = int(row.get("start", {}).get("line", 0))
        src = text_of.get(rel, [])
        code = src[line - 1].strip()[:200] if 0 < line <= len(src) else ""
        out.append(f"{rel}:{line}: {code}")
    return "\n".join(out)
