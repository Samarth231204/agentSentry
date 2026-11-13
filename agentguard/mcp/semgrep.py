"""Semgrep as an external MCP server, used for deterministic sink evidence.

We do not depend on Semgrep's Python package (it conflicts with the pinned MCP
SDK). The official server is started in its own environment with uvx, and it
needs the semgrep binary: `uv tool install semgrep` (see the setup checklist).
If anything is missing, discovery continues without Semgrep and records why.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable, Optional

from agentguard.events import get_event_bus
from agentguard.logging import get_logger
from agentguard.mcp.client import MCPError, ServerSpec, call
from agentguard.schemas import TraceEvent

logger = get_logger("mcp.semgrep")

RULES_PATH = Path(__file__).resolve().parent.parent / "discovery" / "rules" / "sinks.yaml"
SERVER_PACKAGE = "semgrep-mcp==0.8.1"  # 0.9+ only exposes a deprecation notice without Pro Engine
EXTRA_PINS = ["--with", "pydantic>=2.6,<2.11"]  # the server's MCP import breaks on newer pydantic


def semgrep_spec() -> tuple[Optional[ServerSpec], str]:
    """(spec, reason). spec is None when the server cannot be started here."""
    uvx = shutil.which("uvx")
    if uvx is None:
        return None, "uvx is not installed (install uv: https://docs.astral.sh/uv/)"
    binary = shutil.which("semgrep")
    if binary is None:
        return None, "semgrep is not installed (run: uv tool install semgrep)"
    spec = ServerSpec(
        name="semgrep", transport="stdio",
        command=[uvx, *EXTRA_PINS, SERVER_PACKAGE],
        env={**os.environ, "SEMGREP_PATH": binary},
    )
    return spec, "ok"


def _emit_unavailable(reason: str) -> None:
    get_event_bus().emit(TraceEvent(source="mcp", event_type="mcp_unavailable",
                                    payload={"server": "semgrep", "reason": reason}))


def scan_sinks(files: list[tuple[str, str]], timeout: float = 240.0) -> Optional[list[dict]]:
    """Runs the sink rules over (relative_path, text) pairs. None means Semgrep was not used."""
    spec, reason = semgrep_spec()
    if spec is None:
        _emit_unavailable(reason)
        return None
    try:
        result = call(spec, "semgrep_scan_with_custom_rule", {
            "code_files": [{"filename": rel, "content": text} for rel, text in files],
            "rule": RULES_PATH.read_text(encoding="utf-8"),
        }, timeout=timeout)
    except MCPError as exc:
        _emit_unavailable(str(exc)[:300])
        return None
    structured = result.get("structured") or {}
    findings = []
    for row in structured.get("results", []):
        findings.append({
            "check_id": row.get("check_id", ""),
            "path": row.get("path", ""),
            "line": int(row.get("start", {}).get("line", 0)),
            "message": row.get("extra", {}).get("message", ""),
        })
    return findings


Enricher = Callable[[list[tuple[str, str]]], Optional[list[dict]]]
