"""The three AgentGuard agents as A2A handlers. Each one is a thin wrapper around the in-process code.

Security: the project root is fixed by the server (agentguard up --project). A client can never
choose which folder discovery reads or where the reporter writes; reports go under .agentguard/a2a/.
The attacker accepts loopback targets only, the same rule as the dashboard.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from agentguard.budget import BudgetConfig, BudgetTracker
from agentguard.events import get_event_bus
from agentguard.schemas import TargetProfile, TraceEvent

LOOPBACK = {"127.0.0.1", "localhost"}


def _emit(agent: str, latency_ms: float, ok: bool) -> None:
    get_event_bus().emit(TraceEvent(source="a2a", event_type="a2a_handled",
                                    payload={"agent": agent, "latency_ms": latency_ms, "ok": ok}))


def discovery_handler(project_root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    from agentguard.discovery import discover
    from agentguard.mcp.semgrep import scan_sinks
    import os
    started = time.perf_counter()
    enrich = scan_sinks if os.environ.get("AGENTGUARD_SEMGREP", "1") != "0" else None
    result = discover(project_root, cache_dir=project_root / ".agentguard" / "cache" / "discovery",
                      enrich=enrich)
    _emit("discovery", (time.perf_counter() - started) * 1000, True)
    return {
        "root": result.root,
        "files_scanned": result.files_scanned,
        "frameworks": result.frameworks,
        "enrichment": result.enrichment,
        "errors": result.errors,
        "candidates": [vars(c) for c in result.candidates],
    }


def attacker_handler(project_root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    from agentguard.attackers import run_attack_suite
    from agentguard.manifest import Manifest, ToolInfo
    from agentguard.target import Target

    url = str(payload.get("target_url", ""))
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in LOOPBACK:
        raise ValueError("target_url must be http(s) on localhost or 127.0.0.1")
    cap = payload.get("manifest") or {}
    manifest = Manifest(
        tools=[ToolInfo(**t) for t in (cap.get("tools") or [])],
        rag=cap.get("rag") or {"present": False, "ingestion": None},
        memory=cap.get("memory") or {"present": False},
    )
    profile = TargetProfile(**payload["profile"]) if payload.get("profile") else None
    budget = BudgetTracker(BudgetConfig(max_calls_total=payload.get("max_llm_calls"),
                                        max_tokens_total=payload.get("max_tokens")))
    started = time.perf_counter()
    sink = asyncio.run(run_attack_suite(
        Target(url), manifest, canaries=list(payload.get("canaries") or []),
        max_probes=payload.get("max_probes"), budget=budget, profile=profile,
        replay=payload.get("replay") or None,
    ))
    findings = {
        "target": sink.target_desc,
        "manifest_summary": sink.manifest_summary,
        "attempts": sink.session_state.get("findings", [a.model_dump(mode="json") for a in sink.attempts]),
        "budget_usage": budget.usage_report(),
    }
    _emit("attacker", (time.perf_counter() - started) * 1000, True)
    return findings


def reporter_handler(project_root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    from agentguard.reporters import generate_report
    started = time.perf_counter()
    work = project_root / ".agentguard" / "a2a" / uuid.uuid4().hex[:12]
    work.mkdir(parents=True, exist_ok=True)
    findings_path = work / "findings.json"
    findings_path.write_text(json.dumps(payload.get("findings") or {}), encoding="utf-8")
    manifest_path = None
    if payload.get("manifest_yaml"):
        manifest_path = work / "manifest.yaml"
        manifest_path.write_text(str(payload["manifest_yaml"]), encoding="utf-8")
    report_path = work / "report.md"
    generate_report(findings_path, report_path, manifest_path=manifest_path,
                    project_path=project_root, use_llm=not payload.get("mock", False))
    _emit("reporter", (time.perf_counter() - started) * 1000, True)
    return {
        "markdown": report_path.read_text(encoding="utf-8"),
        "json": json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8")),
    }


HANDLERS = {"discovery": discovery_handler, "attacker": attacker_handler, "reporter": reporter_handler}
