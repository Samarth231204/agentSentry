"""Read-only index of AgentGuard runs on disk.

A *run* is a directory that holds any of: findings.json, report.json,
report.md, trace.jsonl, manifest.yaml. Runs are discovered from:

  1. <project>/.agentguard/runs/<name>/   (layout used from Phase 2 on)
  2. <project>/                           (the CLI's default outputs)
  3. every --run-dir given to `agentguard up`

The store never writes anything. Run ids are opaque strings produced from the
absolute path, and they are resolved only through the index built by scan(),
so a request can never make the server read an arbitrary path.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.reporters import compute_scorecard

RUN_FILES = ("findings.json", "report.json", "report.md", "trace.jsonl", "manifest.yaml")


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower() or "run"


def make_run_id(path: Path) -> str:
    digest = hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()[:8]
    return f"{_slug(path.name)}-{digest}"


@dataclass
class Run:
    id: str
    label: str
    path: Path
    source: str  # "agentguard_runs" | "project_root" | "run_dir"
    files: set[str] = field(default_factory=set)
    modified: float = 0.0

    @property
    def has(self) -> set[str]:
        return self.files


class RunStore:
    def __init__(self, project_root: Path, run_dirs: Optional[list[Path]] = None) -> None:
        self.project_root = Path(project_root).resolve()
        self.run_dirs = [Path(p).resolve() for p in (run_dirs or [])]
        self._runs: dict[str, Run] = {}

    # ----- discovery -------------------------------------------------------

    def _candidates(self) -> list[tuple[Path, str]]:
        found: list[tuple[Path, str]] = []
        runs_root = self.project_root / ".agentguard" / "runs"
        if runs_root.is_dir():
            found += [(p, "agentguard_runs") for p in sorted(runs_root.iterdir()) if p.is_dir()]
        found.append((self.project_root, "project_root"))
        found += [(p, "run_dir") for p in self.run_dirs]
        return found

    def scan(self) -> list[Run]:
        runs: dict[str, Run] = {}
        for path, source in self._candidates():
            if not path.is_dir():
                continue
            files = {name for name in RUN_FILES if (path / name).is_file()}
            if not files:
                continue
            run_id = make_run_id(path)
            if run_id in runs:
                continue
            mtime = max((path / name).stat().st_mtime for name in files)
            label = path.name if source != "project_root" else f"{path.name} (project root)"
            runs[run_id] = Run(id=run_id, label=label, path=path, source=source,
                               files=files, modified=mtime)
        self._runs = runs
        return sorted(runs.values(), key=lambda r: r.modified, reverse=True)

    def get(self, run_id: str) -> Optional[Run]:
        if run_id not in self._runs:
            self.scan()
        return self._runs.get(run_id)

    # ----- readers (each returns None/empty when the file is absent or broken)

    def _read_json(self, run: Run, name: str) -> Optional[dict[str, Any]]:
        if name not in run.files:
            return None
        try:
            return json.loads((run.path / name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def report_json(self, run: Run) -> Optional[dict[str, Any]]:
        return self._read_json(run, "report.json")

    def report_markdown(self, run: Run) -> Optional[str]:
        if "report.md" not in run.files:
            return None
        return (run.path / "report.md").read_text(encoding="utf-8")

    def findings_doc(self, run: Run) -> dict[str, Any]:
        """findings.json if present, else the findings embedded in report.json."""
        doc = self._read_json(run, "findings.json")
        if doc is not None:
            doc.setdefault("source", "findings.json")
            return doc
        report = self.report_json(run)
        if report is not None:
            return {"target": None, "manifest_summary": None, "budget_usage": None,
                    "attempts": report.get("findings", []), "source": "report.json"}
        return {"target": None, "manifest_summary": None, "budget_usage": None,
                "attempts": [], "source": None}

    def manifest(self, run: Run) -> Optional[dict[str, Any]]:
        if "manifest.yaml" not in run.files:
            return None
        try:
            return yaml.safe_load((run.path / "manifest.yaml").read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            return None

    def findings(self, run: Run) -> list[dict[str, Any]]:
        """Findings joined with their severity, remediation, OWASP and code references."""
        report = self.report_json(run) or {}
        severity = report.get("severity", {})
        remediation = report.get("remediation", {})
        owasp = report.get("owasp", {})
        code_refs = report.get("code_references", {})
        rows = []
        for attempt in self.findings_doc(run).get("attempts", []):
            fid = attempt.get("id")
            rows.append({
                **attempt,
                "severity": severity.get(fid),
                "remediation": remediation.get(fid),
                "owasp": owasp.get(fid),
                "code_references": code_refs.get(fid, []),
            })
        return rows

    def scorecard(self, run: Run) -> dict[str, Any]:
        report = self.report_json(run)
        if report and report.get("scorecard"):
            return report["scorecard"]
        return compute_scorecard(self.findings_doc(run))

    def read_trace(self, run: Run, offset: int = 0, limit: int = 200) -> tuple[list[dict], int]:
        """Returns (events[offset:offset+limit], total_valid_events). Bad lines are skipped."""
        events = self._all_events(run)
        return events[offset:offset + limit], len(events)

    def _all_events(self, run: Run) -> list[dict]:
        if "trace.jsonl" not in run.files:
            return []
        events = []
        for line in (run.path / "trace.jsonl").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def llm_usage(self, run: Run) -> dict[str, Any]:
        """Per-role usage summed from llm_usage trace events (each carries a per-call delta)."""
        by_role: dict[str, dict[str, int]] = {}
        for event in self._all_events(run):
            if event.get("event_type") != "llm_usage":
                continue
            payload = event.get("payload", {})
            row = by_role.setdefault(payload.get("role", "unknown"),
                                     {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})
            row["calls"] += 1
            row["prompt_tokens"] += int(payload.get("prompt_tokens") or 0)
            row["completion_tokens"] += int(payload.get("completion_tokens") or 0)
        total = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
        for row in by_role.values():
            for key in total:
                total[key] += row[key]
        return {"total": total, "by_role": by_role}

    def mcp_usage(self, run: Run) -> dict[str, Any]:
        """MCP calls per server and tool, from mcp_tool_call / mcp_error trace events."""
        counts: dict[tuple[str, str], int] = {}
        errors = 0
        unavailable: list[str] = []
        for event in self._all_events(run):
            kind = event.get("event_type")
            payload = event.get("payload", {})
            if kind == "mcp_tool_call":
                key = (payload.get("server", "?"), payload.get("tool", "?"))
                counts[key] = counts.get(key, 0) + 1
            elif kind == "mcp_error":
                errors += 1
            elif kind == "mcp_unavailable":
                unavailable.append(f"{payload.get('server', '?')}: {payload.get('reason', '')}"[:200])
        return {
            "calls": [{"server": s, "tool": t, "count": c} for (s, t), c in sorted(counts.items())],
            "total": sum(counts.values()),
            "errors": errors,
            "unavailable": unavailable,
        }

    def event_type_counts(self, run: Run) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self._all_events(run):
            kind = event.get("event_type", "unknown")
            counts[kind] = counts.get(kind, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    # ----- summaries -------------------------------------------------------

    def summary(self, run: Run) -> dict[str, Any]:
        findings = self.findings(run)
        scorecard = self.scorecard(run)
        report = self.report_json(run) or {}
        budget = self.findings_doc(run).get("budget_usage")
        statuses: dict[str, int] = {}
        for f in findings:
            statuses[f.get("status", "unknown")] = statuses.get(f.get("status", "unknown"), 0) + 1
        return {
            "id": run.id,
            "label": run.label,
            "source": run.source,
            "path": str(run.path),
            "modified": run.modified,
            "modified_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(run.modified)),
            "files": sorted(run.files),
            "scorecard": scorecard,
            "statuses": statuses,
            "generated_by": report.get("generated_by"),
            "budget_usage": budget,
            "has_manifest": "manifest.yaml" in run.files,
            "has_report": "report.md" in run.files or "report.json" in run.files,
            "has_trace": "trace.jsonl" in run.files,
            "mock": self.is_mock(run),
            "warnings": self.warnings(run, findings, scorecard),
        }

    def is_mock(self, run: Run) -> bool:
        """True when the run was a demo check (no model calls), read from its run_started trace event."""
        trace = run.path / "trace.jsonl"
        if not trace.is_file():
            return False
        try:
            with trace.open(encoding="utf-8") as fh:
                for _, line in zip(range(50), fh):
                    if '"run_started"' in line:
                        return bool(json.loads(line).get("payload", {}).get("mock"))
        except (OSError, ValueError):
            return False
        return False

    def warnings(self, run: Run, findings: list[dict], scorecard: dict) -> list[str]:
        """Problems a user should see on the dashboard. Nothing here is fatal."""
        out: list[str] = []
        doc_source = self.findings_doc(run).get("source")
        if doc_source is None:
            out.append("No findings.json or report.json in this run.")
        if "report.json" in run.files and self.report_json(run) is None:
            out.append("report.json exists but could not be parsed.")
        counted = scorecard.get("total_attempts", 0)
        if doc_source == "report.json" and counted != len(findings):
            out.append(
                f"report.json lists {len(findings)} finding(s) but its scorecard counts {counted} "
                "attempt(s). The reporter's findings list is written by the LLM and can drop items. "
                "findings.json was not written for this run, so the list may be incomplete."
            )
        return out
