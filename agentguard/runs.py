"""Runs live in <project>/.agentguard/runs/<run_id>/:

  run.json          status, timings, model, error
  scan.json         the deterministic scan
  search.json       the Search agent's result
  trace.jsonl       every event (thoughts, actions, observations, MCP calls)
  checkpoints.db    CrewAI checkpoints of the flow, crew and agent
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from agentguard.events import JSONLFileSink, emit, get_event_bus

_lock = threading.Lock()
_active: Optional[str] = None


def runs_dir(project: str | Path) -> Path:
    d = Path(project).resolve() / ".agentguard" / "runs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def new_run_id() -> str:
    return datetime.now().strftime("run-%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def _write(run_dir: Path, **fields: Any) -> dict:
    path = run_dir / "run.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    data.update(fields)
    path.write_text(json.dumps(data, indent=2))
    return data


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def list_runs(project: str | Path) -> list[dict]:
    out = []
    for d in sorted(runs_dir(project).iterdir(), reverse=True):
        meta = read_json(d / "run.json")
        if meta:
            out.append(meta)
    return out


def checkpoints(run_dir: Path) -> list[dict]:
    """The run's CrewAI checkpoints, newest first: id, time, and which entity (flow or crew) was saved."""
    import sqlite3

    db = run_dir / "checkpoints.db"
    if not db.exists():
        return []
    try:
        with sqlite3.connect(db) as conn:
            rows = conn.execute("SELECT id, created_at, parent_id FROM checkpoints ORDER BY created_at DESC, rowid DESC").fetchall()
    except sqlite3.Error:
        return []
    return [{"id": i, "created_at": c, "parent_id": p} for i, c, p in rows]


def get_run(project: str | Path, run_id: str) -> Optional[dict]:
    d = runs_dir(project) / Path(run_id).name
    meta = read_json(d / "run.json")
    if meta is None:
        return None
    return {**meta, "scan": read_json(d / "scan.json"), "search": read_json(d / "search.json"),
            "checkpoints": checkpoints(d)}


def mark_orphans(project: str | Path) -> None:
    """Runs left 'running' by a process that has exited are 'stopped' (and can be resumed)."""
    for d in runs_dir(project).iterdir():
        meta = read_json(d / "run.json")
        if meta and meta.get("status") == "running" and meta.get("id") != _active:
            _write(d, status="stopped")


def active_run() -> Optional[str]:
    return _active


def start_run(project: str | Path, background: bool = True, resume: Optional[str] = None) -> str:
    """Starts the search flow, or resumes run `resume` from its last checkpoint.
    One run at a time, because the trace sink is process-wide."""
    global _active
    from agentguard.llm import model_name

    with _lock:
        if _active:
            raise RuntimeError(f"run {_active} is still going")
        run_id = Path(resume).name if resume else new_run_id()
        _active = run_id
    run_dir = runs_dir(project) / run_id
    if resume:
        if not (run_dir / "run.json").exists():
            with _lock:
                _active = None
            raise RuntimeError(f"no run {run_id}")
        _write(run_dir, status="running", finished=None, error=None, resumed=time.time())
    else:
        run_dir.mkdir()
        _write(run_dir, id=run_id, project=str(Path(project).resolve()), model=model_name(),
               status="running", step="scan", started=time.time(), finished=None, error=None)

    def work() -> None:
        global _active
        sink = JSONLFileSink(run_dir / "trace.jsonl")
        bus = get_event_bus()
        bus.subscribe(sink)

        def track(event) -> None:  # keep run.json's step in sync for the dashboard
            if event.event_type == "step_started":
                _write(run_dir, step=event.payload.get("step"))
            elif event.event_type == "usage":
                _write(run_dir, usage=event.payload)
        bus.subscribe(track)
        try:
            from agentguard.agents.search import resume_search, run_search
            if resume:
                resume_search(run_dir)
            else:
                emit("flow", "run_started", run_id=run_id, project=str(project))
                run_search(project, run_dir)
            emit("flow", "run_done", run_id=run_id)
            _write(run_dir, status="done", step="done", finished=time.time())
        except BaseException as exc:  # noqa: BLE001  CrewAI's Rust serializer can raise a PanicException
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                _write(run_dir, status="stopped", finished=time.time())
                raise
            emit("flow", "error", error=f"{type(exc).__name__}: {exc}", trace=traceback.format_exc()[-2000:])
            _write(run_dir, status="failed", finished=time.time(), error=f"{type(exc).__name__}: {exc}")
        finally:
            bus.unsubscribe(sink)
            bus.unsubscribe(track)
            with _lock:
                _active = None

    if background:
        threading.Thread(target=work, daemon=True, name=f"agentguard-{run_id}").start()
    else:
        work()
    return run_id
