"""Runs started from the dashboard: target -> scan -> attack -> report.

One run at a time. Each run gets its own folder under .agentguard/runs/ with
trace.jsonl, manifest.yaml, findings.json, report.md, report.json, and
target.log. Phase changes are trace events (run_phase), so the live view and
trace.jsonl show the same progress.

Target handling in this phase: either start an ASGI app ("module:attr") with
uvicorn from the project folder, or attach to an already running target on a
loopback URL. Automatic discovery and instrumentation come in Phase 3.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from agentguard.attackers import run_attack_suite
from agentguard.budget import BudgetConfig, BudgetTracker
from agentguard.events import JSONLFileSink, get_event_bus
from agentguard.llm_mock import MOCK_ENV
from agentguard.logging import get_logger
from agentguard.manifest import synthesize
from agentguard.reporters import generate_report
from agentguard.schemas import TraceEvent
from agentguard.server import keys as keystore
from agentguard.server.settings import effective_config
from agentguard.server.store import make_run_id
from agentguard.config import set_config
from agentguard.target import Target

logger = get_logger("runner")

PHASES = ("target", "scan", "attack", "report")
APP_SPEC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


class RunBusy(RuntimeError):
    pass


class RunRejected(ValueError):
    pass


class _Cancelled(Exception):
    pass


@dataclass
class RunSpec:
    target_app: Optional[str] = None
    target_url: Optional[str] = None
    canaries: list[str] = field(default_factory=list)
    max_probes: Optional[int] = None
    max_llm_calls: Optional[int] = None
    max_tokens: Optional[int] = None
    mock: bool = False

    def validate(self) -> "RunSpec":
        if bool(self.target_app) == bool(self.target_url):
            raise RunRejected("Give exactly one of target_app (module:attr) or target_url.")
        if self.target_app and not APP_SPEC_RE.match(self.target_app):
            raise RunRejected("target_app must look like 'module.path:attribute', for example app:app.")
        if self.target_url:
            parsed = urlparse(self.target_url)
            if parsed.scheme not in ("http", "https") or parsed.hostname not in LOOPBACK_HOSTS:
                raise RunRejected(
                    "target_url must be http(s) on localhost or 127.0.0.1 (remote targets are not supported yet).")
        if len(self.canaries) > 10 or any(len(c) > 200 for c in self.canaries):
            raise RunRejected("At most 10 canaries, each at most 200 characters.")
        if self.max_probes is not None and not 1 <= self.max_probes <= 50:
            raise RunRejected("max_probes must be between 1 and 50.")
        for name, value in (("max_llm_calls", self.max_llm_calls), ("max_tokens", self.max_tokens)):
            if value is not None and not 1 <= value <= 100_000_000:
                raise RunRejected(f"{name} is out of range.")
        return self


@dataclass
class RunHandle:
    store_id: str
    run_dir: Path
    spec: RunSpec
    state: str = "queued"  # queued | running | done | failed | cancelled
    phase: Optional[str] = None
    phases: dict[str, str] = field(default_factory=lambda: {p: "pending" for p in PHASES})
    error: Optional[str] = None
    started: float = field(default_factory=time.time)
    finished: Optional[float] = None
    target_url: Optional[str] = None
    cancel_requested: bool = False
    loop: Optional[asyncio.AbstractEventLoop] = None
    task: Optional[asyncio.Future] = None
    target_proc: Optional[subprocess.Popen] = None
    thread: Optional[threading.Thread] = None

    @property
    def active(self) -> bool:
        return self.state in ("queued", "running")

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.store_id,
            "state": self.state,
            "phase": self.phase,
            "phases": dict(self.phases),
            "error": self.error,
            "started": self.started,
            "finished": self.finished,
            "target_url": self.target_url,
            "cancel_requested": self.cancel_requested,
            "mock": self.spec.mock,
        }


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _kill_group(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


class RunManager:
    def __init__(self, project_root: Path, history_limit: int = 20) -> None:
        self.project_root = Path(project_root).resolve()
        self._lock = threading.Lock()
        self._runs: dict[str, RunHandle] = {}
        self._order: list[str] = []
        self._active: Optional[RunHandle] = None
        self._history_limit = history_limit

    # ----- public API -----------------------------------------------------

    def start(self, spec: RunSpec) -> RunHandle:
        spec.validate()
        with self._lock:
            if self._active is not None and self._active.active:
                raise RunBusy(
                    f"Run {self._active.store_id} is still {self._active.state}. Wait for it or cancel it.")
            run_name = f"run-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
            run_dir = self.project_root / ".agentguard" / "runs" / run_name
            run_dir.mkdir(parents=True, exist_ok=False)
            handle = RunHandle(store_id=make_run_id(run_dir), run_dir=run_dir, spec=spec)
            handle.thread = threading.Thread(target=self._execute, args=(handle,), daemon=True,
                                             name=f"agentguard-{run_name}")
            self._runs[handle.store_id] = handle
            self._order.append(handle.store_id)
            self._active = handle
            self._trim()
            handle.thread.start()
        return handle

    def get(self, run_id: str) -> Optional[RunHandle]:
        return self._runs.get(run_id)

    def active(self) -> Optional[RunHandle]:
        return self._active if self._active is not None and self._active.active else None

    def cancel(self, run_id: str) -> RunHandle:
        handle = self._runs.get(run_id)
        if handle is None:
            raise KeyError(run_id)
        if not handle.active:
            return handle
        handle.cancel_requested = True
        loop, task = handle.loop, handle.task
        if loop is not None and task is not None:
            loop.call_soon_threadsafe(task.cancel)
        return handle

    # ----- internals ------------------------------------------------------

    def _trim(self) -> None:
        while len(self._order) > self._history_limit:
            old = self._order[0]
            if self._runs.get(old) and self._runs[old].active:
                break
            self._order.pop(0)
            self._runs.pop(old, None)

    def _emit(self, event_type: str, **payload: Any) -> None:
        get_event_bus().emit(TraceEvent(source="runner", event_type=event_type, payload=payload))

    def _phase(self, h: RunHandle, phase: str, state: str) -> None:
        h.phase = phase
        h.phases[phase] = state
        self._emit("run_phase", phase=phase, state=state)

    def _redact(self, text: str) -> str:
        secrets = [os.environ[m["env"]] for m in keystore.PROVIDERS.values() if os.environ.get(m["env"])]
        return keystore.redact(text, secrets)

    def _execute(self, h: RunHandle) -> None:
        bus = get_event_bus()
        sink = JSONLFileSink(h.run_dir / "trace.jsonl")
        bus.subscribe(sink)
        prior_mock = os.environ.get(MOCK_ENV)
        if h.spec.mock:
            os.environ[MOCK_ENV] = "1"
        try:
            keystore.apply_to_environ(self.project_root)
            cfg = effective_config(self.project_root)
            set_config(cfg)
            h.state = "running"
            self._emit("run_started", run_id=h.store_id, mock=h.spec.mock,
                       target_app=h.spec.target_app, target_url=h.spec.target_url)

            self._phase(h, "target", "running")
            url = self._start_target(h)
            h.target_url = url
            self._check_cancel(h)
            self._phase(h, "target", "done")

            self._phase(h, "scan", "running")
            manifest = synthesize(self.project_root, use_llm=not h.spec.mock)
            manifest_path = h.run_dir / "manifest.yaml"
            manifest.to_yaml(manifest_path)
            self._check_cancel(h)
            self._phase(h, "scan", "done")

            self._phase(h, "attack", "running")
            budget = BudgetTracker(BudgetConfig(
                max_calls_total=h.spec.max_llm_calls, max_tokens_total=h.spec.max_tokens))
            probes = h.spec.max_probes or cfg.max_probes
            sink_obj = self._attack(h, url, manifest, budget, probes)
            findings = {
                "target": sink_obj.target_desc,
                "manifest_summary": sink_obj.manifest_summary,
                "attempts": sink_obj.session_state.get(
                    "findings", [a.model_dump(mode="json") for a in sink_obj.attempts]),
                "budget_usage": budget.usage_report(),
            }
            (h.run_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
            self._phase(h, "attack", "done")

            self._check_cancel(h)
            self._phase(h, "report", "running")
            generate_report(
                h.run_dir / "findings.json", h.run_dir / "report.md",
                manifest_path=manifest_path, project_path=self.project_root,
                model=cfg.reporter_model, use_llm=not h.spec.mock,
            )
            self._phase(h, "report", "done")
            h.state = "done"
        except (_Cancelled, asyncio.CancelledError):
            h.state = "cancelled"
            self._mark_unfinished(h, "cancelled")
        except Exception as exc:  # noqa: BLE001 - shown to the user, with keys redacted
            h.state = "failed"
            h.error = self._redact(f"{type(exc).__name__}: {exc}")[:500]
            logger.exception("Run %s failed", h.store_id)
            self._mark_unfinished(h, "failed")
            self._emit("error", phase=h.phase, error=h.error)
        finally:
            if h.target_proc is not None:
                _kill_group(h.target_proc)
            h.finished = time.time()
            self._emit("run_finished", run_id=h.store_id, state=h.state, error=h.error)
            bus.unsubscribe(sink)
            if h.spec.mock:
                if prior_mock is None:
                    os.environ.pop(MOCK_ENV, None)
                else:
                    os.environ[MOCK_ENV] = prior_mock

    def _check_cancel(self, h: RunHandle) -> None:
        if h.cancel_requested:
            raise _Cancelled()

    def _mark_unfinished(self, h: RunHandle, state: str) -> None:
        for phase, value in list(h.phases.items()):
            if value == "running":
                h.phases[phase] = state
                self._emit("run_phase", phase=phase, state=state)

    def _attack(self, h: RunHandle, url: str, manifest: Any, budget: BudgetTracker, probes: int):
        loop = asyncio.new_event_loop()
        h.loop = loop
        try:
            task = loop.create_task(run_attack_suite(
                Target(url), manifest, canaries=h.spec.canaries,
                max_probes=probes, budget=budget,
            ))
            h.task = task
            if h.cancel_requested:
                task.cancel()
            return loop.run_until_complete(task)
        finally:
            h.task = None
            h.loop = None
            loop.close()

    def _start_target(self, h: RunHandle) -> str:
        if h.spec.target_url:
            url = h.spec.target_url.rstrip("/")
            self._wait_healthy(url, None, h.run_dir / "target.log", timeout=10)
            return url

        port = _free_port()
        url = f"http://127.0.0.1:{port}"
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(
            p for p in [str(self.project_root), os.environ.get("PYTHONPATH", "")] if p)}
        with open(h.run_dir / "target.log", "w", encoding="utf-8") as log:
            proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", h.spec.target_app,
                 "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
                cwd=self.project_root, env=env, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        h.target_proc = proc
        self._wait_healthy(url, proc, h.run_dir / "target.log", timeout=30)
        return url

    def _wait_healthy(self, url: str, proc: Optional[subprocess.Popen], log_path: Path, timeout: float) -> None:
        deadline = time.time() + timeout
        last_error = "no response yet"
        while time.time() < deadline:
            if proc is not None and proc.poll() is not None:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:] if log_path.exists() else ""
                raise RuntimeError(f"target process exited early (code {proc.returncode}). Log tail:\n{tail}")
            try:
                resp = httpx.get(f"{url}/health", timeout=1.0)
                if resp.status_code == 200:
                    if resp.json().get("entrypoint_registered"):
                        return
                    raise RuntimeError(
                        "target is up but has no @expose entrypoint registered. "
                        "Add @expose to the function that handles user input (see agentguard.adapter).")
                last_error = f"HTTP {resp.status_code}"
            except httpx.HTTPError as exc:
                last_error = type(exc).__name__
            time.sleep(0.3)
        raise RuntimeError(f"target at {url} did not become healthy within {timeout:.0f}s ({last_error})")
