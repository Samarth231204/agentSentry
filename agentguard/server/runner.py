"""Runs started from the dashboard.

Automatic mode (default): discover -> plan (review) -> instrument -> target ->
scan -> attack -> report. The user's code is never edited; the approved plan is
applied by an import hook inside a generated target app.

Advanced mode (target_app given): the user's own ASGI app with @expose/@watch,
as in Phase 2. Discovery, planning and instrumentation are skipped.

One run at a time. Every run has its own folder under .agentguard/runs/ with
trace.jsonl, discovery.json, plan.json, manifest.yaml, findings.json,
report.md/json, and target.log. Phase changes are trace events (run_phase).
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
from agentguard.config import set_config
from agentguard.discovery import discover
from agentguard.discovery.agent import resolve_ambiguous
from agentguard.discovery.candidates import AUTO, DiscoveryResult
from agentguard.discovery.plan import InstrumentationPlan, apply_user_edits, build_plan, manifest_from_plan
from agentguard.events import JSONLFileSink, get_event_bus
from agentguard.instrument.target import TARGET_MODULE, write_target
from agentguard.llm_mock import MOCK_ENV
from agentguard.mcp.semgrep import scan_sinks
from agentguard.logging import get_logger
from agentguard.manifest import Manifest, synthesize
from agentguard.reporters import generate_report
from agentguard.schemas import TargetProfile, TraceEvent
from agentguard.server import keys as keystore
from agentguard.server.settings import effective_config
from agentguard.server.store import make_run_id
from agentguard.target import Target

logger = get_logger("runner")

PHASES = ("discover", "plan", "instrument", "target", "scan", "attack", "report")
APP_SPEC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}
PLAN_REVIEW_TIMEOUT = 1800.0
ADVANCED_SKIPPED = ("discover", "plan", "instrument")


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
    review_plan: bool = True
    replay_run_id: Optional[str] = None  # re-send the probes of an earlier run, in order
    use_a2a: bool = False  # run discovery, attacker and reporter as A2A agents

    @property
    def automatic(self) -> bool:
        return not self.target_app and not self.target_url

    def validate(self) -> "RunSpec":
        if self.target_app and self.target_url:
            raise RunRejected("Give either target_app or target_url, not both.")
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
        if self.replay_run_id is not None and not re.match(r"^[a-z0-9-]{3,80}$", self.replay_run_id):
            raise RunRejected("replay_run_id is not a valid run id.")
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
    awaiting_plan: bool = False
    discovery: Optional[DiscoveryResult] = None
    plan: Optional[InstrumentationPlan] = None
    plan_gate: threading.Event = field(default_factory=threading.Event)
    loop: Optional[asyncio.AbstractEventLoop] = None
    task: Optional[asyncio.Future] = None
    target_proc: Optional[subprocess.Popen] = None
    thread: Optional[threading.Thread] = None
    budget: Optional[BudgetTracker] = None
    profile: Optional[Any] = None
    replay: Optional[dict[str, list[str]]] = None
    progress: dict[str, Any] = field(default_factory=dict)  # live detail for the current phase

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
            "awaiting_plan": self.awaiting_plan,
            "automatic": self.spec.automatic,
            "transport": "a2a" if self.spec.use_a2a else "in_process",
            "mock": self.spec.mock,
            "progress": dict(self.progress),
        }


def package_parent() -> str:
    """The folder that contains the real `agentguard` package. Put first on sys.path for every
    AgentGuard subprocess, so a project folder that happens to be called `agentguard` (for example a
    clone) is never mistaken for the package (a namespace package without __init__.py)."""
    import agentguard as _pkg
    return str(Path(_pkg.__file__).resolve().parents[1])


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
        handle.plan_gate.set()  # wake a run that is waiting for plan review
        loop, task = handle.loop, handle.task
        if loop is not None and task is not None:
            loop.call_soon_threadsafe(task.cancel)
        return handle

    def approve_plan(self, run_id: str, edits: list[dict[str, Any]]) -> RunHandle:
        handle = self._runs.get(run_id)
        if handle is None:
            raise KeyError(run_id)
        if not handle.awaiting_plan or handle.plan is None or handle.discovery is None:
            raise RunRejected("This run is not waiting for plan review.")
        handle.plan = apply_user_edits(handle.plan, edits, handle.discovery)
        handle.plan.save(handle.run_dir / "plan.json")
        handle.plan_gate.set()
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

    def _track_progress(self, h: RunHandle, event: Any) -> None:
        """Keeps the live detail (attack category, attempts so far) that the status endpoint reports."""
        if getattr(event, "event_type", None) == "attack_progress":
            payload = dict(event.payload)
            h.progress = {
                "attack": {
                    "category": payload.get("category"),
                    "index": payload.get("index"),
                    "total": payload.get("total"),
                    "state": payload.get("state"),
                    "attempts_so_far": payload.get("attempts_so_far"),
                }
            }

    def _phase(self, h: RunHandle, phase: str, state: str) -> None:
        h.phase = phase
        h.phases[phase] = state
        if state in ("done", "failed", "cancelled", "skipped"):
            h.progress = {}
        self._emit("run_phase", phase=phase, state=state)

    def _redact(self, text: str) -> str:
        secrets = [os.environ[m["env"]] for m in keystore.PROVIDERS.values() if os.environ.get(m["env"])]
        return keystore.redact(text, secrets)

    def _check_cancel(self, h: RunHandle) -> None:
        if h.cancel_requested:
            raise _Cancelled()

    def _execute(self, h: RunHandle) -> None:
        bus = get_event_bus()
        sink = JSONLFileSink(h.run_dir / "trace.jsonl")
        bus.subscribe(sink)
        progress_sink = lambda event: self._track_progress(h, event)  # noqa: E731
        bus.subscribe(progress_sink)
        prior_mock = os.environ.get(MOCK_ENV)
        if h.spec.mock:
            os.environ[MOCK_ENV] = "1"
        try:
            keystore.apply_to_environ(self.project_root)
            cfg = effective_config(self.project_root)
            set_config(cfg)
            h.budget = BudgetTracker(BudgetConfig(
                max_calls_total=h.spec.max_llm_calls, max_tokens_total=h.spec.max_tokens))
            if h.spec.replay_run_id:
                h.replay = self._load_replay(h.spec.replay_run_id)
            h.state = "running"
            self._emit("run_started", run_id=h.store_id, mock=h.spec.mock, automatic=h.spec.automatic,
                       target_app=h.spec.target_app, target_url=h.spec.target_url)
            if h.spec.automatic:
                target_url, manifest = self._automatic_front(h, cfg)
            else:
                for phase in ADVANCED_SKIPPED:
                    h.phases[phase] = "skipped"
                target_url, manifest = self._advanced_front(h)
            self._check_cancel(h)
            self._run_attack_and_report(h, cfg, target_url, manifest)
            h.state = "done"
        except (_Cancelled, asyncio.CancelledError):
            h.state = "cancelled"
            self._mark_unfinished(h, "cancelled")
        except Exception as exc:  # noqa: BLE001 - shown to the user, keys redacted
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
            bus.unsubscribe(progress_sink)
            h.progress = {}
            if h.spec.mock:
                if prior_mock is None:
                    os.environ.pop(MOCK_ENV, None)
                else:
                    os.environ[MOCK_ENV] = prior_mock

    def _a2a_base(self) -> str:
        base = os.environ.get("AGENTGUARD_A2A_URL")
        if not base:
            raise RuntimeError("A2A is not available: the agents are served by `agentguard up`.")
        return base

    def _automatic_front(self, h: RunHandle, cfg) -> tuple[str, Manifest]:
        self._phase(h, "discover", "running")
        cache = self.project_root / ".agentguard" / "cache" / "discovery"
        if h.spec.use_a2a:
            from agentguard.a2a.client import call_agent
            from agentguard.discovery.candidates import Candidate
            data = call_agent(self._a2a_base(), "discovery", {})
            result = DiscoveryResult(
                root=data["root"], files_scanned=data["files_scanned"], frameworks=data["frameworks"],
                enrichment=data["enrichment"], errors=data["errors"],
                candidates=[Candidate(**c) for c in data["candidates"]],
            )
        else:
            enrich = scan_sinks if os.environ.get("AGENTGUARD_SEMGREP", "1") != "0" else None
            result = discover(self.project_root, cache_dir=cache, enrich=enrich)
        h.discovery = result
        (h.run_dir / "discovery.json").write_text(
            json.dumps({
                "root": result.root,
                "files_scanned": result.files_scanned,
                "frameworks": result.frameworks,
                "enrichment": result.enrichment,
                "errors": result.errors,
                "candidates": [vars(c) for c in result.candidates],
            }, indent=2), encoding="utf-8")
        self._emit("discovery_done", files=result.files_scanned, candidates=len(result.candidates),
                   frameworks=result.frameworks, enrichment=result.enrichment)
        self._check_cancel(h)
        self._phase(h, "discover", "done")

        self._phase(h, "plan", "running")
        ambiguous = [c for c in result.candidates if c.bucket == "ambiguous"]
        decisions = resolve_ambiguous(ambiguous, cfg.chat_model, budget=h.budget) if ambiguous else {}
        plan = build_plan(result, decisions)
        h.plan = plan
        plan.save(h.run_dir / "plan.json")
        self._emit("plan_built", items=len(plan.items), included=sum(1 for i in plan.items if i.include),
                   agent_decisions=len(decisions))
        errors = plan.validate(result)
        if errors:
            raise RuntimeError("invalid plan: " + "; ".join(errors))
        if h.spec.review_plan:
            h.awaiting_plan = True
            self._phase(h, "plan", "awaiting_review")
            h.plan_gate.wait(PLAN_REVIEW_TIMEOUT)
            h.awaiting_plan = False
            self._check_cancel(h)
            if not h.plan_gate.is_set():
                raise RuntimeError("plan review timed out")
            plan = h.plan
        self._phase(h, "plan", "done")
        h.profile = self._profile(plan, result)

        self._phase(h, "instrument", "running")
        write_target(h.run_dir, plan, self.project_root)
        self._emit("instrumented", items=[i.name for i in plan.items if i.include],
                   entrypoint=plan.entrypoint.name if plan.entrypoint else None)
        self._phase(h, "instrument", "done")

        self._phase(h, "target", "running")
        url = self._start_target(h, app=f"{TARGET_MODULE}:app",
                                 extra_path=str(h.run_dir))
        h.target_url = url
        self._check_cancel(h)
        self._phase(h, "target", "done")

        self._phase(h, "scan", "running")
        manifest = manifest_from_plan(plan)
        manifest.to_yaml(h.run_dir / "manifest.yaml")
        self._check_cancel(h)
        self._phase(h, "scan", "done")
        return url, manifest

    def _advanced_front(self, h: RunHandle) -> tuple[str, Manifest]:
        self._phase(h, "target", "running")
        url = self._start_target(h, app=h.spec.target_app, extra_path=None) if h.spec.target_app \
            else self._attach_target(h)
        h.target_url = url
        self._check_cancel(h)
        self._phase(h, "target", "done")

        self._phase(h, "scan", "running")
        manifest = synthesize(self.project_root, use_llm=not h.spec.mock)
        manifest.to_yaml(h.run_dir / "manifest.yaml")
        self._check_cancel(h)
        self._phase(h, "scan", "done")
        return url, manifest

    def _profile(self, plan, result) -> TargetProfile:
        """What the attacker may know: capabilities and the entrypoint's purpose. Never the system prompt."""
        entry = plan.entrypoint
        doc = ""
        if entry is not None:
            cand = next((c for c in result.candidates if c.id == entry.candidate_id), None)
            doc = cand.doc if cand else ""
        included = [i for i in plan.items if i.include]
        return TargetProfile(
            tools=[i.name for i in included if i.role == "watch"],
            has_rag=any(i.role == "watch_retrieval" for i in included),
            has_memory=any(i.role == "watch_memory" for i in included),
            purpose=doc or None,
            system_prompt_hint=None,
        )

    def _load_replay(self, run_id: str) -> dict[str, list[str]]:
        from agentguard.server.store import RunStore
        store = RunStore(self.project_root)
        run = store.get(run_id)
        if run is None or "findings.json" not in run.files and "report.json" not in run.files:
            raise RuntimeError(f"replay run {run_id} has no findings to replay")
        replay: dict[str, list[str]] = {}
        for attempt in store.findings_doc(run).get("attempts", []):
            for turn in attempt.get("turns", []):
                if turn.get("sent"):
                    replay.setdefault(attempt["category"], []).append(turn["sent"])
        return replay

    def _run_attack_and_report(self, h: RunHandle, cfg, url: str, manifest: Manifest) -> None:
        self._phase(h, "attack", "running")
        budget = h.budget
        probes = h.spec.max_probes or cfg.max_probes
        if h.spec.use_a2a:
            from agentguard.a2a.client import call_agent
            findings = call_agent(self._a2a_base(), "attacker", {
                "target_url": url,
                "manifest": {"tools": [vars(t) for t in manifest.tools], "rag": manifest.rag,
                             "memory": manifest.memory},
                "canaries": h.spec.canaries, "max_probes": probes,
                "max_llm_calls": h.spec.max_llm_calls, "max_tokens": h.spec.max_tokens,
                "profile": h.profile.model_dump() if h.profile else None,
                "replay": h.replay,
            })
        else:
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
        if h.spec.use_a2a:
            from agentguard.a2a.client import call_agent
            manifest_yaml = (h.run_dir / "manifest.yaml").read_text(encoding="utf-8")
            report = call_agent(self._a2a_base(), "reporter", {
                "findings": findings, "manifest_yaml": manifest_yaml, "mock": h.spec.mock})
            (h.run_dir / "report.md").write_text(report["markdown"], encoding="utf-8")
            (h.run_dir / "report.json").write_text(json.dumps(report["json"], indent=2), encoding="utf-8")
        else:
            generate_report(
                h.run_dir / "findings.json", h.run_dir / "report.md",
                manifest_path=h.run_dir / "manifest.yaml", project_path=self.project_root,
                model=cfg.reporter_model, use_llm=not h.spec.mock,
            )
        self._phase(h, "report", "done")

    def _mark_unfinished(self, h: RunHandle, state: str) -> None:
        for phase, value in list(h.phases.items()):
            if value in ("running", "awaiting_review"):
                h.phases[phase] = state
                self._emit("run_phase", phase=phase, state=state)

    def _attack(self, h: RunHandle, url: str, manifest: Manifest, budget: BudgetTracker, probes: int):
        loop = asyncio.new_event_loop()
        h.loop = loop
        try:
            task = loop.create_task(run_attack_suite(
                Target(url), manifest, canaries=h.spec.canaries,
                max_probes=probes, budget=budget, profile=h.profile, replay=h.replay,
            ))
            h.task = task
            if h.cancel_requested:
                task.cancel()
            return loop.run_until_complete(task)
        except asyncio.CancelledError:
            raise _Cancelled()
        finally:
            h.task = None
            h.loop = None
            loop.close()

    def _attach_target(self, h: RunHandle) -> str:
        url = h.spec.target_url.rstrip("/")
        self._wait_healthy(url, None, h.run_dir / "target.log", timeout=10)
        return url

    def _start_target(self, h: RunHandle, app: str, extra_path: Optional[str]) -> str:
        port = _free_port()
        url = f"http://127.0.0.1:{port}"
        paths = [p for p in [package_parent(), extra_path, str(self.project_root),
                             os.environ.get("PYTHONPATH", "")] if p]
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(paths)}
        with open(h.run_dir / "target.log", "w", encoding="utf-8") as log:
            proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", app,
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
