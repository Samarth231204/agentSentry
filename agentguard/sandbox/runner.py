"""Starts and talks to the sandbox process (harness.py) for one run.

The project is copied to <run>/sandbox/project first, so anything the agent writes to disk lands in
the copy. The process gets AgentGuard's key and target model; the project needs no key of its own.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

from agentguard.events import emit
from agentguard.schemas import SearchResult

IGNORE = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".agentguard", ".mypy_cache",
          ".pytest_cache", "build", "dist"}
# Tools whose effect is real-world are faked; read-only tools really run (inside the copy).
ACTING = re.compile(r"pay|transfer|send|email|mail|post|upload|delete|remove|drop|cancel|grant|revoke|role|"
                    r"password|admin|exec|command|shell|run|sql|query|write|update|insert|create|book|refund|"
                    r"charge|withdraw|deploy|webhook|notify", re.I)
TARGET_MODEL = "anthropic/claude-haiku-5-5"


# Memory and note tools only change the app's own state, which lives inside the sandbox; they must
# really run, or memory attacks could never be observed.
IN_APP_STATE = re.compile(r"memor|remember|recall|note|history|cache|session", re.I)


def should_intercept(name: str, capability: str, risk: str) -> bool:
    if IN_APP_STATE.search(name):
        return False
    return risk in ("critical", "high") and bool(ACTING.search(name) or ACTING.search(capability))


def _ignore(src: str, names: list[str]) -> set[str]:
    here = Path(src)
    return {n for n in names if n in IGNORE or (here / n / "agentguard" / "scanner.py").exists()}


class SandboxError(RuntimeError):
    pass


class Sandbox:
    def __init__(self, project: str | Path, search: SearchResult, run_dir: str | Path, timeout: float = 120.0):
        self.project = Path(project).resolve()
        self.search = search
        self.dir = Path(run_dir) / "sandbox"
        self.timeout = timeout
        self.proc: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()
        self.patched: list[str] = []

    @property
    def copy(self) -> Path:
        return self.dir / "project"

    def spec(self) -> dict:
        tools = [{"file": t.file, "name": t.name, "risk": t.risk,
                  "intercept": should_intercept(t.name, t.capability, t.risk)} for t in self.search.risky_tools]
        return {"project_root": str(self.copy), "target_model": os.environ.get("AGENTGUARD_TARGET_MODEL", TARGET_MODEL),
                "entry_points": [e.model_dump() for e in self.search.entry_points], "tools": tools}

    def start(self) -> None:
        self.stop()
        if self.copy.exists():
            shutil.rmtree(self.copy)
        shutil.copytree(self.project, self.copy, ignore=_ignore)
        spec_path = self.dir / "spec.json"
        spec_path.write_text(json.dumps(self.spec(), indent=2))
        repo = str(Path(__file__).resolve().parents[2])
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([repo, os.environ.get("PYTHONPATH", "")]),
               "PYTHONUNBUFFERED": "1"}
        self.proc = subprocess.Popen([sys.executable, "-m", "agentguard.sandbox.harness", str(spec_path)],
                                     cwd=self.copy, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=open(self.dir / "stderr.log", "a"), text=True, bufsize=1)
        ready = self._read(30)
        if not ready.get("ready"):
            raise SandboxError(f"sandbox did not start: {ready}")
        emit("sandbox", "sandbox_started", copy=str(self.copy), pid=self.proc.pid,
             intercepted=[t["name"] for t in self.spec()["tools"] if t["intercept"]],
             entry_points=[e.id for e in self.search.entry_points])

    def _read(self, timeout: float) -> dict:
        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        if not sel.select(timeout):
            self.stop()
            raise SandboxError(f"the project did not answer within {timeout:.0f}s")
        line = self.proc.stdout.readline()
        if not line:
            err = (self.dir / "stderr.log").read_text()[-1500:] if (self.dir / "stderr.log").exists() else ""
            self.stop()
            raise SandboxError("the sandbox process exited. " + err)
        return json.loads(line)

    def invoke(self, entry: str, message: str, session: str = "s1") -> dict:
        with self.lock:
            if self.proc is None or self.proc.poll() is not None:
                self.start()
            self.proc.stdin.write(json.dumps({"op": "invoke", "entry": entry, "message": message, "session": session}) + "\n")
            self.proc.stdin.flush()
            return self._read(self.timeout)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc = None
