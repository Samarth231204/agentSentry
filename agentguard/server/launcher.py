"""Starts the dashboard's Next.js dev server next to the backend (used by `agentguard up`)."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = REPO_ROOT / "dashboard"


def dashboard_status() -> tuple[bool, str]:
    """(ready, reason). Ready means npm is on PATH and dependencies are installed."""
    if not DASHBOARD_DIR.is_dir():
        return False, f"dashboard folder not found at {DASHBOARD_DIR}"
    if shutil.which("npm") is None:
        return False, "npm is not installed (install Node.js 20+)"
    if not (DASHBOARD_DIR / "node_modules").is_dir():
        return False, "dependencies missing: run `cd dashboard && npm install` once"
    return True, "ok"


def start_dashboard(backend_url: str, port: int) -> Optional[subprocess.Popen]:
    ready, _ = dashboard_status()
    if not ready:
        return None
    env = {**os.environ, "NEXT_PUBLIC_AGENTGUARD_API": backend_url}
    # New session so the whole npm -> node process group can be stopped together.
    return subprocess.Popen(
        ["npm", "run", "dev", "--", "--port", str(port)],
        cwd=DASHBOARD_DIR, env=env, start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def stop_dashboard(proc: Optional[subprocess.Popen]) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
