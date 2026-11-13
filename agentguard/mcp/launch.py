"""Starts AgentGuard's two MCP servers for one project, and checks that they answer."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agentguard.mcp.client import MCPError, ServerSpec, list_tools

SERVERS = {
    "codeintel": {"module": "agentguard.mcp.codeintel_server", "port": 8790, "project": True,
                  "env": "AGENTGUARD_CODEINTEL_URL"},
    "security-kb": {"module": "agentguard.mcp.security_kb_server", "port": 8791, "project": False,
                    "env": "AGENTGUARD_SECURITY_KB_URL"},
}


@dataclass
class RunningServer:
    name: str
    url: str
    proc: subprocess.Popen
    tools: list[str]


def free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return sock.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free port")


def start_server(name: str, project: Path, port: Optional[int] = None, wait: float = 60.0) -> RunningServer:
    meta = SERVERS[name]
    chosen = free_port(port or meta["port"])
    cmd = [sys.executable, "-m", meta["module"], "--port", str(chosen)]
    if meta["project"]:
        cmd += ["--project", str(Path(project).resolve())]
    proc = subprocess.Popen(cmd, cwd=str(Path(project).resolve()), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True,
                            env={**os.environ, "PYTHONPATH": os.pathsep.join(
                                p for p in [os.environ.get("PYTHONPATH", "")] if p)})
    url = f"http://127.0.0.1:{chosen}/mcp"
    spec = ServerSpec(name=name, transport="http", url=url)
    deadline = time.time() + wait
    last: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} server exited early (code {proc.returncode})")
        try:
            tools = list_tools(spec, timeout=5)
            return RunningServer(name=name, url=url, proc=proc, tools=tools)
        except MCPError as exc:
            last = exc
            time.sleep(0.3)
    stop_server(proc)
    raise RuntimeError(f"{name} did not answer within {wait:.0f}s: {last}")


def stop_server(proc: subprocess.Popen) -> None:
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


def start_all(project: Path) -> list[RunningServer]:
    started: list[RunningServer] = []
    try:
        for name in SERVERS:
            started.append(start_server(name, project))
    except Exception:
        for server in started:
            stop_server(server.proc)
        raise
    for server in started:
        os.environ[SERVERS[server.name]["env"]] = server.url
    return started


def stop_all(servers: list[RunningServer]) -> None:
    for server in servers:
        stop_server(server.proc)
        os.environ.pop(SERVERS[server.name]["env"], None)
