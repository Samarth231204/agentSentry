"""End-to-end run in mock mode against the unsafe_tool sample.

Starts a real uvicorn target, runs the real attack loop with a scripted
attacker model, and checks the files and trace the dashboard reads. Takes a
few seconds; no provider quota is used.
"""

import json
import time
from pathlib import Path

import pytest

from agentguard.server.runner import RunManager, RunSpec

REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "samples" / "unsafe_tool"


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A project folder that holds a copy of the sample app, so the test never writes into samples/."""
    import shutil
    dest = tmp_path / "unsafe_tool"
    shutil.copytree(SAMPLE, dest, ignore=shutil.ignore_patterns(".agentguard", "__pycache__"))
    monkeypatch.setenv("AGENTGUARD_CATEGORY_COOLDOWN", "0")
    monkeypatch.delenv("AGENTGUARD_LLM_MOCK", raising=False)
    return dest


def _wait(handle, timeout=120):
    handle.thread.join(timeout)
    assert not handle.thread.is_alive(), "run did not finish in time"


def test_mock_run_completes_and_writes_every_artifact(project):
    handle = RunManager(project).start(RunSpec(target_app="app:app", mock=True, max_probes=2))
    _wait(handle)

    assert handle.state == "done", handle.error
    assert handle.phases == {"target": "done", "scan": "done", "attack": "done", "report": "done"}
    names = {p.name for p in handle.run_dir.iterdir()}
    assert {"trace.jsonl", "manifest.yaml", "findings.json", "report.md", "report.json", "target.log"} <= names

    findings = json.loads((handle.run_dir / "findings.json").read_text())
    assert [a["category"] for a in findings["attempts"]] == [
        "prompt_injection", "secret_extraction", "tool_misuse", "data_exfiltration"]
    # Mock mode proves plumbing only: no real model ran, so nothing may be confirmed.
    assert all(a["status"] != "confirmed" for a in findings["attempts"])
    assert findings["budget_usage"]["total"]["calls"] >= 1

    report = json.loads((handle.run_dir / "report.json").read_text())
    assert report["generated_by"] == "deterministic_fallback"
    assert "Generated without an LLM" in (handle.run_dir / "report.md").read_text()


def test_trace_records_phases_and_run_lifecycle(project):
    handle = RunManager(project).start(RunSpec(target_app="app:app", mock=True, max_probes=1))
    _wait(handle)
    events = [json.loads(line) for line in (handle.run_dir / "trace.jsonl").read_text().splitlines()]
    phase_events = [(e["payload"]["phase"], e["payload"]["state"]) for e in events if e["event_type"] == "run_phase"]
    assert ("attack", "running") in phase_events and ("report", "done") in phase_events
    kinds = [e["event_type"] for e in events]
    assert kinds[0] == "run_started"
    assert kinds[-1] == "run_finished"


def test_mock_run_does_not_leak_the_mock_flag(project, monkeypatch):
    import os
    handle = RunManager(project).start(RunSpec(target_app="app:app", mock=True, max_probes=1))
    _wait(handle)
    assert "AGENTGUARD_LLM_MOCK" not in os.environ


def test_cancel_stops_the_run_and_the_target(project):
    manager = RunManager(project)
    handle = manager.start(RunSpec(target_app="app:app", mock=True, max_probes=2))
    deadline = time.time() + 60
    while handle.phase != "attack" and time.time() < deadline:
        time.sleep(0.1)
    manager.cancel(handle.store_id)
    _wait(handle)
    assert handle.state == "cancelled"
    assert handle.target_proc is not None and handle.target_proc.poll() is not None
    assert not (handle.run_dir / "report.md").exists()


def test_a_second_run_is_refused_while_one_is_active(project):
    from agentguard.server.runner import RunBusy
    manager = RunManager(project)
    first = manager.start(RunSpec(target_app="app:app", mock=True, max_probes=1))
    try:
        with pytest.raises(RunBusy):
            manager.start(RunSpec(target_app="app:app", mock=True, max_probes=1))
    finally:
        manager.cancel(first.store_id)
        _wait(first)


def test_target_without_expose_fails_with_a_clear_message(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_LLM_MOCK", raising=False)
    (tmp_path / "plain_app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/health')\ndef h():\n"
        "    return {'status': 'ok', 'entrypoint_registered': False}\n")
    handle = RunManager(tmp_path).start(RunSpec(target_app="plain_app:app", mock=True))
    _wait(handle)
    assert handle.state == "failed"
    assert "no @expose entrypoint" in handle.error
