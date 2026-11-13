"""Live progress and demo-run labelling used by the dashboard.

Regression for "stuck in attack mode": the attack phase used to run for minutes with
no detail, and the mock run slept between categories. These tests pin the progress
data the status endpoint reports and the demo flag the run list shows.
"""

import json
from pathlib import Path
from types import SimpleNamespace

from agentguard.server.runner import RunHandle, RunManager, RunSpec
from agentguard.server.store import RunStore


class _NoEmit:
    """Stands in for RunManager.self where only the event emitter is needed."""

    def _emit(self, *args, **kwargs):
        return None


def _event(payload: dict):
    return SimpleNamespace(event_type="attack_progress", payload=payload)


def _handle(tmp_path: Path) -> RunHandle:
    return RunHandle(store_id="run-test-00000000", run_dir=tmp_path, spec=RunSpec(mock=True))


def test_attack_progress_is_reported_in_status(tmp_path):
    h = _handle(tmp_path)
    RunManager._track_progress(None, h, _event({
        "category": "prompt_injection", "index": 1, "total": 4, "state": "running", "attempts_so_far": 0}))
    status = h.as_dict()
    assert status["progress"]["attack"]["category"] == "prompt_injection"
    assert status["progress"]["attack"]["index"] == 1
    assert status["progress"]["attack"]["total"] == 4
    assert status["progress"]["attack"]["state"] == "running"


def test_progress_is_cleared_when_a_phase_finishes(tmp_path):
    h = _handle(tmp_path)
    RunManager._track_progress(None, h, _event({"category": "tool_misuse", "index": 3, "total": 4, "state": "done"}))
    assert h.progress
    RunManager._phase(_NoEmit(), h, "attack", "done")
    assert h.progress == {}


def test_other_events_do_not_touch_progress(tmp_path):
    h = _handle(tmp_path)
    RunManager._track_progress(None, h, SimpleNamespace(event_type="before_model", payload={"x": 1}))
    assert h.progress == {}


def test_run_list_marks_demo_runs(tmp_path):
    project = tmp_path / "project"
    run_dir = project / ".agentguard" / "runs" / "run-demo"
    run_dir.mkdir(parents=True)
    (run_dir / "trace.jsonl").write_text(
        json.dumps({"source": "runner", "event_type": "run_started", "payload": {"mock": True}}) + "\n",
        encoding="utf-8",
    )
    (run_dir / "findings.json").write_text(json.dumps({"attempts": []}), encoding="utf-8")
    store = RunStore(project)
    summaries = {r["id"]: r for r in (store.summary(run) for run in store.scan())}
    demo_id = next(rid for rid in summaries if rid.startswith("run-demo"))
    assert summaries[demo_id]["mock"] is True


def test_run_list_does_not_mark_real_runs_as_demo(tmp_path):
    project = tmp_path / "project"
    run_dir = project / ".agentguard" / "runs" / "run-real"
    run_dir.mkdir(parents=True)
    (run_dir / "trace.jsonl").write_text(
        json.dumps({"source": "runner", "event_type": "run_started", "payload": {"mock": False}}) + "\n",
        encoding="utf-8",
    )
    (run_dir / "findings.json").write_text(json.dumps({"attempts": []}), encoding="utf-8")
    store = RunStore(project)
    run = next(r for r in store.scan() if r.id.startswith("run-real"))
    assert store.summary(run)["mock"] is False


def test_onboarding_is_not_done_until_completed(tmp_path):
    from fastapi.testclient import TestClient

    from agentguard.server.app import create_app

    client = TestClient(create_app(tmp_path))
    assert client.get("/api/onboarding").json() == {"done": False}
    assert client.post("/api/onboarding/complete").json() == {"done": True}
    assert client.get("/api/onboarding").json() == {"done": True}
    assert (tmp_path / ".agentguard" / "onboarding.json").is_file()


def test_run_detail_sees_files_written_after_first_scan(tmp_path):
    """Regression: the run page showed 'No findings.json' for a run that finished after the list was first read."""
    project = tmp_path / "project"
    run_dir = project / ".agentguard" / "runs" / "run-late"
    run_dir.mkdir(parents=True)
    (run_dir / "trace.jsonl").write_text("", encoding="utf-8")
    store = RunStore(project)
    store.scan()  # the list is read while the run is still running
    (run_dir / "findings.json").write_text(json.dumps({"attempts": []}), encoding="utf-8")
    run = store.get(next(r.id for r in store.scan() if r.id.startswith("run-late")))
    assert "findings.json" in run.files
    assert store.findings_doc(run)["source"] == "findings.json"
