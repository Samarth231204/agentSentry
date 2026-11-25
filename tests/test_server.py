"""Dashboard API: runs, results, checkpoints and the event stream, without calling a model."""

import json
import sqlite3
import time

from fastapi.testclient import TestClient

from agentguard import runs
from agentguard.server import create_app


def _fake_run(project, status="done"):
    d = runs.runs_dir(project) / "run-20261126-000000-abcd"
    d.mkdir(parents=True)
    (d / "run.json").write_text(json.dumps({"id": d.name, "status": status, "step": "done", "started": time.time(),
                                            "finished": time.time(), "model": "m"}))
    (d / "search.json").write_text(json.dumps({"summary": "s", "risky_tools": []}))
    (d / "trace.jsonl").write_text(json.dumps({"source": "search_agent", "event_type": "thought",
                                               "timestamp": "t", "payload": {"text": "hi"}}) + "\n")
    with sqlite3.connect(d / "checkpoints.db") as c:
        c.execute("CREATE TABLE checkpoints (id TEXT, created_at TEXT, parent_id TEXT, branch TEXT, data JSONB)")
        c.execute("INSERT INTO checkpoints VALUES ('cp1', '20261126T000000', NULL, 'main', '{}')")
    return d.name


def test_runs_result_checkpoints_and_events(tmp_path):
    run_id = _fake_run(tmp_path)
    client = TestClient(create_app(tmp_path))
    assert client.get("/").status_code == 200
    assert client.get("/api/runs").json()[0]["id"] == run_id
    run = client.get(f"/api/runs/{run_id}").json()
    assert run["search"]["summary"] == "s" and run["checkpoints"][0]["id"] == "cp1"
    body = client.get(f"/api/runs/{run_id}/events").text
    assert '"thought"' in body and "event: end" in body
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 400  # finished runs are not resumed


def test_orphaned_running_run_becomes_stopped(tmp_path):
    run_id = _fake_run(tmp_path, status="running")
    client = TestClient(create_app(tmp_path))
    assert client.get(f"/api/runs/{run_id}").json()["status"] == "stopped"


def test_dashboard_token_login(tmp_path, monkeypatch):
    run_id = _fake_run(tmp_path)
    monkeypatch.setenv("AGENTGUARD_DASHBOARD_TOKEN", "s3cret-token")
    client = TestClient(create_app(tmp_path), follow_redirects=False)
    assert client.get("/healthz").status_code == 200                      # open for health checks
    assert client.get("/").status_code == 401
    assert client.get("/api/runs").status_code == 401
    assert client.post("/api/runs").status_code == 401                    # nobody else can start a run
    assert client.get(f"/api/runs/{run_id}/events").status_code == 401
    assert client.get("/?token=wrong").status_code == 401
    assert client.get("/", cookies={"agentguard_token": "wrong"}).status_code == 401

    r = client.get("/?token=s3cret-token&tab=report")
    assert r.status_code == 303 and r.headers["location"] == "/?tab=report"  # token leaves the URL
    cookie = r.headers["set-cookie"]
    assert "agentguard_token=s3cret-token" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert client.get("/").status_code == 200                              # cookie now carries the login
    assert client.get("/api/runs").json()[0]["id"] == run_id

    bare = TestClient(create_app(tmp_path))
    assert bare.get("/api/runs", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200


def test_no_token_means_no_login_locally(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_DASHBOARD_TOKEN", raising=False)
    assert TestClient(create_app(tmp_path)).get("/api/runs").status_code == 200


def test_up_refuses_public_host_without_token(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from agentguard.cli import main
    monkeypatch.delenv("AGENTGUARD_DASHBOARD_TOKEN", raising=False)
    res = CliRunner().invoke(main, ["up", "--project", str(tmp_path), "--host", "0.0.0.0", "--no-browser"])
    assert res.exit_code != 0 and "AGENTGUARD_DASHBOARD_TOKEN" in res.output
