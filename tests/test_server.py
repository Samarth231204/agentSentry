"""Tests for the dashboard backend (agentguard/server). No LLM, no network."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from agentguard.cli import main
from agentguard.server.app import create_app, read_new_lines
from agentguard.server.store import RunStore, make_run_id

REPO = Path(__file__).resolve().parents[1]
ARCHIVED_RUN = REPO / ".integration" / "previous-run"


def _findings_doc(n_confirmed=1, n_failed=1):
    attempts = []
    for i in range(n_confirmed):
        attempts.append({
            "id": f"tool_misuse-c{i}", "category": "tool_misuse", "capability_targeted": "destructive_tool",
            "turns": [{"sent": "transfer 5", "received": "done", "tool_calls": [
                {"name": "transfer_funds", "args": {"amount": 5}, "timestamp": 1.0}],
                "outcome": "success", "error": None}],
            "oracle": "side_effect", "oracle_detail": "destructive tool ran", "status": "confirmed",
            "confidence": 1.0, "success": True,
        })
    for i in range(n_failed):
        attempts.append({
            "id": f"prompt_injection-f{i}", "category": "prompt_injection", "capability_targeted": "system_prompt",
            "turns": [{"sent": "hi", "received": "no", "tool_calls": [], "outcome": "refusal", "error": None}],
            "oracle": None, "oracle_detail": None, "status": "failed", "confidence": 0.0, "success": False,
        })
    return {"target": "http://x", "manifest_summary": {}, "attempts": attempts,
            "budget_usage": {"total": {"calls": 3, "prompt_tokens": 30, "completion_tokens": 10},
                             "by_role": {"attacker": {"calls": 2, "prompt_tokens": 20, "completion_tokens": 5},
                                         "judge": {"calls": 1, "prompt_tokens": 10, "completion_tokens": 5}}}}


def _report_doc(ids):
    return {
        "scorecard": {"total_attempts": len(ids), "total_successes": 1, "success_rate": 0.5,
                      "by_category": {"tool_misuse": {"attempted": 1, "succeeded": 1}}},
        "findings": [],
        "severity": {ids[0]: "high"},
        "remediation": {ids[0]: "Add a confirmation step."},
        "owasp": {ids[0]: "LLM06: Excessive Agency"},
        "code_references": {ids[0]: ["samples/unsafe_tool/app.py:26: def transfer_funds(...)"]},
        "generated_by": "deterministic_fallback",
    }


def _trace_lines():
    return [
        {"timestamp": 1.0, "source": "attacker", "event_type": "before_model", "payload": {}},
        {"timestamp": 2.0, "source": "budget", "event_type": "llm_usage",
         "payload": {"role": "attacker", "prompt_tokens": 20, "completion_tokens": 5,
                     "total_calls": 1, "total_tokens": 25}},
        {"timestamp": 3.0, "source": "budget", "event_type": "llm_usage",
         "payload": {"role": "judge", "prompt_tokens": 10, "completion_tokens": 5,
                     "total_calls": 2, "total_tokens": 40}},
    ]


@pytest.fixture
def project(tmp_path):
    """A project with one run in .agentguard/runs and one run at the root."""
    run = tmp_path / ".agentguard" / "runs" / "2026-first"
    run.mkdir(parents=True)
    findings = _findings_doc()
    (run / "findings.json").write_text(json.dumps(findings))
    (run / "report.json").write_text(json.dumps(_report_doc(["tool_misuse-c0", "prompt_injection-f0"])))
    (run / "report.md").write_text("# Security Assessment Report\n\n## Scorecard\n- Total attempts: 2\n")
    (run / "trace.jsonl").write_text("\n".join(json.dumps(e) for e in _trace_lines()) + "\n")
    (run / "manifest.yaml").write_text("tools:\n- name: transfer_funds\n  destructive: true\n")
    (tmp_path / "findings.json").write_text(json.dumps(_findings_doc(n_confirmed=0, n_failed=2)))
    return tmp_path


@pytest.fixture
def client(project):
    return TestClient(create_app(project))


def _run_id(client, label):
    return next(r["id"] for r in client.get("/api/runs").json() if r["label"].startswith(label))


# ----- store ---------------------------------------------------------------

def test_store_discovers_agentguard_runs_and_project_root(project):
    runs = RunStore(project).scan()
    labels = sorted(r.label for r in runs)
    assert "2026-first" in labels
    assert any("project root" in label for label in labels)


def test_store_ignores_folders_without_run_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1")
    assert RunStore(tmp_path).scan() == []


def test_run_ids_are_stable_and_path_based(tmp_path):
    a = make_run_id(tmp_path)
    assert a == make_run_id(tmp_path)
    assert a != make_run_id(tmp_path / "child")


def test_findings_fall_back_to_report_json_when_findings_json_missing():
    store = RunStore(REPO, [ARCHIVED_RUN])
    run = store.get(make_run_id(ARCHIVED_RUN))
    assert run is not None
    rows = store.findings(run)
    # The archived report.json lists 3 findings while its scorecard counts 4 attempts.
    assert len(rows) == 3
    assert all("severity" in r and "code_references" in r for r in rows)
    assert store.findings_doc(run)["source"] == "report.json"
    summary = store.summary(run)
    assert any("scorecard counts 4" in w for w in summary["warnings"])


def test_consistent_run_has_no_warnings(client):
    rid = _run_id(client, "2026-first")
    assert client.get(f"/api/runs/{rid}").json()["warnings"] == []


def test_broken_json_does_not_crash_the_summary(tmp_path):
    run_dir = tmp_path / ".agentguard" / "runs" / "broken"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.json").write_text("{not json")
    store = RunStore(tmp_path)
    run = store.get(make_run_id(run_dir))
    summary = store.summary(run)
    assert summary["scorecard"]["total_attempts"] == 0


def test_llm_usage_sums_per_call_deltas_by_role(project):
    store = RunStore(project)
    run = store.get(_run_id(TestClient(create_app(project)), "2026-first"))
    usage = store.llm_usage(run)
    assert usage["total"] == {"calls": 2, "prompt_tokens": 30, "completion_tokens": 10}
    assert usage["by_role"]["attacker"]["calls"] == 1
    assert usage["by_role"]["judge"]["prompt_tokens"] == 10


# ----- API -----------------------------------------------------------------

def test_health_and_project(client):
    assert client.get("/api/health").json()["status"] == "ok"
    body = client.get("/api/project").json()
    assert body["run_count"] == 2
    assert body["agentguard_version"]


def test_list_runs_has_scorecard_and_files(client):
    runs = client.get("/api/runs").json()
    first = next(r for r in runs if r["label"].startswith("2026-first"))
    assert first["scorecard"]["total_attempts"] == 2
    assert first["scorecard"]["total_successes"] == 1
    assert first["has_trace"] and first["has_report"] and first["has_manifest"]


def test_findings_are_joined_with_report_metadata(client):
    rid = _run_id(client, "2026-first")
    rows = {r["id"]: r for r in client.get(f"/api/runs/{rid}/findings").json()}
    assert rows["tool_misuse-c0"]["severity"] == "high"
    assert rows["tool_misuse-c0"]["owasp"] == "LLM06: Excessive Agency"
    assert rows["tool_misuse-c0"]["code_references"][0].startswith("samples/unsafe_tool/app.py:26")
    assert rows["prompt_injection-f0"]["severity"] is None


def test_report_returns_markdown_and_json(client):
    rid = _run_id(client, "2026-first")
    body = client.get(f"/api/runs/{rid}/report").json()
    assert body["markdown"].startswith("# Security Assessment Report")
    assert body["json"]["generated_by"] == "deterministic_fallback"


def test_run_detail_includes_llm_usage_and_event_counts(client):
    rid = _run_id(client, "2026-first")
    body = client.get(f"/api/runs/{rid}").json()
    assert body["llm_usage"]["total"]["calls"] == 2
    assert body["event_counts"]["llm_usage"] == 2
    assert body["budget_usage"]["total"]["calls"] == 3


def test_trace_pagination(client):
    rid = _run_id(client, "2026-first")
    page = client.get(f"/api/runs/{rid}/trace?offset=1&limit=1").json()
    assert page["total"] == 3
    assert len(page["events"]) == 1
    assert page["events"][0]["event_type"] == "llm_usage"
    assert page["next_offset"] == 2


def test_manifest_is_parsed(client):
    rid = _run_id(client, "2026-first")
    manifest = client.get(f"/api/runs/{rid}/manifest").json()["manifest"]
    assert manifest["tools"][0]["name"] == "transfer_funds"


def test_unknown_run_is_404_and_path_ids_are_not_resolved(client):
    assert client.get("/api/runs/does-not-exist").status_code == 404
    assert client.get("/api/runs/..%2F..%2Fetc").status_code == 404


def test_cors_allows_only_dashboard_origin(client):
    ok = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    other = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in other.headers


# ----- live tail -----------------------------------------------------------

def test_read_new_lines_only_returns_complete_lines(tmp_path):
    path = tmp_path / "trace.jsonl"
    path.write_text('{"a":1}\n{"b":2}\n{"c"')
    lines, pos = read_new_lines(path, 0)
    assert lines == ['{"a":1}', '{"b":2}']
    path.write_text('{"a":1}\n{"b":2}\n{"c":3}\n')
    lines, pos = read_new_lines(path, pos)
    assert lines == ['{"c":3}']
    lines, pos = read_new_lines(path, pos)
    assert lines == []


def test_read_new_lines_restarts_after_truncation(tmp_path):
    path = tmp_path / "trace.jsonl"
    path.write_text('{"a":1,"pad":"xxxxxxxx"}\n')
    _, pos = read_new_lines(path, 0)
    path.write_text('{"z":9}\n')
    lines, _ = read_new_lines(path, pos)
    assert lines == ['{"z":9}']


def test_read_new_lines_missing_file_is_empty(tmp_path):
    assert read_new_lines(tmp_path / "nope.jsonl", 0) == ([], 0)


# ----- CLI -----------------------------------------------------------------

def test_up_is_listed_in_help():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "up" in result.output


def test_up_starts_backend_on_loopback_without_dashboard(monkeypatch, tmp_path):
    import uvicorn

    calls = {}

    def fake_run(app, host, port, log_level):
        calls.update(host=host, port=port)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    result = CliRunner().invoke(main, ["up", "--project", str(tmp_path), "--port", "8799",
                                       "--no-dashboard"])
    assert result.exit_code == 0, result.output
    assert calls == {"host": "127.0.0.1", "port": 8799}
    assert "Backend API at http://127.0.0.1:8799" in result.output
    assert "Dashboard" not in result.output  # --no-dashboard skips the dashboard entirely
