"""A2A surface: agent cards, JSON-RPC errors, the three agents, and the security rules."""

import shutil
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from agentguard.a2a.client import A2AError, call_agent, fetch_card
from agentguard.a2a.protocol import AGENTS, build_request
from agentguard.server.app import create_app

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def project(tmp_path, monkeypatch):
    dest = tmp_path / "unsafe_tool"
    shutil.copytree(REPO / "samples/unsafe_tool", dest,
                    ignore=shutil.ignore_patterns(".agentguard", "__pycache__"))
    monkeypatch.setenv("AGENTGUARD_LLM_MOCK", "1")
    monkeypatch.setenv("AGENTGUARD_CATEGORY_COOLDOWN", "0")
    monkeypatch.setenv("AGENTGUARD_SEMGREP", "0")
    return dest


@pytest.fixture
def client(project):
    return TestClient(create_app(project))


@pytest.fixture
def route_calls_to(monkeypatch, client):
    """Sends the client's A2A posts through the in-process test client (no sockets)."""
    def fake_post(url, json=None, timeout=None, **_):
        from urllib.parse import urlparse
        return client.post(urlparse(url).path, json=json)
    monkeypatch.setattr(httpx, "post", fake_post)


def test_every_agent_publishes_a_card(client):
    for agent in AGENTS:
        card = client.get(f"/a2a/{agent}/.well-known/agent.json").json()
        assert card["name"].startswith("AgentGuard")
        assert card["url"].endswith(f"/a2a/{agent}")
        assert card["skills"] and card["capabilities"]["streaming"] is False


def test_unknown_agent_is_not_found(client):
    assert client.get("/a2a/nobody/.well-known/agent.json").status_code == 404
    assert client.post("/a2a/nobody", json={}).status_code == 404


def test_json_rpc_errors_use_standard_codes(client):
    bad_json = client.post("/a2a/discovery", content=b"{not json", headers={"Content-Type": "application/json"})
    assert bad_json.json()["error"]["code"] == -32700
    wrong_version = client.post("/a2a/discovery", json={"jsonrpc": "1.0", "id": 1})
    assert wrong_version.json()["error"]["code"] == -32600
    wrong_method = client.post("/a2a/discovery", json={"jsonrpc": "2.0", "id": 2, "method": "tasks/list"})
    assert wrong_method.json()["error"]["code"] == -32601
    no_params = client.post("/a2a/discovery", json={"jsonrpc": "2.0", "id": 3, "method": "message/send"})
    assert no_params.json()["error"]["code"] == -32602


def test_discovery_agent_returns_candidates_for_the_fixed_project(client, project):
    resp = client.post("/a2a/discovery", json=build_request("discovery", {}, request_id="d1")).json()
    assert resp["id"] == "d1"
    import json
    payload = json.loads(resp["result"]["parts"][0]["text"])
    assert payload["root"] == str(project.resolve())
    assert any(c["name"] == "run" and c["role"] == "expose" for c in payload["candidates"])


def test_clients_cannot_choose_the_project_folder(client, project):
    import json
    body = build_request("discovery", {"project_root": "/etc"}, request_id="d2")
    resp = client.post("/a2a/discovery", json=body).json()
    assert json.loads(resp["result"]["parts"][0]["text"])["root"] == str(project.resolve())


def test_attacker_refuses_non_loopback_targets(client):
    import json
    body = build_request("attacker", {"target_url": "https://example.com"}, request_id="a1")
    resp = client.post("/a2a/attacker", json=body).json()
    assert resp["error"]["code"] == -32602


def test_reporter_writes_only_under_the_project_a2a_folder(client, project):
    import json
    findings = {"target": {}, "manifest_summary": {}, "attempts": [], "budget_usage": {}}
    body = build_request("reporter", {"findings": findings, "mock": True}, request_id="r1")
    resp = client.post("/a2a/reporter", json=body).json()
    payload = json.loads(resp["result"]["parts"][0]["text"])
    assert payload["json"]["generated_by"] == "deterministic_fallback"
    assert (project / ".agentguard" / "a2a").exists()


def test_client_turns_a_json_rpc_error_into_an_exception(route_calls_to, project):
    with pytest.raises(A2AError):
        call_agent("http://testserver", "attacker", {"target_url": "https://example.com"})


def test_client_calls_discovery_and_records_the_call(route_calls_to, events_for_a2a):
    data = call_agent("http://testserver", "discovery", {})
    assert data["candidates"]
    calls = [e for e in events_for_a2a if e.event_type == "a2a_call"]
    assert calls and calls[0].payload["agent"] == "discovery" and calls[0].payload["ok"] is True


@pytest.fixture
def events_for_a2a():
    from agentguard.events import get_event_bus
    collected = []
    bus = get_event_bus()
    bus.subscribe(collected.append)
    yield collected
    bus.unsubscribe(collected.append)


def test_real_http_server_answers_a_card(project):
    import socket
    import uvicorn
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(project), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                card = fetch_card(base, "reporter")
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        assert card["url"] == f"{base}/a2a/reporter"
    finally:
        server.should_exit = True
        thread.join(10)


def test_a2a_run_end_to_end_on_a_decorator_free_copy(project, monkeypatch, tmp_path):
    """Automatic run where discovery, attacker and reporter all go over A2A (real HTTP)."""
    import socket
    import uvicorn
    from agentguard.server.runner import RunManager, RunSpec
    app_text = (project / "app.py").read_text()
    (project / "app.py").write_text(app_text.replace("@watch\n", "").replace("@expose\n", ""))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(project), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    monkeypatch.setenv("AGENTGUARD_A2A_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("AGENTGUARD_CATEGORY_COOLDOWN", "0")
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                fetch_card(f"http://127.0.0.1:{port}", "discovery")
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        handle = RunManager(project).start(RunSpec(mock=True, review_plan=False, max_probes=1, use_a2a=True))
        handle.thread.join(240)
        assert handle.state == "done", handle.error
        assert handle.as_dict()["transport"] == "a2a"
        import json
        trace = [json.loads(line) for line in (handle.run_dir / "trace.jsonl").read_text().splitlines()]
        agents_called = {e["payload"]["agent"] for e in trace if e["event_type"] == "a2a_call"}
        assert agents_called == {"discovery", "attacker", "reporter"}
        assert (handle.run_dir / "report.md").exists()
    finally:
        server.should_exit = True
        thread.join(10)
