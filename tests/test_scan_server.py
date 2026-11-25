"""Our MCP server's tools stay inside the project and never return secrets."""

import importlib

import pytest


@pytest.fixture
def server(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("def chat(message):\n    return client.messages.create(x=message)\n")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-secret\n")
    (tmp_path / "notes.md").write_text("call the tool\n")
    monkeypatch.setenv("AGENTGUARD_PROJECT", str(tmp_path))
    import agentguard.mcp.scan_server as s
    return importlib.reload(s)


def test_read_and_search(server):
    out = server.read_code("app.py", 1, 5)
    assert "1  def chat(message):" in out
    assert "app.py:2:" in server.search_code(r"messages\.create")
    assert "notes.md:1:" in server.search_code("tool")
    assert server.scan_project()["llm_calls"][0]["function"] == "chat"


def test_secrets_and_outside_paths_are_refused(server):
    assert "secrets file" in server.read_code(".env")
    assert "outside the project" in server.read_code("../../etc/passwd")
    assert "sk-secret" not in server.search_code("sk-")
    assert ".env" not in server.list_files()


def test_semgrep_rule_is_valid_json_yaml():
    import json
    from agentguard.mcp.semgrep import pattern_rule
    rule = json.loads(pattern_rule("$C.messages.create(...)"))
    assert rule["rules"][0]["pattern"] == "$C.messages.create(...)"
