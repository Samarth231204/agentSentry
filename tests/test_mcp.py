"""MCP layer: our two Streamable HTTP servers (real processes), tracing, Semgrep bridge, enrichment."""

import shutil
from pathlib import Path

import pytest

from agentguard.discovery import discover
from agentguard.discovery.candidates import Candidate
from agentguard.events import get_event_bus
from agentguard.mcp import launch
from agentguard.mcp.client import MCPError, ServerSpec, call, list_tools
from agentguard.mcp.semgrep import scan_sinks, semgrep_spec
from agentguard.server.store import RunStore

REPO = Path(__file__).resolve().parents[1]
HAS_SEMGREP = semgrep_spec()[0] is not None


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    dest = tmp_path_factory.mktemp("mcp_project") / "unsafe_tool"
    shutil.copytree(REPO / "samples/unsafe_tool", dest,
                    ignore=shutil.ignore_patterns(".agentguard", "__pycache__"))
    return dest


@pytest.fixture(scope="module")
def servers(project):
    started = launch.start_all(project)
    yield {s.name: s for s in started}
    launch.stop_all(started)


@pytest.fixture
def events():
    collected = []
    bus = get_event_bus()
    bus.subscribe(collected.append)
    yield collected
    bus.unsubscribe(collected.append)


def test_both_servers_answer_over_streamable_http(servers):
    assert servers["codeintel"].url.startswith("http://127.0.0.1:")
    assert {"search_code", "read_span", "callers", "list_routes"} <= set(servers["codeintel"].tools)
    assert {"owasp_lookup", "cwe_lookup", "remediation_template", "probe_library"} <= set(
        servers["security-kb"].tools)


def test_codeintel_search_finds_the_tool(servers, events):
    spec = ServerSpec(name="codeintel", transport="http", url=servers["codeintel"].url)
    result = call(spec, "search_code", {"query": "def transfer_funds"})
    assert not result["is_error"]
    assert "app.py:" in result["text"]


def test_read_span_refuses_paths_outside_the_project(servers):
    spec = ServerSpec(name="codeintel", transport="http", url=servers["codeintel"].url)
    result = call(spec, "read_span", {"file": "../../../../etc/hosts", "start": 1, "end": 3})
    assert result["is_error"] is True


def test_candidates_are_served_from_discovery(servers):
    spec = ServerSpec(name="codeintel", transport="http", url=servers["codeintel"].url)
    result = call(spec, "list_candidates", {"role": "expose"})
    assert "run" in result["text"]


def test_security_kb_answers_without_a_network(servers):
    spec = ServerSpec(name="security-kb", transport="http", url=servers["security-kb"].url)
    owasp = call(spec, "owasp_lookup", {"category": "tool_misuse"})
    assert "LLM06" in owasp["text"]
    cwe = call(spec, "cwe_lookup", {"cwe_id": "78"})
    assert "CWE-78" in cwe["text"] or "command" in cwe["text"].lower()


def test_every_mcp_call_is_traced(servers, events):
    spec = ServerSpec(name="security-kb", transport="http", url=servers["security-kb"].url)
    call(spec, "remediation_template", {"category": "tool_misuse"})
    kinds = [e.event_type for e in events if e.source == "mcp"]
    assert "mcp_tool_call" in kinds and "mcp_tool_result" in kinds
    result_event = next(e for e in events if e.event_type == "mcp_tool_result")
    assert result_event.payload["server"] == "security-kb"
    assert result_event.payload["latency_ms"] >= 0


def test_unreachable_server_raises_a_clear_error():
    spec = ServerSpec(name="nowhere", transport="http", url="http://127.0.0.1:9/mcp")
    with pytest.raises(MCPError):
        list_tools(spec, timeout=3)


def test_server_spec_validates_transport():
    with pytest.raises(ValueError):
        ServerSpec(name="x", transport="carrier-pigeon")
    with pytest.raises(ValueError):
        ServerSpec(name="x", transport="http")


@pytest.mark.skipif(not HAS_SEMGREP, reason="needs uvx and the semgrep binary (see the setup checklist)")
def test_semgrep_finds_a_process_call(tmp_path):
    findings = scan_sinks([("x.py", "import os\n\ndef run_cmd(c):\n    os.system(c)\n")])
    assert findings and any(f["check_id"].endswith("process-exec") and f["line"] == 4 for f in findings)


def test_missing_semgrep_is_reported_not_fatal(monkeypatch, events, tmp_path):
    monkeypatch.setattr("agentguard.mcp.semgrep.shutil.which", lambda name: None)
    assert scan_sinks([("x.py", "x = 1\n")]) is None
    assert any(e.event_type == "mcp_unavailable" for e in events)


def test_sink_evidence_raises_confidence_of_the_containing_function(tmp_path):
    (tmp_path / "tools.py").write_text(
        "def chat(m):\n    return m\n\n"
        "def export_report(text):\n    import os\n    os.system('cp ' + text)\n    return text\n\n"
        "def run(input_text):\n    return chat([input_text])\n")

    def fake_semgrep(files):
        return [{"check_id": "agentguard.process-exec", "path": "tools.py", "line": 6, "message": "x"}]

    result = discover(tmp_path, enrich=fake_semgrep)
    assert result.enrichment == "semgrep"
    cand = next(c for c in result.candidates if c.qualname == "export_report")
    assert cand.destructive and cand.confidence >= 0.85
    assert any("semgrep agentguard.process-exec at line 6" in s for s in cand.signals)


def test_discovery_records_when_enrichment_was_unavailable(tmp_path):
    (tmp_path / "app.py").write_text("def run(input_text):\n    return chat(input_text)\n")
    result = discover(tmp_path, enrich=lambda files: None)
    assert result.enrichment == "unavailable"


def test_reporter_uses_http_servers_when_they_are_running(monkeypatch):
    from crewai.mcp.config import MCPServerHTTP
    from agentguard.reporters import _mcp_servers
    monkeypatch.setenv("AGENTGUARD_CODEINTEL_URL", "http://127.0.0.1:8790/mcp")
    monkeypatch.setenv("AGENTGUARD_SECURITY_KB_URL", "http://127.0.0.1:8791/mcp")
    servers = _mcp_servers(None)
    assert len(servers) == 2 and all(isinstance(s, MCPServerHTTP) for s in servers)


def test_run_detail_summarises_mcp_usage(tmp_path):
    import json
    run_dir = tmp_path / ".agentguard" / "runs" / "r1"
    run_dir.mkdir(parents=True)
    rows = [
        {"timestamp": 1, "source": "mcp", "event_type": "mcp_tool_call", "payload": {"server": "codeintel", "tool": "search_code"}},
        {"timestamp": 2, "source": "mcp", "event_type": "mcp_tool_call", "payload": {"server": "codeintel", "tool": "search_code"}},
        {"timestamp": 3, "source": "mcp", "event_type": "mcp_error", "payload": {"server": "codeintel", "tool": "read_span"}},
        {"timestamp": 4, "source": "mcp", "event_type": "mcp_unavailable", "payload": {"server": "semgrep", "reason": "uvx missing"}},
    ]
    (run_dir / "trace.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    store = RunStore(tmp_path)
    usage = store.mcp_usage(store.get(store.scan()[0].id))
    assert usage["total"] == 2 and usage["errors"] == 1
    assert usage["calls"][0] == {"server": "codeintel", "tool": "search_code", "count": 2}
    assert usage["unavailable"] == ["semgrep: uvx missing"]
