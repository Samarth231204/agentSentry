"""Phase 6: static dashboard serving, bootstrap, doctor, and the up command. No network."""

from pathlib import Path

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from agentguard import __version__
from agentguard.cli import main
from agentguard.server import app as app_module
from agentguard.server.app import create_app


@pytest.fixture
def static_site(tmp_path, monkeypatch):
    site = tmp_path / "static"
    (site / "run").mkdir(parents=True)
    (site / "index.html").write_text("<html>HOME-PAGE</html>")
    (site / "run" / "index.html").write_text("<html>RUN-PAGE</html>")
    (site / "404.html").write_text("<html>NOT-FOUND</html>")
    (site / "_next").mkdir()
    (site / "_next" / "app.js").write_text("console.log(1)")
    (tmp_path / "secret.txt").write_text("TOP-SECRET")
    monkeypatch.setattr(app_module, "STATIC_DIR", site)
    return site


def test_dashboard_pages_are_served_by_the_backend(static_site, tmp_path):
    client = TestClient(create_app(tmp_path))
    assert "HOME-PAGE" in client.get("/").text
    assert "RUN-PAGE" in client.get("/run").text
    assert client.get("/_next/app.js").text == "console.log(1)"


def test_static_serving_refuses_path_traversal(static_site, tmp_path):
    client = TestClient(create_app(tmp_path))
    for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/run/../../secret.txt"):
        resp = client.get(path)
        assert "TOP-SECRET" not in resp.text


def test_unknown_pages_show_the_404_page(static_site, tmp_path):
    client = TestClient(create_app(tmp_path))
    resp = client.get("/no-such-page")
    assert resp.status_code == 404 and "NOT-FOUND" in resp.text


def test_api_routes_still_win_over_the_static_fallback(static_site, tmp_path):
    client = TestClient(create_app(tmp_path))
    assert client.get("/api/health").json()["status"] == "ok"


def test_bootstrap_ignores_the_clone_and_is_idempotent(tmp_path):
    project = tmp_path / "myproject"
    project.mkdir()
    (project / ".gitignore").write_text("node_modules/\n")
    runner = CliRunner()
    first = runner.invoke(main, ["bootstrap", "--project", str(project)])
    assert first.exit_code == 0
    text = (project / ".gitignore").read_text()
    assert "node_modules/" in text and ".agentguard/" in text
    assert (project / ".agentguard").is_dir()
    second = runner.invoke(main, ["bootstrap", "--project", str(project)])
    assert "already ignores" in second.output
    assert (project / ".gitignore").read_text().count(".agentguard/") == 1


def test_bootstrap_creates_gitignore_when_missing(tmp_path):
    project = tmp_path / "fresh"
    project.mkdir()
    result = CliRunner().invoke(main, ["bootstrap", "--project", str(project)])
    assert result.exit_code == 0
    assert (project / ".gitignore").exists()


def test_doctor_runs_and_never_prints_key_values(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_TESTONLY_doctor_value_1234567890")
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "Groq key set" in result.output
    assert "gsk_TESTONLY" not in result.output


def test_version_flag():
    result = CliRunner().invoke(main, ["--version"])
    assert __version__ in result.output


def test_up_serves_the_static_dashboard_without_node(static_site, monkeypatch, tmp_path):
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr("agentguard.server.launcher.start_dashboard", lambda *a, **k: None)
    result = CliRunner().invoke(main, ["up", "--project", str(tmp_path), "--port", "8798",
                                       "--no-browser", "--no-mcp"])
    assert result.exit_code == 0, result.output
    assert "served by the backend" in result.output
    assert "http://127.0.0.1:8798/" in result.output


def test_up_sets_the_a2a_url_for_the_runner(monkeypatch, tmp_path):
    import os
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.delenv("AGENTGUARD_A2A_URL", raising=False)
    CliRunner().invoke(main, ["up", "--project", str(tmp_path), "--port", "8797", "--no-dashboard",
                              "--no-mcp", "--no-browser"])
    assert os.environ.get("AGENTGUARD_A2A_URL") == "http://127.0.0.1:8797"
    monkeypatch.delenv("AGENTGUARD_A2A_URL", raising=False)
