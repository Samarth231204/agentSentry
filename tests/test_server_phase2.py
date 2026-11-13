"""Phase 2 backend tests: keys, settings, run API. No network, no LLM quota."""

import json
import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard.server import keys as keystore
from agentguard.server.app import create_app
from agentguard.server.runner import RunManager, RunRejected, RunSpec
from agentguard.server.settings import SettingsIn, read_settings, write_settings

SECRET = "gsk_TESTONLY_abcdefghijklmnop1234"


@pytest.fixture
def project(tmp_path, monkeypatch):
    for meta in keystore.PROVIDERS.values():
        monkeypatch.delenv(meta["env"], raising=False)
    return tmp_path


@pytest.fixture
def client(project):
    return TestClient(create_app(project))


# ----- keys ---------------------------------------------------------------

def test_save_key_writes_private_env_file(project):
    keystore.save_key(project, "groq", SECRET)
    path = keystore.env_path(project)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert f"GROQ_API_KEY={SECRET}" in path.read_text()


def test_save_key_returns_masked_value_only(project):
    result = keystore.save_key(project, "groq", SECRET)
    assert SECRET not in json.dumps(result)
    assert result["masked"] == "gsk_…1234"


def test_replacing_a_key_keeps_other_providers(project):
    keystore.save_key(project, "groq", SECRET)
    keystore.save_key(project, "gemini", "AIzaTESTONLY1234567890")
    keystore.save_key(project, "groq", "gsk_NEWVALUE_abcdefgh9999")
    stored = keystore.read_keys(project)
    assert stored["groq"] == "gsk_NEWVALUE_abcdefgh9999"
    assert stored["gemini"] == "AIzaTESTONLY1234567890"
    assert sum(1 for ln in keystore.env_path(project).read_text().splitlines()
               if ln.startswith("GROQ_API_KEY=")) == 1


def test_delete_key_removes_only_that_provider(project):
    keystore.save_key(project, "groq", SECRET)
    keystore.save_key(project, "openai", "sk-TESTONLY-abcdef123456")
    keystore.delete_key(project, "groq")
    assert set(keystore.read_keys(project)) == {"openai"}


@pytest.mark.parametrize("bad", ["", "short", "has space in it 123456", "new\nline-key-1234567", "quote'key-1234567"])
def test_invalid_keys_are_rejected(project, bad):
    with pytest.raises(keystore.KeyInputError):
        keystore.save_key(project, "groq", bad)


def test_unknown_provider_is_rejected(project):
    with pytest.raises(keystore.KeyInputError):
        keystore.save_key(project, "llama", SECRET)


def test_key_status_lists_five_providers_without_values(project):
    keystore.save_key(project, "groq", SECRET)
    status = keystore.key_status(project)
    assert [p["id"] for p in status] == ["groq", "openai", "anthropic", "gemini", "openrouter"]
    assert SECRET not in json.dumps(status)


def test_key_test_error_is_redacted(project, monkeypatch):
    import litellm

    def boom(**kwargs):
        raise RuntimeError(f"invalid api key {kwargs['api_key']}")

    monkeypatch.setattr(litellm, "completion", boom)
    result = keystore.test_key("groq", SECRET)
    assert result["ok"] is False
    assert SECRET not in result["message"]
    assert "***" in result["message"]


def test_key_test_success_reports_ok(project, monkeypatch):
    import litellm

    class Resp:
        choices = [object()]

    monkeypatch.setattr(litellm, "completion", lambda **kw: Resp())
    result = keystore.test_key("groq", SECRET)
    assert result["ok"] is True


def test_key_endpoints_send_no_store_and_never_echo_key(client, project, monkeypatch):
    resp = client.post("/api/settings/keys", json={"provider": "groq", "api_key": SECRET})
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    assert SECRET not in resp.text
    listing = client.get("/api/settings")
    assert SECRET not in listing.text
    assert next(p for p in listing.json()["providers"] if p["id"] == "groq")["configured"] is True
    deleted = client.delete("/api/settings/keys/groq")
    assert deleted.status_code == 200
    assert client.delete("/api/settings/keys/llama").status_code == 400


def test_test_endpoint_without_stored_key_is_400(client):
    resp = client.post("/api/settings/keys/test", json={"provider": "openai"})
    assert resp.status_code == 400


# ----- settings -----------------------------------------------------------

def test_settings_round_trip(project):
    body = SettingsIn(attacker_model="groq/openai/gpt-oss-20b", reporter_model="groq/openai/gpt-oss-20b",
                      chat_model="groq/openai/gpt-oss-20b", max_probes=4,
                      category_cooldown_seconds=2, target_timeout=30,
                      max_llm_calls=60, max_tokens=None)
    write_settings(project, body)
    saved = read_settings(project)
    assert saved["max_probes"] == 4
    assert saved["max_tokens"] is None


def test_settings_endpoint_validates_ranges(client):
    base = {"attacker_model": "groq/openai/gpt-oss-20b", "reporter_model": "groq/openai/gpt-oss-20b",
            "chat_model": "groq/openai/gpt-oss-20b", "max_probes": 3,
            "category_cooldown_seconds": 1, "target_timeout": 30}
    assert client.put("/api/settings", json={**base, "max_probes": 0}).status_code == 422
    assert client.put("/api/settings", json={**base, "max_probes": 51}).status_code == 422
    assert client.put("/api/settings", json={**base, "attacker_model": "x; rm -rf"}).status_code == 422
    ok = client.put("/api/settings", json=base)
    assert ok.status_code == 200
    assert ok.json()["settings"]["max_probes"] == 3


def test_settings_file_overrides_defaults(project, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_MAX_PROBES", "8")
    body = SettingsIn(attacker_model="groq/openai/gpt-oss-20b", reporter_model="groq/openai/gpt-oss-20b",
                      chat_model="groq/openai/gpt-oss-20b", max_probes=2,
                      category_cooldown_seconds=0, target_timeout=30)
    write_settings(project, body)
    from agentguard.server.settings import effective_config
    assert effective_config(project).max_probes == 2


# ----- run requests -------------------------------------------------------

@pytest.mark.parametrize("spec", [
    RunSpec(),                                               # neither target
    RunSpec(target_app="app:app", target_url="http://127.0.0.1:9"),  # both
    RunSpec(target_app="import os; os.system('x')"),        # not a module:attr
    RunSpec(target_url="https://example.com"),               # remote host refused
    RunSpec(target_url="http://10.0.0.5:8000"),              # private LAN refused
    RunSpec(target_app="app:app", max_probes=0),
    RunSpec(target_app="app:app", canaries=["x"] * 11),
])
def test_run_spec_validation_rejects(spec):
    with pytest.raises(RunRejected):
        spec.validate()


def test_run_request_rejected_returns_422(client):
    resp = client.post("/api/runs", json={"target_url": "https://example.com"})
    assert resp.status_code == 422


def test_status_for_unknown_run_is_404(client):
    assert client.get("/api/runs/unknown-run/status").status_code == 404
    assert client.post("/api/runs/unknown-run/cancel").status_code == 404
    assert client.get("/api/active-run").json() is None


def test_manager_creates_run_folder_before_starting(tmp_path):
    manager = RunManager(tmp_path)
    # A rejected spec must not leave a folder behind.
    with pytest.raises(RunRejected):
        manager.start(RunSpec(target_url="https://example.com"))
    assert not (tmp_path / ".agentguard" / "runs").exists()
