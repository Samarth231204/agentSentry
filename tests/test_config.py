import os
from pathlib import Path
from agentguard.config import AgentGuardConfig, get_config, set_config


def test_default_config(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_CATEGORY_COOLDOWN", raising=False)
    monkeypatch.delenv("AGENTGUARD_MAX_PROBES", raising=False)
    monkeypatch.delenv("AGENTGUARD_ATTACKER_MODEL", raising=False)
    monkeypatch.delenv("AGENTGUARD_REPORTER_MODEL", raising=False)
    monkeypatch.delenv("AGENTGUARD_CHAT_MODEL", raising=False)
    config = AgentGuardConfig()
    assert config.max_probes == 8
    assert config.category_cooldown_seconds == 15.0
    assert config.source_snippet_max_chars == 1200
    assert config.target_timeout == 60.0
    assert config.litellm_retries == 5
    assert config.attacker_model == "anthropic/claude-haiku-5-5"


def test_config_env_override(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_MAX_PROBES", "12")
    monkeypatch.setenv("AGENTGUARD_ATTACKER_MODEL", "custom/test-model")
    config = AgentGuardConfig()
    assert config.max_probes == 12
    assert config.attacker_model == "custom/test-model"


def test_config_yaml_file_loading(tmp_path: Path):
    yaml_file = tmp_path / "custom_config.yaml"
    yaml_file.write_text(
        """
        agentguard:
          max_probes: 5
          attacker_model: "test/attacker"
          reporter_model: "test/reporter"
          category_cooldown_seconds: 2.0
        """,
        encoding="utf-8",
    )

    loaded = AgentGuardConfig.load(config_path=yaml_file)
    assert loaded.max_probes == 5
    assert loaded.attacker_model == "test/attacker"
    assert loaded.reporter_model == "test/reporter"
    assert loaded.category_cooldown_seconds == 2.0


def test_get_and_set_global_config():
    custom = AgentGuardConfig(max_probes=99)
    set_config(custom)
    assert get_config().max_probes == 99
