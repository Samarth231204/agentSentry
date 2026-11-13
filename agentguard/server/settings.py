"""Editable settings stored in <project>/.agentguard/config.yaml."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field

from agentguard.config import AgentGuardConfig

_MODEL_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,120}$")


class SettingsIn(BaseModel):
    attacker_model: str = Field(pattern=_MODEL_RE.pattern)
    reporter_model: str = Field(pattern=_MODEL_RE.pattern)
    chat_model: str = Field(pattern=_MODEL_RE.pattern)
    max_probes: int = Field(ge=1, le=50)
    category_cooldown_seconds: float = Field(ge=0, le=300)
    target_timeout: float = Field(ge=5, le=600)
    max_llm_calls: Optional[int] = Field(default=None, ge=1, le=100000)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=100000000)


def config_path(project_root: Path) -> Path:
    return Path(project_root) / ".agentguard" / "config.yaml"


def read_settings(project_root: Path) -> dict[str, Any]:
    path = config_path(project_root)
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def write_settings(project_root: Path, settings: SettingsIn) -> dict[str, Any]:
    path = config_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = settings.model_dump()
    path.write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")
    return data


def effective_config(project_root: Path) -> AgentGuardConfig:
    """Defaults < environment < .agentguard/config.yaml (the file wins for editable fields)."""
    saved = {k: v for k, v in read_settings(project_root).items() if k in SettingsIn.model_fields and v is not None}
    return AgentGuardConfig.load(overrides=saved)


def current_settings(project_root: Path) -> dict[str, Any]:
    cfg = effective_config(project_root)
    saved = read_settings(project_root)
    return {
        "attacker_model": cfg.attacker_model,
        "reporter_model": cfg.reporter_model,
        "chat_model": cfg.chat_model,
        "max_probes": cfg.max_probes,
        "category_cooldown_seconds": cfg.category_cooldown_seconds,
        "target_timeout": cfg.target_timeout,
        "max_llm_calls": saved.get("max_llm_calls"),
        "max_tokens": saved.get("max_tokens"),
        "saved_to_file": config_path(project_root).exists(),
    }
