"""Configuration management for AgentGuard.

Loads settings with precedence:
1. Explicit runtime overrides / CLI arguments
2. Environment variables (AGENTGUARD_*)
3. Configuration file (agentguard.yaml or specified path)
4. Built-in defaults
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field

from agentguard._env import load_env

load_env()


def normalize_model(model: str) -> str:
    """Normalize model string to format expected by LiteLLM / providers.

    Examples:
        'openai/gpt-oss-20b' -> 'groq/openai/gpt-oss-20b' (if groq key is active)
        'gpt-4o' -> 'openai/gpt-4o'
        'claude-3-5-sonnet-20241022' -> 'anthropic/claude-3-5-sonnet-20241022'
        'gemini-2.0-flash' -> 'gemini/gemini-2.0-flash'
        'groq/openai/gpt-oss-20b' -> 'groq/openai/gpt-oss-20b'
    """
    m = model.strip()
    if "/" in m:
        prefix = m.split("/", 1)[0].lower()
        if prefix in ("groq", "openai", "anthropic", "gemini", "ollama", "azure", "cohere", "bedrock", "vertex_ai"):
            # If prefix is 'openai' but it's gpt-oss or allam, and Groq is configured, redirect to Groq
            if prefix == "openai" and "gpt-oss" in m and os.environ.get("GROQ_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
                return f"groq/{m}"
            return m

    # Detect known model names and map to appropriate litellm prefix
    if m.startswith(("gpt-", "o1-", "o3-", "chatgpt-")):
        return f"openai/{m}"
    if m.startswith("claude-"):
        return f"anthropic/{m}"
    if m.startswith("gemini-"):
        return f"gemini/{m}"
    if m in ("allam-2-7b", "openai/gpt-oss-20b", "openai/gpt-oss-120b", "qwen/qwen3.8-27b"):
        return f"groq/{m}"

    # If GROQ_API_KEY is present and no prefix is specified, default to groq
    if os.environ.get("GROQ_API_KEY") and not any(os.environ.get(k) for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY")):
        return f"groq/{m}"

    return m


# Which environment variable(s) hold the credentials for a LiteLLM provider prefix.
PROVIDER_KEY_ENVS: dict[str, tuple[str, ...]] = {
    "groq": ("GROQ_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "cohere": ("COHERE_API_KEY",),
}


def has_credentials(model: str) -> bool:
    """False only when the model's provider needs a key and none is set (a call could never succeed)."""
    prefix = normalize_model(model).split("/", 1)[0].lower()
    envs = PROVIDER_KEY_ENVS.get(prefix)
    return envs is None or any(os.environ.get(e) for e in envs)


def usable_fallbacks(primary: str, chain: list[str]) -> list[str]:
    """The fallback models to try after `primary`: normalized, deduplicated, and only providers with a key.

    A model whose provider has no key fails with an authentication error, so trying it only hides
    the original (usually rate-limit) error behind a confusing one.
    """
    seen = {normalize_model(primary)}
    out: list[str] = []
    for name in chain:
        model = normalize_model(name)
        if model in seen or not has_credentials(model):
            continue
        seen.add(model)
        out.append(model)
    return out


class AgentGuardConfig(BaseModel):
    attacker_model: str = Field(
        default_factory=lambda: os.environ.get(
            "AGENTGUARD_ATTACKER_MODEL", "groq/openai/gpt-oss-20b"
        )
    )
    reporter_model: str = Field(
        default_factory=lambda: os.environ.get(
            "AGENTGUARD_REPORTER_MODEL", "groq/openai/gpt-oss-20b"
        )
    )
    chat_model: str = Field(
        default_factory=lambda: os.environ.get(
            "AGENTGUARD_CHAT_MODEL", "groq/openai/gpt-oss-20b"
        )
    )
    api_base: Optional[str] = Field(
        default_factory=lambda: os.environ.get("AGENTGUARD_API_BASE", None)
    )
    fallback_chain: list[str] = Field(
        default_factory=lambda: [
            m.strip() for m in os.environ.get(
                "AGENTGUARD_FALLBACK_CHAIN",
                # Groq rate limits are per model, so a second Groq model is a real fallback on one key.
                "groq/openai/gpt-oss-20b,groq/openai/gpt-oss-120b,gemini/gemini-2.5-flash",
            ).split(",") if m.strip()
        ]
    )
    groq_url: str = Field(
        default_factory=lambda: os.environ.get(
            "AGENTGUARD_GROQ_URL", "https://api.groq.com/openai/v1/chat/completions"
        )
    )
    max_probes: int = Field(
        default_factory=lambda: int(os.environ.get("AGENTGUARD_MAX_PROBES", "8"))
    )
    category_cooldown_seconds: float = Field(
        default_factory=lambda: float(
            os.environ.get("AGENTGUARD_CATEGORY_COOLDOWN", "15.0")
        )
    )
    source_snippet_max_chars: int = Field(
        default_factory=lambda: int(
            os.environ.get("AGENTGUARD_SOURCE_SNIPPET_MAX_CHARS", "1200")
        )
    )
    target_timeout: float = Field(
        default_factory=lambda: float(
            os.environ.get("AGENTGUARD_TARGET_TIMEOUT", "60.0")
        )
    )
    litellm_retries: int = Field(
        default_factory=lambda: int(
            os.environ.get("AGENTGUARD_LITELLM_RETRIES", "5")
        )
    )
    llm_retry_attempts: int = Field(
        default_factory=lambda: int(
            os.environ.get("AGENTGUARD_LLM_RETRY_ATTEMPTS", "3")
        )
    )
    log_level: str = Field(
        default_factory=lambda: os.environ.get("AGENTGUARD_LOG_LEVEL", "INFO").upper()
    )

    def get_normalized_attacker_model(self) -> str:
        return normalize_model(self.attacker_model)

    def get_normalized_reporter_model(self) -> str:
        return normalize_model(self.reporter_model)

    def get_normalized_chat_model(self) -> str:
        return normalize_model(self.chat_model)

    @classmethod
    def load(
        cls,
        config_path: Optional[str | Path] = None,
        overrides: Optional[dict[str, Any]] = None,
    ) -> "AgentGuardConfig":
        """Load configuration from optional yaml file and environment with overrides."""
        file_data: dict[str, Any] = {}
        target_path: Optional[Path] = None

        if config_path:
            p = Path(config_path)
            if p.exists() and p.is_file():
                target_path = p
        else:
            default_path = Path("agentguard.yaml")
            if default_path.exists() and default_path.is_file():
                target_path = default_path

        if target_path:
            try:
                loaded = yaml.safe_load(target_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    file_data = loaded.get("agentguard", loaded)
            except Exception:
                file_data = {}

        data = {**file_data, **(overrides or {})}
        return cls(**data)


_current_config: Optional[AgentGuardConfig] = None


def get_config() -> AgentGuardConfig:
    """Retrieve global configuration instance."""
    global _current_config
    if _current_config is None:
        _current_config = AgentGuardConfig.load()
    return _current_config


def set_config(config: AgentGuardConfig) -> None:
    """Set global configuration instance."""
    global _current_config
    _current_config = config
