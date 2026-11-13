"""API key storage for the dashboard.

Keys go into <project>/.agentguard/.env (file mode 600). They are never held in
the browser, never logged, never placed in trace events, and responses only
ever contain a masked form. Keys are sent to providers only by test_key().
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

PROVIDERS: dict[str, dict[str, str]] = {
    "groq": {"label": "Groq", "env": "GROQ_API_KEY", "test_model": "groq/openai/gpt-oss-20b"},
    "openai": {"label": "OpenAI", "env": "OPENAI_API_KEY", "test_model": "openai/gpt-4o-mini"},
    "anthropic": {"label": "Anthropic", "env": "ANTHROPIC_API_KEY", "test_model": "anthropic/claude-3-5-haiku-latest"},
    "gemini": {"label": "Gemini", "env": "GEMINI_API_KEY", "test_model": "gemini/gemini-2.5-flash"},
    "openrouter": {"label": "OpenRouter", "env": "OPENROUTER_API_KEY", "test_model": "openrouter/openai/gpt-4o-mini"},
}

_KEY_RE = re.compile(r"^[A-Za-z0-9._\-+/=:]{8,512}$")


class KeyInputError(ValueError):
    """Bad provider or key format. Messages never contain the key itself."""


def env_path(project_root: Path) -> Path:
    return Path(project_root) / ".agentguard" / ".env"


def provider_or_raise(provider: str) -> dict[str, str]:
    if provider not in PROVIDERS:
        raise KeyInputError(f"Unknown provider '{provider}'. Choose one of: {', '.join(PROVIDERS)}.")
    return PROVIDERS[provider]


def validate_key(api_key: str) -> str:
    key = (api_key or "").strip()
    if not _KEY_RE.match(key):
        raise KeyInputError("The key has an unexpected format (only letters, digits and . _ - + / = : are allowed).")
    return key


def masked(key: str) -> str:
    if len(key) <= 12:
        return "set"
    return f"{key[:4]}…{key[-4:]}"


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def read_keys(project_root: Path) -> dict[str, str]:
    """Provider id -> key, for keys stored in .agentguard/.env."""
    out: dict[str, str] = {}
    for line in _read_lines(env_path(project_root)):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        for provider, meta in PROVIDERS.items():
            if name.strip() == meta["env"] and value.strip():
                out[provider] = value.strip()
    return out


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".env.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    os.chmod(path, 0o600)


def save_key(project_root: Path, provider: str, api_key: str) -> dict[str, Any]:
    meta = provider_or_raise(provider)
    key = validate_key(api_key)
    path = env_path(project_root)
    kept = [ln for ln in _read_lines(path) if not ln.strip().startswith(f"{meta['env']}=")]
    _write_lines(path, kept + [f"{meta['env']}={key}"])
    os.environ[meta["env"]] = key  # the running process uses it immediately
    return {"provider": provider, "configured": True, "masked": masked(key)}


def delete_key(project_root: Path, provider: str) -> dict[str, Any]:
    meta = provider_or_raise(provider)
    path = env_path(project_root)
    if path.exists():
        kept = [ln for ln in _read_lines(path) if not ln.strip().startswith(f"{meta['env']}=")]
        _write_lines(path, kept)
    os.environ.pop(meta["env"], None)
    return {"provider": provider, "configured": False, "masked": None}


def apply_to_environ(project_root: Path) -> None:
    """Load saved keys into this process (they override values from the root .env)."""
    for provider, key in read_keys(project_root).items():
        os.environ[PROVIDERS[provider]["env"]] = key


def key_status(project_root: Path) -> list[dict[str, Any]]:
    stored = read_keys(project_root)
    return [
        {
            "id": pid,
            "label": meta["label"],
            "configured": pid in stored,
            "masked": masked(stored[pid]) if pid in stored else None,
        }
        for pid, meta in PROVIDERS.items()
    ]


def redact(text: str, secrets: list[str]) -> str:
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, "***")
    return out


def test_key(provider: str, api_key: str) -> dict[str, Any]:
    """One tiny completion with the given key. Returns ok/message, never the key."""
    meta = provider_or_raise(provider)
    key = validate_key(api_key)
    import litellm  # imported here: heavy, and not needed by the rest of the API

    try:
        resp = litellm.completion(
            model=meta["test_model"],
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
            # gpt-oss spends part of max_tokens on reasoning; 20 returned empty text.
            max_tokens=300,
            api_key=key,
            timeout=30,
        )
        choices = getattr(resp, "choices", None) or []
        if not choices:
            return {"ok": False, "model": meta["test_model"], "message": "The provider returned no choices."}
        return {"ok": True, "model": meta["test_model"], "message": "Key accepted by the provider."}
    except Exception as exc:  # noqa: BLE001 - surface the provider's reason, minus the key
        text = redact(f"{type(exc).__name__}: {exc}", [key])
        return {"ok": False, "model": meta["test_model"], "message": text[:300]}
