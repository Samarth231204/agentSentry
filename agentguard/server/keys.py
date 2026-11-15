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
from typing import Any, Optional

PROVIDERS: dict[str, dict[str, str]] = {
    "anthropic": {"label": "Anthropic", "env": "ANTHROPIC_API_KEY", "test_model": "anthropic/claude-haiku-5-5"},
    "groq": {"label": "Groq", "env": "GROQ_API_KEY", "test_model": "groq/openai/gpt-oss-20b"},
    "openai": {"label": "OpenAI", "env": "OPENAI_API_KEY", "test_model": "openai/gpt-4o-mini"},
    "gemini": {"label": "Gemini", "env": "GEMINI_API_KEY", "test_model": "gemini/gemini-2.5-flash"},
    "openrouter": {"label": "OpenRouter", "env": "OPENROUTER_API_KEY", "test_model": "openrouter/openai/gpt-4o-mini"},
}

# Optional, non-secret per-provider setting stored next to the key (shown in the key form).
PROVIDER_EXTRAS: dict[str, dict[str, str]] = {
    "anthropic": {"field": "workspace_id", "env": "ANTHROPIC_WORKSPACE_ID", "label": "Workspace ID",
                  "help": "Only for a key that is not scoped to a workspace (Console → Settings → Workspaces)."},
}
_EXTRA_RE = re.compile(r"^[A-Za-z0-9_\-]{1,200}$")

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
    if not key:
        raise KeyInputError("Paste a key first.")
    if len(key) < 8:
        raise KeyInputError("That is too short to be an API key. Paste the whole key from your provider's console.")
    if len(key) > 512:
        raise KeyInputError("That is too long to be an API key. Paste only the key itself.")
    if not _KEY_RE.match(key):
        raise KeyInputError("The key contains characters an API key never has (spaces or quotes, for example). "
                            "Paste only the key itself.")
    return key


def masked(key: str) -> str:
    if len(key) <= 12:
        return "set"
    return f"{key[:4]}…{key[-4:]}"


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def _unquote(value: str) -> str:
    """KEY="value" and KEY='value' are common in .env files; the quotes are not part of the key."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


def read_keys(project_root: Path) -> dict[str, str]:
    """Provider id -> key, for keys stored in .agentguard/.env."""
    out: dict[str, str] = {}
    for line in _read_lines(env_path(project_root)):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        value = _unquote(value.strip())
        for provider, meta in PROVIDERS.items():
            if name.strip() == meta["env"] and value:
                out[provider] = value
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


def validate_extra(provider: str, value: Optional[str]) -> Optional[str]:
    """None = leave unchanged, "" = clear, otherwise a validated value."""
    if value is None:
        return None
    extra = PROVIDER_EXTRAS.get(provider)
    if extra is None:
        raise KeyInputError(f"{PROVIDERS[provider]['label']} has no extra setting.")
    value = _unquote(value.strip())
    if value and not _EXTRA_RE.match(value):
        raise KeyInputError(f"That does not look like a {extra['label']}: use only letters, digits, '-' and '_'.")
    return value


def _set_env_line(path: Path, name: str, value: Optional[str]) -> None:
    kept = [ln for ln in _read_lines(path) if not ln.strip().startswith(f"{name}=")]
    _write_lines(path, kept + ([f"{name}={value}"] if value else []))
    if value:
        os.environ[name] = value  # the running process uses it immediately
    else:
        os.environ.pop(name, None)


def save_key(project_root: Path, provider: str, api_key: Optional[str],
             extra_value: Optional[str] = None) -> dict[str, Any]:
    meta = provider_or_raise(provider)
    extra = validate_extra(provider, extra_value)
    path = env_path(project_root)
    if api_key:
        _set_env_line(path, meta["env"], validate_key(api_key))
    elif extra is None:
        raise KeyInputError("Paste a key first.")
    elif provider not in read_keys(project_root):
        raise KeyInputError("Save the API key first, or paste it together with this setting.")
    if extra is not None:
        _set_env_line(path, PROVIDER_EXTRAS[provider]["env"], extra)
    status = next(s for s in key_status(project_root) if s["id"] == provider)
    return {"provider": provider, **status}


def delete_key(project_root: Path, provider: str) -> dict[str, Any]:
    meta = provider_or_raise(provider)
    path = env_path(project_root)
    names = [meta["env"]] + ([PROVIDER_EXTRAS[provider]["env"]] if provider in PROVIDER_EXTRAS else [])
    if path.exists():
        kept = [ln for ln in _read_lines(path) if not any(ln.strip().startswith(f"{n}=") for n in names)]
        _write_lines(path, kept)
    for name in names:
        os.environ.pop(name, None)
    return {"provider": provider, "configured": False, "masked": None}


# Non-secret provider settings that may sit next to the keys in .agentguard/.env.
PROVIDER_SETTINGS = tuple(e["env"] for e in PROVIDER_EXTRAS.values())


def apply_to_environ(project_root: Path) -> None:
    """Load saved keys into this process (they override values from the root .env)."""
    for provider, key in read_keys(project_root).items():
        os.environ[PROVIDERS[provider]["env"]] = key
    for line in _read_lines(env_path(project_root)):
        name, sep, value = line.strip().partition("=")
        if sep and name.strip() in PROVIDER_SETTINGS and _unquote(value.strip()):
            os.environ[name.strip()] = _unquote(value.strip())


def read_extras(project_root: Path) -> dict[str, str]:
    """Provider id -> its extra setting's value, from .agentguard/.env."""
    by_env = {e["env"]: pid for pid, e in PROVIDER_EXTRAS.items()}
    out: dict[str, str] = {}
    for line in _read_lines(env_path(project_root)):
        name, sep, value = line.strip().partition("=")
        if sep and name.strip() in by_env and _unquote(value.strip()):
            out[by_env[name.strip()]] = _unquote(value.strip())
    return out


def key_status(project_root: Path) -> list[dict[str, Any]]:
    stored = read_keys(project_root)
    extras = read_extras(project_root)
    out = []
    for pid, meta in PROVIDERS.items():
        row: dict[str, Any] = {
            "id": pid,
            "label": meta["label"],
            "configured": pid in stored,
            "masked": masked(stored[pid]) if pid in stored else None,
        }
        if pid in PROVIDER_EXTRAS:
            e = PROVIDER_EXTRAS[pid]
            row["extra"] = {"field": e["field"], "label": e["label"], "help": e["help"],
                            "value": extras.get(pid) or os.environ.get(e["env"]) or None}
        out.append(row)
    return out


def redact(text: str, secrets: list[str]) -> str:
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, "***")
    return out


def test_key(provider: str, api_key: str, extra_value: Optional[str] = None) -> dict[str, Any]:
    """One tiny completion with the given key. Returns ok/message, never the key."""
    meta = provider_or_raise(provider)
    key = validate_key(api_key)
    extra = validate_extra(provider, extra_value) if extra_value else None
    import litellm  # imported here: heavy, and not needed by the rest of the API

    from agentguard.config import litellm_kwargs

    try:
        resp = litellm.completion(
            model=meta["test_model"],
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
            # gpt-oss spends part of max_tokens on reasoning; 20 returned empty text.
            max_tokens=300,
            api_key=key,
            timeout=30,
            **_with_extra_header(litellm_kwargs(meta["test_model"]), provider, extra),
        )
        choices = getattr(resp, "choices", None) or []
        if not choices:
            return {"ok": False, "model": meta["test_model"], "message": "The provider returned no choices."}
        return {"ok": True, "model": meta["test_model"], "message": "Key accepted by the provider."}
    except Exception as exc:  # noqa: BLE001 - surface the provider's reason, minus the key
        return {"ok": False, "model": meta["test_model"], "message": provider_reason(exc, key)}


def _with_extra_header(kwargs: dict[str, Any], provider: str, extra: Optional[str]) -> dict[str, Any]:
    """A workspace ID typed into the form (not saved yet) is tested as given."""
    if provider == "anthropic" and extra:
        kwargs = {**kwargs, "extra_headers": {**kwargs.get("extra_headers", {}), "anthropic-workspace-id": extra}}
    return kwargs


_PROVIDER_MESSAGE_RE = re.compile(r'"message"\s*:\s*"((?:[^"\\]|\\.)+)"')


def provider_reason(exc: Exception, key: str) -> str:
    """The provider's own explanation (the JSON "message"), without the client library's wrapper text."""
    raw = redact(str(exc), [key])
    found = _PROVIDER_MESSAGE_RE.search(raw)
    if found:
        return f"The provider rejected the request: {found.group(1).replace(chr(92) + chr(34), chr(34))}"[:600]
    return redact(f"{type(exc).__name__}: {exc}", [key])[:600]
