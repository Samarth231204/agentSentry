"""Minimal Groq (OpenAI-compatible) chat client, shared by samples and later phases."""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from agentguard._env import load_env

load_env()

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.3-70b-versatile has been retired from Groq's catalog; gpt-oss-20b
# is the current default — fast, cheap, and supports tool calling.
DEFAULT_MODEL = "openai/gpt-oss-20b"


def chat(
    messages: list[dict],
    tools: Optional[list[dict]] = None,
    model: str = DEFAULT_MODEL,
    temperature: float = 0.7,
    max_tokens: int = 1024,
) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set (checked .env and environment)")

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"

    resp = httpx.post(
        GROQ_URL,
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()
