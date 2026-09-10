"""Client-side handle for a running agentguard-adapter target."""

from __future__ import annotations

import uuid
from typing import Any, Optional

import httpx


class Target:
    """HTTP client for a target app instrumented with @expose / @watch."""

    def __init__(self, url: str, timeout: float = 60.0):
        self.url = url.rstrip("/")
        self._client = httpx.Client(base_url=self.url, timeout=timeout)

    def new_session_id(self) -> str:
        return uuid.uuid4().hex

    def health(self) -> dict:
        resp = self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    def invoke(self, input_text: str, session_id: Optional[str] = None) -> dict:
        """POST /invoke and return {output, tool_calls, error, latency_ms}.

        Never raises on target-side failures — those come back as the
        `error` field so an attack loop can keep going.
        """
        resp = self._client.post(
            "/invoke",
            json={"input_text": input_text, "session_id": session_id},
        )
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
