"""Calls one AgentGuard agent over A2A (JSON-RPC message/send). Each call is a trace event."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from agentguard.a2a.protocol import build_request
from agentguard.events import get_event_bus
from agentguard.schemas import TraceEvent


class A2AError(RuntimeError):
    pass


def _emit(agent: str, base_url: str, latency_ms: float, ok: bool, error: str | None = None) -> None:
    payload: dict[str, Any] = {"agent": agent, "url": base_url, "latency_ms": round(latency_ms, 1), "ok": ok}
    if error:
        payload["error"] = error[:300]
    get_event_bus().emit(TraceEvent(source="a2a", event_type="a2a_call", payload=payload))


def call_agent(base_url: str, agent: str, payload: dict[str, Any], timeout: float = 900.0) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/a2a/{agent}"
    started = time.perf_counter()
    try:
        resp = httpx.post(url, json=build_request(agent, payload), timeout=timeout)
        body = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        _emit(agent, base_url, (time.perf_counter() - started) * 1000, False, str(exc))
        raise A2AError(f"{agent} agent unreachable: {type(exc).__name__}") from exc
    latency = (time.perf_counter() - started) * 1000
    if "error" in body:
        message = body["error"].get("message", "error")
        detail = body["error"].get("data", "")
        _emit(agent, base_url, latency, False, f"{message}: {detail}")
        raise A2AError(f"{agent} agent error: {message} {detail}".strip())
    parts = body.get("result", {}).get("parts", [])
    text = next((p.get("text") for p in parts if p.get("kind") == "text"), None)
    if text is None:
        _emit(agent, base_url, latency, False, "no text part")
        raise A2AError(f"{agent} agent returned no text part")
    _emit(agent, base_url, latency, True)
    return json.loads(text)


def fetch_card(base_url: str, agent: str, timeout: float = 10.0) -> dict[str, Any]:
    resp = httpx.get(f"{base_url.rstrip('/')}/a2a/{agent}/.well-known/agent.json", timeout=timeout)
    resp.raise_for_status()
    return resp.json()
