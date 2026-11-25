"""Starts AgentGuard's two A2A services.

Locally `agentguard up` starts both inside its own process (each on its own port, real HTTP), so the
trace, dashboard and LangFuse see every event. In the cloud each runs as its own service:
    agentguard a2a-attack     agentguard a2a-review
"""

from __future__ import annotations

import threading
import time

import httpx
import uvicorn

from agentguard.a2a.cards import attack_url, port_of, review_url

_started: dict[str, uvicorn.Server] = {}


def is_up(url: str) -> bool:
    try:
        return httpx.get(f"{url}/.well-known/agent-card.json", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def _serve(name: str, url: str, build) -> None:
    if name in _started or is_up(url):
        return
    server = uvicorn.Server(uvicorn.Config(build(), host="127.0.0.1", port=port_of(url), log_level="warning"))
    threading.Thread(target=server.run, daemon=True, name=f"agentguard-a2a-{name}").start()
    _started[name] = server
    for _ in range(100):
        if is_up(url):
            return
        time.sleep(0.1)
    raise RuntimeError(f"A2A {name} service did not start at {url}")


def start_local_services() -> dict[str, str]:
    from agentguard.a2a import attack_service, review_service

    _serve("review", review_url(), review_service.build_app)
    _serve("attack", attack_url(), attack_service.build_app)
    return {"attack": attack_url(), "review": review_url()}


def serve_forever(which: str, host: str = "0.0.0.0") -> None:
    from agentguard.a2a import attack_service, review_service

    url, build = (attack_url(), attack_service.build_app) if which == "attack" else (review_url(), review_service.build_app)
    uvicorn.run(build(), host=host, port=port_of(url), log_level="info")
