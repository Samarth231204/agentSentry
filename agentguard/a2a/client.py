"""A2A client (official a2a-sdk): send one JSON task to an AgentGuard service and wait for its result.

Every call is traced: a2a_call / a2a_update / a2a_result events, with the card name, skill and latency.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from typing import Any

import httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, TextPart

from agentguard.events import emit

TIMEOUT = 3600.0
CALLS: list[dict] = []   # A2A calls made by this process (for the report)


def _texts(task) -> list[str]:
    out = [p.root.text for a in (task.artifacts or []) for p in a.parts if getattr(p.root, "text", None)]
    if not out and task.status.message:
        out = [p.root.text for p in task.status.message.parts if getattr(p.root, "text", None)]
    return out


async def send(url: str, payload: dict[str, Any], skill: str = "", context_id: str = "",
               timeout: float = TIMEOUT) -> dict[str, Any]:
    """Sends payload (as JSON text) and returns the JSON object the service answers with."""
    started = time.perf_counter()
    emit("a2a", "a2a_call", url=url, skill=skill or payload.get("mode", ""), context_id=context_id)
    async with httpx.AsyncClient(timeout=timeout) as hc:
        card = await A2ACardResolver(hc, url).get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=True)).create(card)
        msg = Message(role=Role.user, message_id=uuid.uuid4().hex, context_id=context_id or None,
                      parts=[Part(root=TextPart(text=json.dumps(payload)))])
        final: list[str] = []
        state = ""
        async for item in client.send_message(msg):
            if isinstance(item, Message):
                final = [p.root.text for p in item.parts if getattr(p.root, "text", None)]
                continue
            task, update = item
            state = str(task.status.state.value if hasattr(task.status.state, "value") else task.status.state)
            if task.status.message and type(update).__name__ == "TaskStatusUpdateEvent":
                text = " ".join(p.root.text for p in task.status.message.parts if getattr(p.root, "text", None))
                if text and not text.startswith("{"):
                    emit("a2a", "a2a_update", agent=card.name, state=state, text=text[:300])
            final = _texts(task) or final
    latency = round(time.perf_counter() - started, 1)
    record = {"agent": card.name, "url": url, "skill": skill or payload.get("mode", ""), "state": state,
              "seconds": latency}
    CALLS.append(record)
    emit("a2a", "a2a_result", **record)
    for text in reversed(final):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                if "error" in data and len(data) == 1:
                    raise RuntimeError(f"{card.name}: {data['error']}")
                return data
        except ValueError:
            continue
    raise RuntimeError(f"{card.name} returned no JSON result (state {state}): {' '.join(final)[:300]}")


def send_sync(url: str, payload: dict[str, Any], **kw: Any) -> dict[str, Any]:
    """send() from synchronous code, on its own thread and event loop."""
    out: dict = {}

    def work():
        try:
            out["v"] = asyncio.run(send(url, payload, **kw))
        except BaseException as exc:  # noqa: BLE001
            out["e"] = exc
    t = threading.Thread(target=work, name="agentguard-a2a-client")
    t.start()
    t.join()
    if "e" in out:
        raise out["e"]
    return out["v"]
