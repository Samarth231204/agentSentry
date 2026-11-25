"""Event bus: every agent thought, tool call, MCP call and step goes through emit().

A run subscribes a JSONL sink (trace.jsonl) and the dashboard reads that file live.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable, Optional

from agentguard.schemas import TraceEvent

Subscriber = Callable[[TraceEvent], None]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subscribers.append(fn)

    def unsubscribe(self, fn: Subscriber) -> None:
        with self._lock:
            if fn in self._subscribers:
                self._subscribers.remove(fn)

    def emit(self, event: TraceEvent) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for fn in subs:
            try:
                fn(event)
            except Exception:  # noqa: BLE001  a broken subscriber must never crash the run
                pass


class JSONLFileSink:
    """Appends each event as one JSON line."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def __call__(self, event: TraceEvent) -> None:
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")


_global_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _global_bus
    if _global_bus is None:
        _global_bus = EventBus()
    return _global_bus


def emit(source: str, event_type: str, **payload: Any) -> None:
    get_event_bus().emit(TraceEvent(source=source, event_type=event_type, payload=payload))


def reset_event_bus() -> None:
    """For test isolation only."""
    global _global_bus
    _global_bus = None
