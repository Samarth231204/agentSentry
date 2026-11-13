"""Minimal pub/sub event bus for run-time monitoring.

Phase 1 only needs: something can emit() a TraceEvent, something can
subscribe() to receive them, and one default subscriber persists them to
disk. Deeper integration (wiring this into every ADK/CrewAI callback) is
Phase 2 — do not add that here.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable, Optional

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
            except Exception:
                # A broken subscriber must never crash the run.
                pass


class JSONLFileSink:
    """Subscriber that appends each event as one JSON line to a file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def __call__(self, event: TraceEvent) -> None:
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")


_global_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _global_bus
    if _global_bus is None:
        _global_bus = EventBus()
    return _global_bus


def reset_event_bus() -> None:
    """For test isolation only."""
    global _global_bus
    _global_bus = None
