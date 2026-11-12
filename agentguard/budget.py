"""Hard ceilings on LLM spend for one `agentguard test` run.

Every role (attacker, judge, reporter, analyst) shares one BudgetTracker
instance per run so the total cost of a scan is bounded, not just each
role individually.
"""

from __future__ import annotations

import threading
from typing import Optional

from pydantic import BaseModel, Field

from agentguard.events import get_event_bus
from agentguard.logging import get_logger
from agentguard.schemas import BudgetUsage, TraceEvent

logger = get_logger("budget")


def _emit(event_type: str, **payload: object) -> None:
    get_event_bus().emit(TraceEvent(source="budget", event_type=event_type, payload=payload))


class BudgetExceededError(Exception):
    """Raised by BudgetTracker.record() when a configured ceiling is hit."""


class BudgetConfig(BaseModel):
    max_calls_total: Optional[int] = None
    max_tokens_total: Optional[int] = None
    max_calls_per_role: dict[str, int] = Field(default_factory=dict)


class BudgetTracker:
    """Thread-safe. One instance shared across an entire `agentguard test` run."""

    def __init__(self, config: Optional[BudgetConfig] = None):
        self.config = config or BudgetConfig()
        self._lock = threading.Lock()
        self._total = BudgetUsage()
        self._by_role: dict[str, BudgetUsage] = {}
        self._exhausted = False

    @property
    def exhausted(self) -> bool:
        """True once any record() call has hit a ceiling. Stays True for the
        rest of the run so every caller can stop making LLM calls."""
        return self._exhausted

    def _exceed(self, message: str, role: str) -> BudgetExceededError:
        self._exhausted = True
        logger.warning("Budget exceeded: %s", message)
        _emit("budget_exceeded", role=role, reason=message, total=self._total.model_dump())
        return BudgetExceededError(message)

    def record(self, role: str, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """Call this after every LLM completion. Raises BudgetExceededError
        if recording this call would exceed a configured ceiling — the
        caller must catch this and stop making further LLM calls for the
        rest of the run (not just this role)."""
        with self._lock:
            role_usage = self._by_role.setdefault(role, BudgetUsage())

            new_total_calls = self._total.calls + 1
            new_total_tokens = self._total.total_tokens + prompt_tokens + completion_tokens
            new_role_calls = role_usage.calls + 1

            if self.config.max_calls_total is not None and new_total_calls > self.config.max_calls_total:
                raise self._exceed(
                    f"max_calls_total={self.config.max_calls_total} exceeded (role={role})", role
                )
            if self.config.max_tokens_total is not None and new_total_tokens > self.config.max_tokens_total:
                raise self._exceed(
                    f"max_tokens_total={self.config.max_tokens_total} exceeded (role={role})", role
                )
            role_ceiling = self.config.max_calls_per_role.get(role)
            if role_ceiling is not None and new_role_calls > role_ceiling:
                raise self._exceed(f"max_calls_per_role[{role}]={role_ceiling} exceeded", role)

            role_usage.calls = new_role_calls
            role_usage.prompt_tokens += prompt_tokens
            role_usage.completion_tokens += completion_tokens
            self._total.calls = new_total_calls
            self._total.prompt_tokens += prompt_tokens
            self._total.completion_tokens += completion_tokens

            logger.debug(
                "Budget record role=%s calls=%d/%s tokens=%d/%s",
                role, new_role_calls, role_ceiling,
                new_total_tokens, self.config.max_tokens_total,
            )
            usage_event = dict(
                role=role,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_calls=new_total_calls,
                total_tokens=new_total_tokens,
            )
        # Emit outside the lock: subscribers do file I/O.
        _emit("llm_usage", **usage_event)

    def usage_report(self) -> dict:
        """Returns {"total": BudgetUsage, "by_role": {role: BudgetUsage}} as plain dicts."""
        with self._lock:
            return {
                "total": self._total.model_dump(),
                "by_role": {k: v.model_dump() for k, v in self._by_role.items()},
            }
