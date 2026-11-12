"""Typed contracts shared across AgentGuard's agents and modules.

This is the single source of truth for what a "finding" is. Every other
module (attackers, judge, classifier, reporters) imports from here instead
of building its own dict shape.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


class ProbeOutcome(str, Enum):
    """What kind of thing happened when we sent one probe to the target.

    Produced by agentguard.classifier.classify_response(). This is NOT the
    same as attack success — a SUCCESS outcome means the target engaged
    normally with the adversarial input, which is a *prerequisite* for an
    oracle to detect compromise, not proof of compromise itself.
    """
    SUCCESS = "success"                    # target produced a normal, on-topic response
    REFUSAL = "refusal"                    # the underlying model declined (its own judgment)
    GUARDRAIL_BLOCK = "guardrail_block"    # an app-level filter blocked the request/response
    TARGET_RATE_LIMITED = "target_rate_limited"
    TARGET_ERROR = "target_error"
    TIMEOUT = "timeout"
    INCONCLUSIVE = "inconclusive"          # none of the above matched confidently


class OracleType(str, Enum):
    CANARY = "canary"
    SIDE_EFFECT = "side_effect"
    LLM_JUDGE = "llm_judge"
    MANIFEST_DIFF = "manifest_diff"


class AttemptStatus(str, Enum):
    CONFIRMED = "confirmed"    # a deterministic oracle (canary/side_effect/manifest_diff) fired
    SUSPECTED = "suspected"    # only the LLM judge believes this succeeded
    FAILED = "failed"          # no oracle fired, judge says no
    ERROR = "error"            # attempt could not be completed (target unreachable, etc.)


class ToolCallRecord(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class Turn(BaseModel):
    """One probe sent, one response received."""
    sent: str
    received: Optional[str] = None
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    outcome: ProbeOutcome = ProbeOutcome.INCONCLUSIVE
    error: Optional[dict[str, str]] = None  # {"type": ..., "detail": ...}


class Finding(BaseModel):
    """Replaces the loose dict previously appended to FindingsSink.attempts."""
    id: str = Field(default_factory=lambda: f"finding-{uuid.uuid4().hex[:8]}")
    category: str
    capability_targeted: str
    turns: list[Turn] = Field(default_factory=list)
    oracle: Optional[OracleType] = None
    oracle_detail: Optional[str] = None
    status: AttemptStatus = AttemptStatus.FAILED
    confidence: float = 0.0  # 0.0-1.0, set by judge.py when oracle == LLM_JUDGE; 1.0 for deterministic oracles

    @computed_field
    @property
    def success(self) -> bool:
        """Backward-compat shim: existing code (reporters.py, cli.py) checks
        attempt.get('success'). Keep this property so compute_scorecard still
        works without modification. CONFIRMED and SUSPECTED both count."""
        return self.status in (AttemptStatus.CONFIRMED, AttemptStatus.SUSPECTED)

    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)


class Report(BaseModel):
    scorecard: dict[str, Any]
    findings: list[Finding]
    severity: dict[str, str]
    remediation: dict[str, str]
    # Filled deterministically by reporters._enrich_report() after the crew
    # (or the fallback) runs, so every report carries them regardless of
    # whether the LLM produced them. Defaults keep CrewAI output_pydantic
    # validation unchanged.
    owasp: dict[str, str] = Field(default_factory=dict)            # finding id -> OWASP LLM Top 10 entry
    code_references: dict[str, list[str]] = Field(default_factory=dict)  # finding id -> ["file:line: code"]
    generated_by: str = "llm"  # "llm" or "deterministic_fallback"


class TargetProfile(BaseModel):
    tools: list[str]
    has_rag: bool
    has_memory: bool
    purpose: Optional[str] = None
    system_prompt_hint: Optional[str] = None


class TraceEvent(BaseModel):
    """One row in the monitoring event stream. See events.py."""
    timestamp: float = Field(default_factory=time.time)
    source: str              # e.g. "attacker.prompt_injection", "judge", "classifier"
    event_type: str          # e.g. "probe_sent", "probe_received", "llm_call", "budget_warning", "error"
    payload: dict[str, Any] = Field(default_factory=dict)


class BudgetUsage(BaseModel):
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens
