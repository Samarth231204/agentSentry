"""Typed data that moves between AgentGuard's steps. Every agent output is one of these models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TraceEvent(BaseModel):
    """One line of trace.jsonl: who did what, when."""
    source: str
    event_type: str
    timestamp: str = Field(default_factory=_now)
    payload: dict[str, Any] = Field(default_factory=dict)


# ---- Deterministic scan (the MCP scan_project tool) ------------------------------------------

class CodeSite(BaseModel):
    """One place in the user's code: an LLM call, a tool, a prompt or an entry point."""
    id: str
    kind: Literal["llm_call", "tool", "prompt", "entry_point"]
    name: str
    file: str
    line: int
    end_line: int
    function: str = ""          # enclosing function (qualified name), "" at module level
    code: str = ""              # the source line(s), trimmed
    signals: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    root: str
    files_scanned: int = 0
    frameworks: list[str] = Field(default_factory=list)
    llm_calls: list[CodeSite] = Field(default_factory=list)
    tools: list[CodeSite] = Field(default_factory=list)
    prompts: list[CodeSite] = Field(default_factory=list)
    entry_points: list[CodeSite] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ---- Search agent output -----------------------------------------------------------------------

Risk = Literal["critical", "high", "medium", "low"]


class MainLLMCall(BaseModel):
    file: str
    line: int
    function: str = Field(description="Function that makes the call")
    entry_point: str = Field(default="", description="Function that receives the end user's message, as file:function")
    system_prompt: str = Field(default="", description="Where the system prompt is defined, as file:line, or ''")
    reason: str = Field(description="Why this is the main LLM call")


class RiskyTool(BaseModel):
    name: str
    file: str
    line: int
    risk: Risk
    capability: str = Field(description="What the tool can do in the real world, e.g. 'moves money'")
    reason: str = Field(description="Why an attacker would target it")
    model_can_call: bool = Field(default=True, description="True if the LLM chooses when to call it")

    @field_validator("risk", mode="before")
    @classmethod
    def _lower(cls, v: Any) -> Any:
        return v.lower().strip() if isinstance(v, str) else v


class OtherLLMCall(BaseModel):
    file: str
    line: int
    function: str = ""
    purpose: str = ""


class EntryPoint(BaseModel):
    """A Python function the end user's message enters through. AgentGuard calls it to attack the app."""
    id: str = Field(description="Short unique slug, e.g. 'bank_chat'")
    file: str = Field(description="Project-relative path of the file that defines the function")
    function: str = Field(description="Function name, or Class.method for a method")
    message_param: str = Field(description="Name of the parameter that receives the user's message")
    session_param: str = Field(default="", description="Parameter that identifies the user or session, or ''")
    description: str = Field(default="", description="What this entry point does and which tools it reaches")


class SearchResult(BaseModel):
    summary: str = Field(description="Two or three sentences: what the agent does and where it is exposed")
    main_llm_call: Optional[MainLLMCall] = None
    entry_points: list[EntryPoint] = Field(default_factory=list)
    risky_tools: list[RiskyTool] = Field(default_factory=list)
    safe_tools: list[str] = Field(default_factory=list, description="Tools that only read harmless data")
    other_llm_calls: list[OtherLLMCall] = Field(default_factory=list)


# ---- Attack phase --------------------------------------------------------------------------------

class ToolCall(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    intercepted: bool = False   # True: recorded and faked, never really executed
    result: str = ""


class Probe(BaseModel):
    """One message the attacker sent and what the target did with it."""
    entry_point: str
    session: str = ""
    message: str
    reply: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    error: str = ""
    latency_ms: float = 0
    web_reads: list[str] = Field(default_factory=list, description="Trap pages ('page:<id>') and beacons ('beacon:<id>') the target opened")
    flags: list[str] = Field(default_factory=list)   # guardrail flags on the target's reply


Status = Literal["confirmed", "suspected", "resisted", "not_tested"]


class AttackFinding(BaseModel):
    category: str
    title: str
    owasp: str
    status: Status
    entry_point: str = ""
    detail: str = Field(default="", description="Why the oracle (or the attacker) says it worked")
    oracle: str = ""
    probes: list[Probe] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list, description="Payload-library techniques and disguises the attack agent used")
    evidence: Optional[int] = Field(default=None, description="Index of the probe that proves it")


class AttackReport(BaseModel):
    findings: list[AttackFinding] = Field(default_factory=list)
    confirmed: int = 0
    suspected: int = 0
    resisted: int = 0
    probes: int = 0
    usage: dict[str, Any] = Field(default_factory=dict)
    target_usage: dict[str, Any] = Field(default_factory=dict, description="Tokens the app under attack used")


# ---- Review phase (CrewAI review crew) -------------------------------------------------------------

Severity = Literal["critical", "high", "medium", "low", "info"]


class Retest(BaseModel):
    category: str
    reason: str = ""
    status_before: str = ""
    status_after: str = ""
    detail: str = ""
    probes: int = 0


class LeadPlan(BaseModel):
    """Security Lead: what the review should focus on, and which findings were re-tested over A2A."""
    focus: list[str] = Field(default_factory=list, description="Finding categories that matter most, in order")
    retests: list[Retest] = Field(default_factory=list, description="Re-tests asked of the ADK attack agents")
    notes_for_triage: str = ""


class TriagedFinding(BaseModel):
    category: str
    title: str
    status: Literal["confirmed", "suspected", "resisted", "not_tested"]
    severity: Severity
    rank: int = Field(description="1 = most urgent")
    duplicate_of: str = Field(default="", description="Category this one duplicates, if any")
    rationale: str = Field(description="Why this severity: impact and how easy it was")
    evidence: list[str] = Field(default_factory=list, description="Probe ids such as 'tool_misuse#2'")


class TriageResult(BaseModel):
    overall_risk: Severity
    findings: list[TriagedFinding]


class ReportSection(BaseModel):
    category: str
    what_happened: str = Field(description="Plain-language account of the attack and the target's behaviour")
    impact: str = Field(description="What a real attacker could do with this")
    evidence: list[str] = Field(default_factory=list, description="Probe ids backing every claim")


class ReportDraft(BaseModel):
    """Report Writer's prose. Tables, evidence and cost are filled in by code from the real data."""
    title: str
    executive_summary: str
    sections: list[ReportSection]


class QAReview(BaseModel):
    approved: bool
    issues: list[str] = Field(default_factory=list, description="Each unsupported or wrong claim, and how to fix it")


class ReportRow(BaseModel):
    rank: int
    category: str
    title: str
    owasp: str
    status: str
    severity: str
    entry_point: str = ""
    evidence: list[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    id: str
    entry_point: str
    session: str
    attacker: str
    target: str
    tools: list[str] = Field(default_factory=list)
    oracle: str = ""


class CostLine(BaseModel):
    agent: str
    model: str
    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0


class FinalReport(BaseModel):
    run_id: str = ""
    project: str = ""
    title: str
    overall_risk: Severity
    executive_summary: str
    findings: list[ReportRow]
    sections: list[ReportSection]
    evidence: list[EvidenceItem]
    plan: LeadPlan
    qa: QAReview
    revisions: int = 0
    cost: list[CostLine] = Field(default_factory=list)
    total_usd: float = 0.0
    timings: dict[str, float] = Field(default_factory=dict, description="Seconds per step")
    total_seconds: float = 0.0
    a2a: list[dict[str, Any]] = Field(default_factory=list, description="A2A calls made in this run")
