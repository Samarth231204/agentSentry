"""The instrumentation plan: which functions get which wrapper, and why.

The plan is data. It is written to plan.json, shown in the dashboard for review,
and validated before it is used. Only candidate ids produced by discovery are
accepted, so no plan can point at a file or line that discovery did not find.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field

from agentguard.discovery.candidates import Candidate, DiscoveryResult


class PlanItem(BaseModel):
    candidate_id: str
    role: str
    file: str
    module: str
    qualname: str
    name: str
    line: int
    include: bool = True
    sandbox: bool = False
    destructive: bool = False
    confidence: float
    source: Literal["auto", "agent", "user", "default"] = "auto"
    reason: str = ""


class InstrumentationPlan(BaseModel):
    project_root: str
    created: float = Field(default_factory=time.time)
    items: list[PlanItem] = Field(default_factory=list)

    @property
    def entrypoint(self) -> Optional[PlanItem]:
        included = [i for i in self.items if i.include and i.role == "expose"]
        return included[0] if included else None

    def validate(self, result: DiscoveryResult) -> list[str]:
        known = result.by_id()
        errors: list[str] = []
        seen: set[str] = set()
        for item in self.items:
            if item.candidate_id in seen:
                errors.append(f"duplicate candidate {item.candidate_id}")
            seen.add(item.candidate_id)
            cand = known.get(item.candidate_id)
            if cand is None:
                errors.append(f"unknown candidate id {item.candidate_id}")
                continue
            if cand.role != item.role or cand.file != item.file or cand.line != item.line:
                errors.append(f"candidate {item.candidate_id} does not match discovery")
        included_entries = [i for i in self.items if i.include and i.role == "expose"]
        if len(included_entries) != 1:
            errors.append(f"exactly one entrypoint must be included (found {len(included_entries)})")
        return errors

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "InstrumentationPlan":
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _item(cand: Candidate, include: bool, source: str, reason: str, sandbox: Optional[bool] = None) -> PlanItem:
    return PlanItem(
        candidate_id=cand.id, role=cand.role, file=cand.file, module=cand.module,
        qualname=cand.qualname, name=cand.name, line=cand.line, include=include,
        sandbox=cand.destructive if sandbox is None else sandbox,
        destructive=cand.destructive, confidence=cand.confidence,
        source=source, reason=reason or "; ".join(cand.signals),
    )


def build_plan(result: DiscoveryResult,
               agent_decisions: Optional[dict[str, tuple[bool, Optional[bool], str]]] = None) -> InstrumentationPlan:
    """Deterministic plan. Auto candidates are included; ambiguous ones only if the agent said so."""
    agent_decisions = agent_decisions or {}
    items: list[PlanItem] = []
    for cand in result.candidates:
        if cand.bucket == "auto":
            items.append(_item(cand, True, "auto", ""))
        elif cand.bucket == "ambiguous" and cand.id in agent_decisions:
            include, sandbox, reason = agent_decisions[cand.id]
            items.append(_item(cand, include, "agent", reason, sandbox))
        elif cand.bucket == "ambiguous":
            items.append(_item(cand, False, "default", "ambiguous; not included without review"))

    plan = InstrumentationPlan(project_root=result.root, items=items)
    if plan.entrypoint is None:
        # Exactly one entrypoint is required: take the highest-scoring expose candidate.
        entries = [i for i in items if i.role == "expose"]
        if entries:
            best = max(entries, key=lambda i: i.confidence)
            best.include = True
            best.source = "default"
            best.reason = (best.reason + "; chosen as the highest-scoring entrypoint").strip("; ")
    return plan


def apply_user_edits(plan: InstrumentationPlan, edits: list[dict], result: DiscoveryResult) -> InstrumentationPlan:
    """Applies a reviewer's include/sandbox choices. Candidate ids must already be in the plan.

    Works on a copy: a rejected edit leaves the original plan untouched.
    """
    plan = plan.model_copy(deep=True)
    by_id = {i.candidate_id: i for i in plan.items}
    for edit in edits:
        item = by_id.get(edit.get("candidate_id", ""))
        if item is None:
            raise ValueError(f"unknown candidate id {edit.get('candidate_id')!r}")
        if "include" in edit:
            item.include = bool(edit["include"])
        if "sandbox" in edit and edit["sandbox"] is not None:
            item.sandbox = bool(edit["sandbox"])
        item.source = "user"
    errors = plan.validate(result)
    if errors:
        raise ValueError("; ".join(errors))
    return plan


def manifest_from_plan(plan: InstrumentationPlan):
    """Builds the capability manifest the attacker routes on, from the approved plan."""
    from agentguard.manifest import Manifest, ToolInfo

    included = [i for i in plan.items if i.include]
    tools = [
        ToolInfo(name=i.name, destructive=i.destructive, file=i.file)
        for i in included if i.role == "watch"
    ]
    return Manifest(
        tools=tools,
        rag={"present": any(i.role == "watch_retrieval" for i in included), "ingestion": None},
        memory={"present": any(i.role == "watch_memory" for i in included)},
    )
