"""Final report: adds cost and running time to the review crew's report and renders it as Markdown."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from agentguard.costs import usd
from agentguard.schemas import AttackReport, CostLine, FinalReport


def _sum(*usages: dict) -> dict:
    out = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0}
    for u in usages:
        for k in out:
            out[k] += int((u or {}).get(k) or 0)
    return out


def cost_lines(search_usage: dict, attacks: AttackReport, review: dict) -> list[CostLine]:
    from agentguard.attack.team import ATTACK_MODEL
    from agentguard.llm import model_name

    s = {"requests": search_usage.get("successful_requests", 0), "prompt_tokens": search_usage.get("prompt_tokens", 0),
         "completion_tokens": search_usage.get("completion_tokens", 0)}
    rows = [("Search agent (CrewAI)", model_name(), s),
            ("Attack agents (ADK)", attacks.usage.get("model", ATTACK_MODEL), _sum(attacks.usage, *review.get("retest_usage", []))),
            ("App under attack (sandbox)", attacks.target_usage.get("model", ""),
             _sum(attacks.target_usage, *review.get("retest_target_usage", []))),
            ("Review crew (CrewAI)", (review.get("usage") or {}).get("model", model_name()), _sum(review.get("usage") or {}))]
    return [CostLine(agent=a, model=m, usd=usd(m, u["prompt_tokens"], u["completion_tokens"]), **u) for a, m, u in rows]


def step_timings(trace: Path) -> tuple[dict[str, float], float]:
    """Seconds per step, from the step_started events in trace.jsonl."""
    starts: list[tuple[str, float]] = []
    first = last = None
    if trace.exists():
        for line in trace.read_text().splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            ts = datetime.fromisoformat(e["timestamp"]).timestamp()
            first = ts if first is None else first
            last = ts
            if e.get("event_type") == "step_started":
                starts.append((e["payload"].get("step", "?"), ts))
    out: dict[str, float] = {}
    for i, (step, ts) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else (last or ts)
        out[step] = round(out.get(step, 0) + end - ts, 1)
    if "review" in out and "attack" in out:  # the review runs inside the attack service's A2A call
        out["attack"] = round(max(0.0, out["attack"]), 1)
    return out, round((last or 0) - (first or 0), 1)


def a2a_calls(trace: Path) -> list[dict[str, Any]]:
    calls = []
    if trace.exists():
        for line in trace.read_text().splitlines():
            if '"a2a_result"' in line:
                try:
                    calls.append(json.loads(line)["payload"])
                except (ValueError, KeyError):
                    pass
    return calls


def finalize(report: FinalReport, run_dir: Path, run_id: str, project: str, search_usage: dict,
             attacks: AttackReport, review: dict) -> FinalReport:
    report.run_id, report.project = run_id, project
    report.cost = cost_lines(search_usage, attacks, review)
    report.total_usd = round(sum(c.usd for c in report.cost), 4)
    report.timings, report.total_seconds = step_timings(run_dir / "trace.jsonl")
    report.a2a = a2a_calls(run_dir / "trace.jsonl")
    return report


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(r: FinalReport) -> str:
    lines = [f"# {r.title}", "", f"Run `{r.run_id}` · project `{r.project}` · overall risk **{r.overall_risk.upper()}**", "",
             "## Summary", "", r.executive_summary, "", "## Findings", "",
             "| # | Finding | OWASP | Status | Severity | Entry point | Evidence |", "|---|---|---|---|---|---|---|"]
    for f in r.findings:
        lines.append(f"| {f.rank} | {_cell(f.title)} | {_cell(f.owasp)} | {f.status} | {f.severity} | "
                     f"{_cell(f.entry_point or '-')} | {', '.join(f.evidence) or '-'} |")
    lines += ["", "Statuses come from code oracles that check what really happened in the sandbox. "
                  "Risky tools were intercepted: recorded, never really run.", ""]
    for s in r.sections:
        lines += [f"### {s.category}", "", f"**What happened.** {s.what_happened}", "", f"**Impact.** {s.impact}", "",
                  f"Evidence: {', '.join(s.evidence) or '-'}", ""]
    if r.plan.retests:
        lines += ["## Re-tests (Security Lead → ADK attack agents over A2A)", ""]
        lines += [f"- **{t.category}**: {t.status_before} → {t.status_after} after {t.probes} probes. {t.reason}" for t in r.plan.retests]
        lines.append("")
    lines += ["## QA review", "", f"{'Approved' if r.qa.approved else 'Not approved'} after {r.revisions} revision(s)."]
    lines += [f"- {i}" for i in r.qa.issues] + [""]
    lines += ["## Cost and running time", "", "| Agent | Model | Requests | Prompt tokens | Output tokens | USD |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {c.agent} | {c.model} | {c.requests} | {c.prompt_tokens:,} | {c.completion_tokens:,} | ${c.usd:.4f} |" for c in r.cost]
    lines += [f"| **Total** | | | | | **${r.total_usd:.4f}** |", "",
              "Time per step: " + ", ".join(f"{k} {v:.0f}s" for k, v in r.timings.items()) + f" · total {r.total_seconds:.0f}s", ""]
    if r.a2a:
        lines += ["## A2A calls", ""] + [f"- {c.get('agent')} · {c.get('skill')} · {c.get('state')} · {c.get('seconds')}s" for c in r.a2a] + [""]
    lines += ["## Evidence", ""]
    for e in r.evidence:
        if any(e.id in f.evidence for f in r.findings) or e.oracle:
            lines += [f"### {e.id} → {e.entry_point} as {e.session}", "", "```", f"attacker: {e.attacker}", "",
                      f"target:   {e.target}", *(["", "tools:    " + "\n          ".join(e.tools)] if e.tools else []), "```",
                      *([f"Oracle: {e.oracle}"] if e.oracle else []), ""]
    return "\n".join(lines)
