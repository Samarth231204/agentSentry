"""Evaluation: scores for every run, and a test set with known answers (VulnLab) in LangFuse.

Run scores (on the run's LangFuse trace): confirmed/suspected counts, probes, cost, time, QA approval.
Test set: when the project is a known test project (evals/<name>.json says which), every attack type is a
LangFuse dataset item with its expected result, and the run is recorded as a dataset run with a
'detected' score per item, plus detection rate and false alarms for the run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from agentguard.schemas import AttackReport, FinalReport

EVALS = Path(__file__).resolve().parents[1] / "evals"


def run_scores(report: FinalReport, attacks: AttackReport) -> dict[str, float]:
    return {"confirmed": float(sum(f.status == "confirmed" for f in attacks.findings)),
            "suspected": float(sum(f.status == "suspected" for f in attacks.findings)),
            "probes": float(sum(len(f.probes) for f in attacks.findings)),
            "cost_usd": report.total_usd, "seconds": report.total_seconds,
            "qa_approved": 1.0 if report.qa.approved else 0.0, "revisions": float(report.revisions)}


def dataset_for(project: str | Path) -> Optional[dict[str, Any]]:
    name = Path(project).resolve().name
    for f in sorted(EVALS.glob("*.json")):
        spec = json.loads(f.read_text())
        if name in spec.get("project_names", []):
            return spec
    return None


def score_against(spec: dict[str, Any], attacks: AttackReport) -> dict[str, Any]:
    """Per attack type: did AgentGuard confirm what is known to be there, and nothing that is not?"""
    got = {f.category: f.status for f in attacks.findings}
    items, hits, expected_n, false_alarms = [], 0, 0, 0
    for cat, expected in spec["expected"].items():
        status = got.get(cat, "not_tested")
        detected = status == "confirmed"
        if expected == "confirmed":
            expected_n += 1
            hits += detected
        elif detected:
            false_alarms += 1
        items.append({"category": cat, "expected": expected, "status": status,
                      "correct": detected == (expected == "confirmed")})
    return {"dataset": spec["dataset"], "items": items, "detection_rate": round(hits / max(1, expected_n), 3),
            "false_alarms": false_alarms, "detected": hits, "expected": expected_n}


def push_to_langfuse(spec: dict[str, Any], result: dict[str, Any], run_id: str) -> str:
    """Creates the dataset (once) and records this run as a dataset run. Returns a status line."""
    from langfuse import Langfuse

    from agentguard.observability import NOISY_SCOPES
    lf = Langfuse(blocked_instrumentation_scopes=NOISY_SCOPES)  # same settings as the run's tracer
    try:
        lf.get_dataset(spec["dataset"])
    except Exception:  # noqa: BLE001  (not found)
        lf.create_dataset(name=spec["dataset"], description=spec.get("description", ""))
    for it in result["items"]:
        lf.create_dataset_item(dataset_name=spec["dataset"], id=f"{spec['dataset']}-{it['category']}",
                               input={"attack_type": it["category"]}, expected_output={"status": it["expected"]})
    dataset = lf.get_dataset(spec["dataset"])
    by_cat = {it["category"]: it for it in result["items"]}
    for item in dataset.items:
        it = by_cat.get((item.input or {}).get("attack_type"))
        if not it:
            continue
        with item.run(run_name=run_id, run_metadata={"run_id": run_id}) as span:
            span.update(output={"status": it["status"]})
            span.score_trace(name="detected", value=1.0 if it["status"] == "confirmed" else 0.0)
            span.score_trace(name="correct", value=1.0 if it["correct"] else 0.0)
    lf.flush()
    return f"LangFuse dataset '{spec['dataset']}': run {run_id} recorded ({len(result['items'])} items)"
