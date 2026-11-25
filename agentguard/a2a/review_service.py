"""The review service: AgentGuard's CrewAI review crew behind an A2A server (official a2a-sdk).

It receives the attack results from the ADK attack service, runs the review crew, and lets the Security
Lead re-test suspected findings by calling the attack service back over A2A (CrewAI -> ADK).
"""

from __future__ import annotations

import asyncio
import json
import re

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.apps import A2AStarletteApplication
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import Part, TextPart
from a2a.utils import new_agent_text_message, new_task

from agentguard.a2a.cards import attack_url, review_card
from agentguard.a2a.client import send_sync
from agentguard.schemas import AttackFinding, AttackReport


def parse_handoff(text: str) -> tuple[dict, AttackReport]:
    run = re.search(r"<<RUN>>(.*?)<<END_RUN>>", text, re.S)
    rep = re.search(r"<<ATTACK_REPORT>>(.*?)<<END>>", text, re.S)
    if not run or not rep:
        raise ValueError("no <<RUN>> / <<ATTACK_REPORT>> block in the message")
    return json.loads(run.group(1)), AttackReport.model_validate_json(rep.group(1))


class ReviewExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        from agentguard.review.crew import run_review

        task = context.current_task or new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)
        try:
            info, report = parse_handoff(context.get_user_input())
        except (ValueError, KeyError) as exc:
            await updater.add_artifact([Part(root=TextPart(text=json.dumps({"error": str(exc)})))], name="error")
            await updater.complete()
            return
        await updater.start_work(new_agent_text_message("Review crew started: Security Lead, Triage Analyst, "
                                                        "Report Writer, QA Reviewer", task.context_id, task.id))

        def retest(category: str, hint: str) -> AttackFinding:  # the Security Lead's A2A call back to ADK
            out = send_sync(attack_url(), {"mode": "retest", "category": category, "hint": hint, **info},
                            skill="retest", context_id=task.context_id)
            retest.usage.append(out.get("usage", {}))
            retest.target_usage.append(out.get("target_usage", {}))
            return AttackFinding.model_validate(out["finding"])
        retest.usage, retest.target_usage = [], []

        try:
            final, attacks, usage = await asyncio.to_thread(run_review, report, info["run_dir"], retest)
            result = {"report": final.model_dump(), "attack_report": attacks.model_dump(), "usage": usage,
                      "retest_usage": retest.usage, "retest_target_usage": retest.target_usage}
        except Exception as exc:  # noqa: BLE001
            result = {"error": f"review failed: {type(exc).__name__}: {str(exc)[:500]}"}
        await updater.add_artifact([Part(root=TextPart(text=json.dumps(result)))], name="final_report")
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("cancel is not supported")


def build_app():
    handler = DefaultRequestHandler(agent_executor=ReviewExecutor(), task_store=InMemoryTaskStore())
    return A2AStarletteApplication(agent_card=review_card(), http_handler=handler).build()
