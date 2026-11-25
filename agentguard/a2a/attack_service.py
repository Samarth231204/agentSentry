"""The attack service: AgentGuard's ADK attack team behind an A2A server (ADK's own to_a2a).

    mode 'attack'  run every attack type, then hand the results to the review service over A2A with
                   ADK's RemoteA2aAgent (ADK -> CrewAI), and answer with both results
    mode 'retest'  run one attack type again with the Security Lead's hint (CrewAI -> ADK)

The service is a custom ADK BaseAgent; the attack agents inside it are the LlmAgents of attack/team.py.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import AsyncGenerator

from google.adk.agents import BaseAgent
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.events import Event
from google.genai import types
from starlette.applications import Starlette

from agentguard.a2a.cards import attack_card, review_url
from agentguard.attack.team import run_attacks
from agentguard.events import emit, get_event_bus
from agentguard.schemas import AttackReport, SearchResult

START, END = "<<ATTACK_REPORT>>", "<<END>>"


def _text_event(agent: BaseAgent, ctx, text: str, partial: bool = False) -> Event:
    return Event(author=agent.name, invocation_id=ctx.invocation_id, partial=partial,
                 content=types.Content(role="model", parts=[types.Part(text=text)]))


class AttackService(BaseAgent):
    """Parses the A2A request (JSON) and runs the ADK attack team."""

    async def _run_async_impl(self, ctx) -> AsyncGenerator[Event, None]:
        raw = "".join(p.text or "" for p in (ctx.user_content.parts if ctx.user_content else []))
        try:
            req = json.loads(raw)
            search = SearchResult.model_validate(req["search"])
            project, run_dir = req["project"], Path(req["run_dir"])
        except (ValueError, KeyError) as exc:
            yield _text_event(self, ctx, json.dumps({"error": f"bad request: {exc}"}))
            return
        max_probes = int(req.get("max_probes", 4))

        if req.get("mode") == "retest":
            cat, hint = req.get("category", ""), req.get("hint", "")
            sub = run_dir / "retests" / f"{cat}-{int(time.time())}"
            sub.mkdir(parents=True, exist_ok=True)
            emit("attack", "retest_started", category=cat, hint=hint[:300])
            report = await asyncio.to_thread(run_attacks, project, search, sub, [cat], max_probes, hint)
            finding = next((f for f in report.findings if f.category == cat), None)
            yield _text_event(self, ctx, json.dumps({"finding": finding.model_dump() if finding else None,
                                                     "usage": report.usage, "target_usage": report.target_usage}))
            return

        # mode 'attack': stream progress while the team runs on a worker thread
        loop, queue = asyncio.get_running_loop(), asyncio.Queue()

        def relay(e) -> None:
            if e.event_type == "category_done":
                loop.call_soon_threadsafe(queue.put_nowait, f"{e.payload.get('category')}: {e.payload.get('status')}")
        bus = get_event_bus()
        bus.subscribe(relay)
        try:
            job = asyncio.ensure_future(asyncio.to_thread(run_attacks, project, search, run_dir, None, max_probes))
            while not job.done() or not queue.empty():
                try:
                    yield _text_event(self, ctx, await asyncio.wait_for(queue.get(), 1.0), partial=True)
                except asyncio.TimeoutError:
                    pass
            report: AttackReport = job.result()
        finally:
            bus.unsubscribe(relay)

        # hand-off to the CrewAI review service over A2A (ADK's A2A client)
        info = {"project": project, "run_dir": str(run_dir), "search": search.model_dump(), "max_probes": max_probes}
        handoff = f"Review these attack results.\n<<RUN>>{json.dumps(info)}<<END_RUN>>\n{START}{report.model_dump_json()}{END}"
        yield _text_event(self, ctx, handoff)
        reviewer = self.sub_agents[0]
        answer, t0 = "", time.perf_counter()
        emit("a2a", "a2a_call", url=review_url(), skill="security_review", via="ADK RemoteA2aAgent")
        async for ev in reviewer.run_async(ctx):
            if ev.content and ev.content.parts:
                text = "".join(p.text or "" for p in ev.content.parts)
                if text.strip().startswith("{"):
                    answer = text
        try:
            review = json.loads(answer)
        except ValueError:
            review = {"error": f"review service gave no JSON: {answer[:300]}"}
        emit("a2a", "a2a_result", url=review_url(), skill="security_review", agent="agentguard-review",
             state="completed" if "report" in review else "failed", seconds=round(time.perf_counter() - t0, 1))
        yield _text_event(self, ctx, json.dumps({"attack_report": report.model_dump(), "review": review}))


def build_app() -> Starlette:
    from google.adk.a2a.utils.agent_to_a2a import to_a2a

    card = attack_card()
    reviewer = RemoteA2aAgent(name="agentguard_review", agent_card=f"{review_url()}/.well-known/agent-card.json",
                              description="CrewAI review crew", timeout=3600)
    service = AttackService(name="agentguard_attack", description=card.description, sub_agents=[reviewer])
    return to_a2a(service, agent_card=card)
