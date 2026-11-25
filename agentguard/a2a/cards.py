"""Agent Cards and addresses of AgentGuard's two A2A services.

    attack service (Google ADK)  the 11 attack agents          AGENTGUARD_A2A_ATTACK_URL  (default :8771)
    review service (CrewAI)      the role-based review crew    AGENTGUARD_A2A_REVIEW_URL  (default :8772)

Each card is served at <url>/.well-known/agent-card.json (A2A protocol, JSON-RPC over HTTP).
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from a2a.types import AgentCapabilities, AgentCard, AgentProvider, AgentSkill

from agentguard.attack.categories import CATEGORIES

VERSION = "0.4.0"
PROVIDER = AgentProvider(organization="AgentGuard", url="https://github.com/")


def attack_url() -> str:
    return os.environ.get("AGENTGUARD_A2A_ATTACK_URL", "http://127.0.0.1:8771").rstrip("/")


def review_url() -> str:
    return os.environ.get("AGENTGUARD_A2A_REVIEW_URL", "http://127.0.0.1:8772").rstrip("/")


def port_of(url: str) -> int:
    return urlparse(url).port or 80


def attack_card() -> AgentCard:
    skills = [AgentSkill(id="attack", name="Run the attack team",
                         description="Runs every attack type against the project in a sandbox and hands the results "
                                     "to the review service. Input: JSON {mode:'attack', project, run_dir, search, max_probes}.",
                         tags=["red-team", "sandbox", "adk"]),
              AgentSkill(id="retest", name="Re-test one finding",
                         description="Runs one attack type again with a hint. Input: JSON {mode:'retest', category, hint, "
                                     "project, run_dir, search, max_probes}. Output: an AttackFinding.",
                         tags=["red-team", "retest"])]
    skills += [AgentSkill(id=c.id, name=c.title, description=f"{c.owasp}: {c.goal[:180]}", tags=["attack-type", c.id])
               for c in CATEGORIES]
    return AgentCard(name="agentguard-attack", version=VERSION, url=attack_url() + "/", provider=PROVIDER,
                     description="AgentGuard attack team: Google ADK agents (Claude Haiku 5.5), one per attack type, "
                                 "that attack an AI app in a sandbox. A code oracle confirms every hit.",
                     capabilities=AgentCapabilities(streaming=True), default_input_modes=["text/plain"],
                     default_output_modes=["text/plain"], skills=skills)


def review_card() -> AgentCard:
    return AgentCard(name="agentguard-review", version=VERSION, url=review_url() + "/", provider=PROVIDER,
                     description="AgentGuard review crew (CrewAI): Security Lead, Triage Analyst, Report Writer and QA "
                                 "Reviewer turn attack results into a ranked, evidence-backed report.",
                     capabilities=AgentCapabilities(streaming=True), default_input_modes=["text/plain"],
                     default_output_modes=["text/plain"],
                     skills=[AgentSkill(id="security_review", name="Security review",
                                        description="Input: an AttackReport between <<ATTACK_REPORT>> and <<END>> with "
                                                    "run info. Output: FinalReport JSON.",
                                        tags=["report", "triage", "crewai"])])
