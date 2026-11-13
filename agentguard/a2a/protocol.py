"""JSON-RPC 2.0 envelope and agent cards for the three AgentGuard agents."""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

PROTOCOL_VERSION = "0.3.0"
AGENTS = ("discovery", "attacker", "reporter")

ERRORS = {
    "parse": (-32700, "Parse error"),
    "invalid_request": (-32600, "Invalid Request"),
    "method_not_found": (-32601, "Method not found"),
    "invalid_params": (-32602, "Invalid params"),
    "internal": (-32603, "Internal error"),
}

SKILLS = {
    "discovery": {"id": "discover", "name": "Discover entrypoints and tools",
                  "description": "Deterministic AST discovery of candidates for one project. Never runs project code."},
    "attacker": {"id": "attack", "name": "Run attack categories",
                 "description": "Runs the ADK attacker loop against a loopback target and returns findings."},
    "reporter": {"id": "report", "name": "Write the security report",
                 "description": "Turns findings into report.md and report.json. Never contacts a target."},
}


def agent_card(agent: str, base_url: str) -> dict[str, Any]:
    skill = SKILLS[agent]
    return {
        "name": f"AgentGuard {agent.capitalize()}",
        "description": skill["description"],
        "url": f"{base_url.rstrip('/')}/a2a/{agent}",
        "version": "0.1.0",
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": skill["id"], "name": skill["name"], "description": skill["description"],
                    "tags": ["agentguard", agent]}],
    }


def rpc_error(request_id: Any, kind: str, detail: Optional[str] = None) -> dict[str, Any]:
    code, message = ERRORS[kind]
    error: dict[str, Any] = {"code": code, "message": message}
    if detail:
        error["data"] = detail[:500]
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def rpc_result(request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "kind": "message",
            "messageId": uuid.uuid4().hex,
            "role": "agent",
            "parts": [{"kind": "text", "text": json.dumps(payload, default=str)}],
        },
    }


def request_payload(text_parts: list[dict[str, Any]]) -> dict[str, Any]:
    """The JSON payload carried in the first text part of a user message."""
    for part in text_parts:
        if part.get("kind") == "text" and isinstance(part.get("text"), str):
            return json.loads(part["text"])
    raise ValueError("no text part with a JSON payload")


def build_request(agent: str, payload: dict[str, Any], request_id: Optional[str] = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id or uuid.uuid4().hex,
        "method": "message/send",
        "params": {"message": {
            "kind": "message",
            "messageId": uuid.uuid4().hex,
            "role": "user",
            "parts": [{"kind": "text", "text": json.dumps(payload, default=str)}],
        }},
    }
