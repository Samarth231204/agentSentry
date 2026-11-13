"""MCP server (ours): security knowledge. Streamable HTTP on 127.0.0.1.

Tools: owasp_lookup, cwe_lookup, remediation_template, probe_library.
Static content only: nothing here calls a network service.
Run with: python -m agentguard.mcp.security_kb_server --port 8791
"""

from __future__ import annotations

import argparse

from mcp.server.fastmcp import FastMCP

from agentguard.mcp_server import lookup_owasp

mcp = FastMCP("agentguard-security-kb")

CWE = {
    "CWE-77": "Improper neutralization of special elements used in a command (command injection)",
    "CWE-78": "Improper neutralization of special elements used in an OS command",
    "CWE-94": "Improper control of generation of code (code injection)",
    "CWE-200": "Exposure of sensitive information to an unauthorized actor",
    "CWE-285": "Improper authorization",
    "CWE-306": "Missing authentication for critical function",
    "CWE-639": "Authorization bypass through user-controlled key",
    "CWE-862": "Missing authorization",
    "CWE-1039": "Automated recognition mechanism with inadequate detection or handling of adversarial input perturbations",
}

REMEDIATION = {
    "tool_misuse": ("Require an explicit confirmation step, with amount and recipient limits, before any "
                    "destructive tool runs. Keep destructive tools out of the model's direct reach."),
    "prompt_injection": ("Separate instructions from data, treat retrieved and user text as untrusted, and "
                         "validate tool arguments outside the model."),
    "secret_extraction": ("Do not place secrets in system prompts. Load them server-side and never echo them "
                          "to the model or the user."),
    "data_exfiltration": ("Restrict outbound destinations with an allow-list and redact sensitive fields before "
                          "any external call."),
    "privilege_escalation": ("Enforce authorization in code for every tool, not in the prompt."),
    "rag_poisoning": ("Sanitise and provenance-check ingested documents; never let retrieved text change "
                      "instructions or tool use."),
    "memory_persistence": ("Scope and expire long-term memory; do not store untrusted instructions."),
}


@mcp.tool()
def owasp_lookup(category: str) -> str:
    """OWASP LLM Top 10 entry for an AgentGuard attack category."""
    return lookup_owasp(category)


@mcp.tool()
def cwe_lookup(cwe_id: str) -> str:
    """Short description for a CWE id such as CWE-78. Unknown ids return a clear message."""
    key = cwe_id.strip().upper()
    if not key.startswith("CWE-"):
        key = f"CWE-{key}"
    return CWE.get(key, f"{key} is not in the local table; see https://cwe.mitre.org/")


@mcp.tool()
def remediation_template(category: str) -> str:
    """Generic remediation guidance for an attack category (used when no model is available)."""
    return REMEDIATION.get(category, "Review the affected code path and add deterministic checks.")


@mcp.tool()
def probe_library(category: str) -> str:
    """The attack playbook AgentGuard uses for a category (text only)."""
    from agentguard.attackers import PLAYBOOKS
    return PLAYBOOKS.get(category, f"no playbook for {category}")


@mcp.resource("owasp://llm-top-10")
def owasp_resource() -> str:
    return "\n".join(lookup_owasp(c) for c in REMEDIATION)


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentGuard security-knowledge MCP server")
    parser.add_argument("--port", type=int, default=8791)
    args = parser.parse_args()
    mcp.settings.host = "127.0.0.1"
    mcp.settings.port = args.port
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
