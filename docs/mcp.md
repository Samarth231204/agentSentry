# MCP servers

AgentGuard has two MCP servers of its own, plus one external server. All use the MCP Streamable HTTP transport, and every
call goes through one traced client.

## Our servers

Started by `agentguard up` (skip with `--no-mcp`). Run one alone with `agentguard mcp serve`.

**Code intelligence** (`agentguard/mcp/codeintel_server.py`, port 8790, rooted at the project):

| Tool | What it returns |
|---|---|
| `search_code(query, max_results)` | `path:line: text` matches, case-insensitive |
| `list_candidates(role?)` | discovery candidates with confidence and signals |
| `get_symbol(file, qualname)` | location, decorators, calls, framework signals |
| `callers(name)` / `callees(file, qualname)` | the call relations, by last name segment |
| `read_span(file, start, end)` | numbered source lines (at most 200) |
| `list_routes()` | HTTP route handlers and their paths |

Paths must be existing `.py` files inside the project root. Anything else is refused.

**Security knowledge** (`agentguard/mcp/security_kb_server.py`, port 8791, static content only):
`owasp_lookup`, `cwe_lookup`, `remediation_template`, `probe_library`, and the resource `owasp://llm-top-10`.

## External server: Semgrep

The official Semgrep MCP server (`semgrep-mcp==0.8.1`, pinned) runs as a stdio subprocess through `uvx`, in its own
environment. It needs the `semgrep` binary on PATH. Its tool `semgrep_scan_with_custom_rule` runs our sink rules
(`agentguard/discovery/rules/sinks.yaml`) over the project. Each hit adds evidence to the function that contains it.

Why it runs separately: `semgrep-mcp` depends on an older MCP SDK than the one CrewAI needs, so it cannot share our venv.
Version 0.9.0 exposes only a deprecation notice without Semgrep's Pro Engine, so we pin 0.8.1.

## Tracing

Every call writes `mcp_tool_call` and then `mcp_tool_result` (with latency and a 300-character preview), or `mcp_error`.
If a server is unavailable, the run records `mcp_unavailable` and continues without it. The run's MCP panel shows counts per
server and tool.

## Where the servers are used

- Discovery agent (ADK): an `McpToolset` over the code-intelligence server, with `read_span`, `callers`, `callees`, `get_symbol`.
- Reporter (CrewAI): `MCPServerHTTP` for both of our servers, falling back to the stdio server when they are not running.
- Discovery itself: Semgrep, when available.

Not yet proven live: the two model-driven uses above. Both need a provider run.
