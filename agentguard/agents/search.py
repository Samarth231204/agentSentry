"""The Search agent: finds the main LLM call and the tools an attacker would target.

It is one CrewAI ReAct agent. Each step it writes a Thought, picks an Action (one of its tools),
reads the Observation, and repeats until it can give a typed SearchResult.

  SearchFlow (CrewAI Flow, checkpointed to SQLite after every step)
    1. scan    deterministic: our agentguard-scan MCP server, tool scan_project
    2. search  the Search agent verifies and ranks the scan, using
                 agentguard-scan MCP: search_code, read_code, list_files
                 Semgrep MCP (external): semgrep_search
    3. save    writes search.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional, Type

from crewai import Agent, Crew, Process, Task
from crewai.flow.flow import Flow, FlowState, listen, start
from crewai.state.checkpoint_config import CheckpointConfig
from crewai.state.provider.sqlite_provider import SqliteProvider
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from agentguard.events import emit
from agentguard.llm import crew_llm, model_name
from agentguard.mcp.client import ServerSpec, call
from agentguard.mcp.semgrep import semgrep_search
from agentguard.schemas import ScanReport, SearchResult

MAX_OBSERVATION = 6000


# ---- MCP access -------------------------------------------------------------------------------

def scan_server(project: str | Path) -> ServerSpec:
    """Our MCP server, started over stdio for the given project."""
    repo = str(Path(__file__).resolve().parents[2])
    env = {**os.environ, "AGENTGUARD_PROJECT": str(Path(project).resolve()),
           "PYTHONPATH": os.pathsep.join([repo, os.environ.get("PYTHONPATH", "")])}
    return ServerSpec(name="agentguard-scan", transport="stdio",
                      command=[sys.executable, "-m", "agentguard.mcp.scan_server"], env=env)


def call_scan_tool(project: str | Path, tool: str, args: Optional[dict] = None) -> Any:
    out = call(scan_server(project), tool, args or {}, timeout=120)
    if out["is_error"]:
        raise RuntimeError(out["text"][:500])
    structured = out.get("structured")
    if isinstance(structured, dict) and set(structured) == {"result"}:
        structured = structured["result"]  # FastMCP wraps non-dict returns
    if structured is not None:
        return structured
    try:  # dict/list results may arrive only as JSON text
        return json.loads(out["text"])
    except ValueError:
        return out["text"]


def _clip(text: str) -> str:
    return text if len(text) <= MAX_OBSERVATION else text[:MAX_OBSERVATION] + "\n... (cut, ask for less)"


# ---- The agent's tools (each one is an MCP call) -------------------------------------------------

class _SearchArgs(BaseModel):
    pattern: str = Field(description="Python regular expression, case-insensitive")
    file_glob: str = Field(default="", description="Optional file filter such as '*.py'")


class _ReadArgs(BaseModel):
    file: str = Field(description="Project-relative path, e.g. app.py")
    start_line: int = Field(default=1)
    end_line: int = Field(default=80)


class _SemgrepArgs(BaseModel):
    pattern: str = Field(description="A Semgrep pattern, e.g. '$X.messages.create(...)' or 'subprocess.run(...)'")


class _NoArgs(BaseModel):
    pass


class _ProjectTool(BaseTool):
    project: str = ""


class SearchCodeTool(_ProjectTool):
    name: str = "search_code"
    description: str = "Regex search over the project's files (MCP agentguard-scan). Returns file:line: text."
    args_schema: Type[BaseModel] = _SearchArgs

    def _run(self, pattern: str, file_glob: str = "") -> str:
        return _clip(str(call_scan_tool(self.project, "search_code", {"pattern": pattern, "file_glob": file_glob})))


class ReadCodeTool(_ProjectTool):
    name: str = "read_code"
    description: str = "Reads numbered lines of a project file (MCP agentguard-scan). At most 200 lines."
    args_schema: Type[BaseModel] = _ReadArgs

    def _run(self, file: str, start_line: int = 1, end_line: int = 80) -> str:
        return _clip(str(call_scan_tool(self.project, "read_code",
                                        {"file": file, "start_line": start_line, "end_line": end_line})))


class ListFilesTool(_ProjectTool):
    name: str = "list_files"
    description: str = "Lists the project's source and text files (MCP agentguard-scan)."
    args_schema: Type[BaseModel] = _NoArgs

    def _run(self) -> str:
        files = call_scan_tool(self.project, "list_files")
        return _clip("\n".join(files) if isinstance(files, list) else str(files))


class SemgrepSearchTool(_ProjectTool):
    name: str = "semgrep_search"
    description: str = ("Structural code search with Semgrep (external MCP server). Finds calls by shape, "
                        "ignoring variable names, e.g. '$C.chat.completions.create(...)', "
                        "'requests.post(...)', 'subprocess.$F(...)', 'eval(...)'.")
    args_schema: Type[BaseModel] = _SemgrepArgs

    def _run(self, pattern: str) -> str:
        return _clip(semgrep_search(self.project, pattern))


def search_tools(project: str) -> list[BaseTool]:
    return [cls(project=project) for cls in (SearchCodeTool, ReadCodeTool, ListFilesTool, SemgrepSearchTool)]


# ---- ReAct monitoring: every Thought, Action and Observation goes to the trace ------------------
# CrewAI runs native tool calls in parallel and calls step_callback only at the end, so the
# individual steps come from CrewAI's event bus. Handlers are registered once, per agent role.

AGENT_ROLE = "Search agent"
_registered = False


def react_thought(response: Any) -> str:
    """The Thought part of a text ReAct reply ('Thought: ... Action: ...' or '... Final Answer: ...')."""
    if not isinstance(response, str):
        return ""
    text = response
    for marker in ("\nAction:", "\nFinal Answer:", "Action:", "Final Answer:"):
        if marker in text:
            text = text.split(marker, 1)[0]
            break
    text = text.strip()
    return text[len("Thought:"):].strip() if text.startswith("Thought:") else text


def register_monitoring() -> None:
    global _registered
    if _registered:
        return
    _registered = True
    from crewai.events import (LLMCallCompletedEvent, ToolUsageErrorEvent, ToolUsageFinishedEvent,
                               ToolUsageStartedEvent, crewai_event_bus)

    def mine(event: Any) -> bool:
        role = getattr(event, "agent_role", None) or getattr(getattr(event, "from_agent", None), "role", None)
        return role == AGENT_ROLE

    @crewai_event_bus.on(LLMCallCompletedEvent)
    def _llm(source: Any, event: Any) -> None:
        if not mine(event):
            return
        usage = event.usage if isinstance(event.usage, dict) else {}
        emit("search_agent", "llm_call", model=event.model, finish_reason=event.finish_reason,
             prompt_tokens=usage.get("prompt_tokens"), completion_tokens=usage.get("completion_tokens"))
        thought = react_thought(event.response)
        if thought:  # the model's reply arrives before its tool runs, so the Thought comes first
            emit("search_agent", "thought", text=thought[:3000])

    @crewai_event_bus.on(ToolUsageStartedEvent)
    def _action(source: Any, event: Any) -> None:
        if mine(event):
            emit("search_agent", "action", tool=event.tool_name, input=str(event.tool_args)[:1000])

    @crewai_event_bus.on(ToolUsageFinishedEvent)
    def _observation(source: Any, event: Any) -> None:
        if mine(event):
            emit("search_agent", "observation", tool=event.tool_name, text=str(event.output)[:3000])

    @crewai_event_bus.on(ToolUsageErrorEvent)
    def _tool_error(source: Any, event: Any) -> None:
        if mine(event):
            emit("search_agent", "observation", tool=event.tool_name, error=str(getattr(event, "error", ""))[:1000])


def _step_callback(step: Any) -> None:
    """End of a ReAct step. Thoughts, actions and observations are already traced from the event bus."""
    if not getattr(step, "tool", "") and hasattr(step, "output"):  # AgentFinish
        emit("search_agent", "final_answer", text=str(step.output)[:3000])


def _task_callback(output: Any) -> None:
    emit("search_agent", "task_done", summary=str(getattr(output, "raw", output))[:500])


# ---- Prompt ------------------------------------------------------------------------------------

def _scan_digest(scan: ScanReport) -> str:
    def rows(items) -> str:
        return "\n".join(f"  - [{s.id}] {s.name} at {s.file}:{s.line}"
                         + (f" in {s.function}()" if s.function else "")
                         + (f"  signals: {', '.join(s.signals)}" if s.signals else "")
                         + f"\n      code: {s.code.splitlines()[0][:160] if s.code else ''}"
                         for s in items[:40]) or "  (none found)"
    return (f"Project: {scan.root}\nFiles scanned: {scan.files_scanned}\n"
            f"Frameworks imported: {', '.join(scan.frameworks) or 'none recognised'}\n\n"
            f"LLM call sites:\n{rows(scan.llm_calls)}\n\nTool definitions:\n{rows(scan.tools)}\n\n"
            f"Prompts:\n{rows(scan.prompts)}\n\nFunctions that take a message:\n{rows(scan.entry_points)}\n"
            + (f"\nFiles that failed to parse: {'; '.join(scan.errors[:5])}\n" if scan.errors else ""))


TASK = """You are given a static scan of an AI agent's code. It is a hint list: it can miss things
(tools registered in unusual ways, wrapper functions around the model call) and it can include
noise (a function that merely has a 'query' parameter).

SCAN
{digest}

Find, by reading the real code:
1. The MAIN LLM call: the model call that handles the end user's message, the function the user's
   message enters through (entry point), and where its system prompt is defined.
2. Every tool the model can call, and for each one what it can do in the real world. Rate risk:
   critical = moves money, changes permissions, runs code or deletes data;
   high = sends messages or data outside, reads other users' private data, writes data;
   medium = reads internal data, fetches URLs; low = harmless reads (time, weather, static FAQ).
   List only harmless tools under safe_tools.
3. Any other LLM calls (summarisers, judges, embeddings) and their purpose.

Work step by step: confirm each scan item with read_code, use search_code or semgrep_search to
look for tools or model calls the scan missed (e.g. tool registries in other files, 'tools=' or
'"name":' schemas, '.create(', 'completion(', 'invoke('). Only report file:line locations you have
seen in the code. Be efficient: at most about 12 tool calls.

In every Thought, say what you learned from the last Observation and what you will check next."""


# ---- The flow ----------------------------------------------------------------------------------

class SearchState(FlowState):
    project: str = ""
    run_dir: str = ""
    scan: dict = Field(default_factory=dict)
    result: dict = Field(default_factory=dict)
    usage: dict = Field(default_factory=dict)
    step: str = "pending"


def checkpoint_config(run_dir: str | Path, events: list[str]) -> CheckpointConfig:
    """Every agent in AgentGuard checkpoints into its run's checkpoints.db."""
    return CheckpointConfig(location=str(Path(run_dir) / "checkpoints.db"), provider=SqliteProvider(),
                            on_events=events, max_checkpoints=50)


def build_crew(project: str, scan: ScanReport, run_dir: str) -> Crew:
    register_monitoring()
    agent = Agent(
        role=AGENT_ROLE,
        goal="Locate the main LLM call and every tool an attacker could abuse in this AI agent's code",
        backstory=("You are a security engineer who reads unfamiliar codebases quickly. You reason in "
                   "Thought / Action / Observation steps and never claim a location you have not read."),
        tools=search_tools(project),
        llm=crew_llm(),
        max_iter=18,
        allow_delegation=False,
        verbose=False,
        step_callback=_step_callback,
    )
    task = Task(
        description=TASK.format(digest=_scan_digest(scan)),
        expected_output="The main LLM call, the risky tools with risk and reason, safe tools, other LLM calls.",
        agent=agent,
        output_pydantic=SearchResult,
        callback=_task_callback,
    )
    return Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False,
                checkpoint=checkpoint_config(run_dir, ["task_completed"]))


class SearchFlow(Flow[SearchState]):
    """scan -> search -> save, checkpointed after each method."""

    @start()
    def scan(self) -> None:
        self.state.step = "scan"
        emit("flow", "step_started", step="scan", detail="MCP agentguard-scan: scan_project")
        data = call_scan_tool(self.state.project, "scan_project")
        report = ScanReport.model_validate(data)
        self.state.scan = report.model_dump()
        Path(self.state.run_dir, "scan.json").write_text(json.dumps(self.state.scan, indent=2))
        emit("flow", "scan_done", files=report.files_scanned, llm_calls=len(report.llm_calls),
             tools=len(report.tools), prompts=len(report.prompts), entry_points=len(report.entry_points))

    @listen(scan)
    def search(self) -> None:
        self.state.step = "search"
        emit("flow", "step_started", step="search", detail=f"Search agent ({model_name()})")
        crew = build_crew(self.state.project, ScanReport.model_validate(self.state.scan), self.state.run_dir)
        out = crew.kickoff()
        result = out.pydantic if isinstance(out.pydantic, SearchResult) else SearchResult.model_validate_json(out.raw)
        self.state.result = result.model_dump()
        usage = getattr(crew, "usage_metrics", None)
        self.state.usage = usage.model_dump() if hasattr(usage, "model_dump") else {}
        emit("search_agent", "usage", model=model_name(), **self.state.usage)

    @listen(search)
    def save(self) -> dict:
        self.state.step = "done"
        Path(self.state.run_dir, "search.json").write_text(json.dumps(self.state.result, indent=2))
        emit("flow", "step_done", step="save", file="search.json")
        return self.state.result


def run_search(project: str | Path, run_dir: str | Path) -> dict:
    flow = SearchFlow(checkpoint=checkpoint_config(run_dir, ["method_execution_finished"]))
    return flow.kickoff(inputs={"project": str(Path(project).resolve()), "run_dir": str(run_dir)})


def latest_checkpoint(run_dir: str | Path) -> Optional[str]:
    """'<db>#<id>' of the newest flow checkpoint, or None."""
    import sqlite3

    db = Path(run_dir) / "checkpoints.db"
    if not db.exists():
        return None
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT id FROM checkpoints ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
    return f"{db}#{row[0]}" if row else None


def resume_search(run_dir: str | Path, location: Optional[str] = None) -> dict:
    """Continues a stopped or failed run from its checkpoint: finished steps are not repeated."""
    location = location or latest_checkpoint(run_dir)
    if location is None:
        raise RuntimeError("this run has no checkpoint to resume from")
    emit("flow", "resumed", checkpoint=location.rsplit("#", 1)[1])
    cfg = checkpoint_config(run_dir, ["method_execution_finished"]).model_copy(update={"restore_from": location})
    return SearchFlow().kickoff(from_checkpoint=cfg)
