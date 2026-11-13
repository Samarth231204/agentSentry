"""Scores every function in the project for each instrumentation role.

Every candidate has a stable id, a file and line, a confidence, and the signals
that produced it. Confidence >= AUTO is accepted without a model. Values in
[AMBIGUOUS, AUTO) go to the discovery agent, which may only include or exclude
an existing candidate; it cannot add one. Below AMBIGUOUS, candidates are dropped.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agentguard.discovery.symbols import (
    EXPOSE_DECORATOR, FileInfo, FunctionInfo, MEMORY_CALLS, RETRIEVAL_CALLS, TOOL_DECORATORS,
)
from agentguard.discovery.walker import analyse_file, iter_python_files

AUTO = 0.8
AMBIGUOUS = 0.4

ROLES = ("expose", "watch", "watch_retrieval", "watch_memory", "watch_llm", "watch_outbound")
INPUT_NAMES = {"input_text", "input", "message", "prompt", "query", "question",
               "user_input", "text", "user_message"}
ENTRY_NAMES = {"run", "chat", "handle", "respond", "answer", "ask", "invoke", "process", "converse"}
RETRIEVAL_HINTS = ("retriev", "search_docs", "query_docs", "lookup_docs", "knowledge")
MEMORY_HINTS = ("memory", "remember", "recall")
DESTRUCTIVE_HINTS = (
    "transfer", "pay", "charge", "refund", "delete", "remove", "drop", "send", "email", "wire",
    "withdraw", "shell", "exec", "purge", "cancel", "deploy", "update", "write", "modify",
)


@dataclass
class Candidate:
    id: str
    role: str
    file: str
    module: str
    qualname: str
    name: str
    line: int
    end_line: int
    confidence: float
    signals: list[str] = field(default_factory=list)
    destructive: bool = False
    is_method: bool = False
    snippet: str = ""

    @property
    def bucket(self) -> str:
        if self.confidence >= AUTO:
            return "auto"
        if self.confidence >= AMBIGUOUS:
            return "ambiguous"
        return "dropped"


@dataclass
class DiscoveryResult:
    root: str
    files_scanned: int = 0
    frameworks: list[str] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def by_id(self) -> dict[str, Candidate]:
        return {c.id: c for c in self.candidates}


def _candidate_id(file: str, qualname: str, role: str) -> str:
    return "c-" + hashlib.sha1(f"{file}:{qualname}:{role}".encode()).hexdigest()[:8]


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def is_destructive(fn: FunctionInfo) -> tuple[bool, list[str]]:
    signals = []
    if fn.sink_calls:
        signals.append(f"destructive sink call(s): {', '.join(fn.sink_calls)}")
    if fn.sql_write:
        signals.append("SQL write statement in a string literal")
    lowered = fn.name.lower()
    hits = [h for h in DESTRUCTIVE_HINTS if h in lowered]
    if hits:
        signals.append(f"name suggests a side effect ({', '.join(hits)})")
    return bool(signals), signals


def _entry_candidate(info: FileInfo, fn: FunctionInfo) -> Optional[tuple[float, list[str]]]:
    if fn.is_method or not fn.args or fn.route_paths:
        return None  # routes take HTTP bodies, not the single text input the adapter sends
    score, signals = 0.0, []
    if any(_last(d) == EXPOSE_DECORATOR for d in fn.decorators):
        score += 0.5
        signals.append("explicitly marked @expose")
    if fn.has_llm_call:
        score += 0.4
        signals.append("calls an LLM client")
    if fn.args[0] in INPUT_NAMES or fn.first_arg_annotation == "str":
        score += 0.3
        signals.append(f"first parameter '{fn.args[0]}' looks like user input")
    if fn.name in ENTRY_NAMES:
        score += 0.1
        signals.append(f"name '{fn.name}' is a common agent entrypoint")
    if score < AMBIGUOUS:
        return None
    return min(score, 1.0), signals


def _candidates_for(info: FileInfo, fn: FunctionInfo) -> list[tuple[str, float, list[str], bool]]:
    """(role, confidence, signals, destructive) for one function."""
    out: list[tuple[str, float, list[str], bool]] = []
    destructive, d_signals = is_destructive(fn)
    last = _last(fn.name)

    entry = _entry_candidate(info, fn)
    if entry is not None:
        out.append(("expose", entry[0], entry[1], False))

    tool_decorated = any(_last(d) in TOOL_DECORATORS for d in fn.decorators)
    if tool_decorated:
        out.append(("watch", 0.95, ["decorated as a tool"] + d_signals, destructive))
    elif fn.name in info.tool_refs:
        out.append(("watch", 0.85, ["passed to an agent in tools=[...]"] + d_signals, destructive))
    elif destructive and fn.name in info.value_refs:
        out.append(("watch", 0.8, ["registered as a value (tool table or dict)"] + d_signals, True))
    elif destructive and not (entry and entry[0] >= AUTO):
        out.append(("watch", 0.6, d_signals, True))

    if any(h in fn.name.lower() for h in RETRIEVAL_HINTS) or any(_last(c) in RETRIEVAL_CALLS for c in fn.calls):
        has_rag = "rag" in info.frameworks
        out.append(("watch_retrieval", 0.8 if has_rag else 0.6,
                    ["retrieval call or name"] + (["RAG library imported"] if has_rag else []), False))

    if any(h in fn.name.lower() for h in MEMORY_HINTS) or any(c in MEMORY_CALLS for c in fn.calls):
        has_mem = "memory" in info.frameworks
        out.append(("watch_memory", 0.8 if has_mem else 0.6,
                    ["memory read/write"] + (["memory library imported"] if has_mem else []), False))

    if fn.outbound_calls:
        out.append(("watch_outbound", 0.8, [f"outbound request: {', '.join(fn.outbound_calls[:3])}"], destructive))

    if fn.has_llm_call and not (entry and entry[0] >= AMBIGUOUS):
        out.append(("watch_llm", 0.8, ["calls an LLM client (not the entrypoint)"], False))
    return out


def _snippet(path: Path, start: int, end: int, limit: int = 40) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(f"{n:5d}  {lines[n - 1]}" for n in range(start, min(end, start + limit - 1, len(lines)) + 1))


def discover(project_root: Path, cache_dir: Optional[Path] = None) -> DiscoveryResult:
    root = Path(project_root).resolve()
    result = DiscoveryResult(root=str(root))
    frameworks: set[str] = set()
    for path in iter_python_files(root):
        result.files_scanned += 1
        try:
            info = analyse_file(path, root, cache_dir)
        except (OSError, UnicodeError) as exc:
            result.errors.append({"file": path.relative_to(root).as_posix(), "error": str(exc)})
            continue
        if info.parse_error:
            result.errors.append({"file": info.path, "error": info.parse_error})
            continue
        frameworks.update(info.frameworks)
        for fn in info.functions:
            for role, conf, signals, destructive in _candidates_for(info, fn):
                if conf < AMBIGUOUS:
                    continue
                result.candidates.append(Candidate(
                    id=_candidate_id(info.path, fn.qualname, role),
                    role=role,
                    file=info.path,
                    module=info.module,
                    qualname=fn.qualname,
                    name=_last(fn.qualname),
                    line=fn.lineno,
                    end_line=fn.end_lineno,
                    confidence=round(conf, 2),
                    signals=signals,
                    destructive=destructive,
                    is_method=fn.is_method,
                    snippet=_snippet(path, fn.lineno, fn.end_lineno),
                ))
    result.frameworks = sorted(frameworks)
    result.candidates.sort(key=lambda c: (c.file, c.line, c.role))
    return result
