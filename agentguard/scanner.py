"""Deterministic scan of a Python project: where the LLM is called, which tools exist, where the
prompts are and which functions take a user's message.

It only reads code (ast), never imports or runs it. It is a starting point, not the verdict:
the Search agent confirms, corrects and ranks what this finds, and searches for what it missed.
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
from typing import Iterator, Optional

from agentguard.schemas import CodeSite, ScanReport

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".agentguard", "build",
             "dist", "site-packages", ".mypy_cache", ".pytest_cache", ".tox", ".idea", ".vscode"}
MAX_FILE_BYTES = 400_000

# Call chains that send a prompt to a model (matched against the end of the dotted name).
LLM_CALL_SUFFIXES = {
    "chat.completions.create": "openai-style chat completion",
    "completions.create": "completion API",
    "responses.create": "openai responses API",
    "messages.create": "anthropic messages API",
    "messages.stream": "anthropic messages stream",
    "generate_content": "gemini generate_content",
    "generate_content_async": "gemini generate_content",
    "chat.complete": "mistral chat",
    "litellm.completion": "litellm",
    "litellm.acompletion": "litellm",
    "ollama.chat": "ollama",
    "ollama.generate": "ollama",
}
LLM_CALL_NAMES = {"completion": "litellm", "acompletion": "litellm"}
# Agent-framework calls that run a model loop.
AGENT_RUN_SUFFIXES = {"kickoff": "crewai", "run_async": "agent runner", "Runner.run": "agent runner",
                      "Runner.run_sync": "agent runner", "run_live": "adk"}
# .invoke() and friends count only when the receiver looks like a model, chain or agent.
INVOKE_METHODS = {"invoke", "ainvoke", "stream", "astream", "predict", "batch", "chat", "generate"}
MODEL_RECEIVER_HINTS = ("llm", "model", "chat", "chain", "agent", "client", "graph", "bot")

TOOL_DECORATORS = {"tool", "function_tool", "register_tool", "mcp.tool", "server.tool", "app.tool",
                   "kernel_function", "ai_function"}
TOOL_BASE_CLASSES = {"BaseTool", "Tool", "StructuredTool", "FunctionTool"}
ROUTE_DECORATORS = {"post", "get", "put", "route", "websocket", "api_route"}

INPUT_NAMES = {"message", "messages", "prompt", "query", "question", "user_input", "input", "text",
               "user_message", "input_text", "content", "utterance", "msg", "request"}
PROMPT_NAME_HINTS = ("prompt", "system", "instruction", "persona", "preamble")

RISK_HINTS = {
    "moves money": ("transfer", "pay", "charge", "refund", "withdraw", "wire", "invoice", "purchase", "order"),
    "sends messages": ("send", "email", "mail", "sms", "notify", "post_message", "tweet", "slack"),
    "changes permissions": ("grant", "revoke", "role", "admin", "promote", "permission", "elevate"),
    "deletes data": ("delete", "remove", "drop", "purge", "truncate", "destroy", "wipe"),
    "runs code": ("exec", "eval", "shell", "subprocess", "run_command", "execute", "system"),
    "writes data": ("write", "update", "save", "insert", "create", "set_", "modify", "upload"),
    "reads private data": ("customer", "user", "account", "profile", "balance", "secret", "password",
                           "record", "lookup", "ssn", "card"),
    "reaches the network": ("fetch", "http", "url", "request", "browse", "download", "webhook"),
}


def iter_python_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        # AgentGuard's own clone lives inside the project; never scan it as the user's code.
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not d.startswith(".")
                             and not (here / d / "agentguard" / "scanner.py").exists())
        for name in sorted(filenames):
            if name.endswith(".py"):
                path = here / name
                try:
                    if path.stat().st_size <= MAX_FILE_BYTES:
                        yield path
                except OSError:
                    continue


def dotted(node: ast.AST) -> str:
    """client.chat.completions.create -> 'client.chat.completions.create'; calls in the chain become '()'."""
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            break
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            break
    return ".".join(reversed(parts))


def risk_signals(name: str) -> list[str]:
    low = name.lower()
    return [label for label, hints in RISK_HINTS.items() if any(h in low for h in hints)]


def _site_id(kind: str, file: str, line: int, name: str) -> str:
    return kind[:3] + "-" + hashlib.sha1(f"{kind}:{file}:{line}:{name}".encode()).hexdigest()[:8]


class _FileScan(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]):
        self.rel = rel
        self.lines = lines
        self.stack: list[str] = []
        self.functions: dict[str, ast.AST] = {}      # name -> def node (for linking tools)
        self.llm_calls: list[CodeSite] = []
        self.tools: list[CodeSite] = []
        self.prompts: list[CodeSite] = []
        self.entry_points: list[CodeSite] = []
        self.tool_refs: list[tuple[str, int, str]] = []  # (function name, line, how) from dispatch tables
        self.frameworks: set[str] = set()

    # -- helpers
    def _code(self, start: int, end: Optional[int] = None) -> str:
        end = min(end or start, start + 2)
        return "\n".join(l.rstrip() for l in self.lines[start - 1:end])[:300]

    def _site(self, kind: str, name: str, node: ast.AST, signals: list[str], end: Optional[int] = None) -> CodeSite:
        line = getattr(node, "lineno", 1)
        return CodeSite(id=_site_id(kind, self.rel, line, name), kind=kind, name=name, file=self.rel,
                        line=line, end_line=end or getattr(node, "end_lineno", line) or line,
                        function=".".join(self.stack), code=self._code(line), signals=signals)

    # -- imports tell us the frameworks
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.frameworks.add(a.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.frameworks.add(node.module.split(".")[0])

    # -- functions and classes
    def _visit_def(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.functions.setdefault(node.name, node)
        decos = [dotted(d) for d in node.decorator_list]
        tool_decos = [d for d in decos if d in TOOL_DECORATORS or d.split(".")[-1] in {"tool", "function_tool"}]
        if tool_decos:
            self.tools.append(self._site("tool", node.name, node, [f"decorator @{tool_decos[0]}"]
                                         + risk_signals(node.name), end=node.end_lineno))
        params = [a.arg for a in node.args.args + node.args.kwonlyargs if a.arg not in ("self", "cls")]
        takes_input = [p for p in params if p in INPUT_NAMES]
        is_route = any(d.split(".")[-1] in ROUTE_DECORATORS for d in decos)
        if (takes_input or is_route) and not tool_decos and not node.name.startswith("_"):
            sig = [f"parameter '{takes_input[0]}'"] if takes_input else []
            if is_route:
                sig.append("web route " + next(d for d in decos if d.split(".")[-1] in ROUTE_DECORATORS))
            self.entry_points.append(self._site("entry_point", node.name, node, sig, end=node.end_lineno))
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _visit_def
    visit_AsyncFunctionDef = _visit_def

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = {dotted(b).split(".")[-1] for b in node.bases}
        if bases & TOOL_BASE_CLASSES:
            self.tools.append(self._site("tool", node.name, node, [f"subclass of {sorted(bases & TOOL_BASE_CLASSES)[0]}"]
                                         + risk_signals(node.name), end=node.end_lineno))
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    # -- LLM calls
    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        label = None
        for suffix, what in LLM_CALL_SUFFIXES.items():
            if name == suffix or name.endswith("." + suffix):
                label = what
                break
        if label is None and name in LLM_CALL_NAMES:
            label = LLM_CALL_NAMES[name]
        if label is None:
            for suffix, what in AGENT_RUN_SUFFIXES.items():
                if name.endswith("." + suffix) or name == suffix:
                    label = what
        if label is None and "." in name:
            receiver, method = name.rsplit(".", 1)
            if method in INVOKE_METHODS and any(h in receiver.lower() for h in MODEL_RECEIVER_HINTS):
                label = f".{method}() on {receiver}"
        if label is not None:
            sig = [label]
            if any(k.arg in ("tools", "functions", "tool_choice") for k in node.keywords):
                sig.append("passes tools to the model")
            self.llm_calls.append(self._site("llm_call", name, node, sig))
        # tools=[a, b] passed to a model or agent
        for kw in node.keywords:
            if kw.arg == "tools" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elt in kw.value.elts:
                    if isinstance(elt, (ast.Name, ast.Attribute)):
                        self.tool_refs.append((dotted(elt).split(".")[-1], node.lineno, f"tools=[...] in {name}()"))
        self.generic_visit(node)

    # -- prompts, tool schemas and dispatch tables
    def visit_Assign(self, node: ast.Assign) -> None:
        targets = [dotted(t) for t in node.targets if isinstance(t, (ast.Name, ast.Attribute))]
        if isinstance(node.value, (ast.Constant, ast.JoinedStr)) and targets:
            text = node.value.value if isinstance(node.value, ast.Constant) else "f-string"
            if isinstance(text, str) and any(h in targets[0].lower() for h in PROMPT_NAME_HINTS) and len(text) > 20:
                self.prompts.append(self._site("prompt", targets[0], node, ["prompt-like name"]))
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        keys = {k.value: v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        # {"role": "system", "content": ...}
        role = keys.get("role")
        if isinstance(role, ast.Constant) and role.value == "system":
            self.prompts.append(self._site("prompt", "system message", node, ["role: system"]))
        # JSON tool schema: {"name": "x", "parameters"|"input_schema": ...}
        nm = keys.get("name")
        if isinstance(nm, ast.Constant) and isinstance(nm.value, str) and ({"parameters", "input_schema"} & set(keys)):
            self.tool_refs.append((nm.value, node.lineno, "JSON tool schema"))
        # Dispatch table: {"get_balance": get_balance, "pay": pay_vendor, ...}
        values = [v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        refs = [v for v in values if isinstance(v, (ast.Name, ast.Attribute))]
        if len(refs) >= 2 and len(refs) == len(values):
            for v in refs:
                self.tool_refs.append((dotted(v).split(".")[-1], node.lineno, "name-to-function table"))
        self.generic_visit(node)


def scan_project(root: str | Path) -> ScanReport:
    root = Path(root).resolve()
    report = ScanReport(root=str(root))
    scans: list[_FileScan] = []
    for path in iter_python_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text, filename=rel)
        except (SyntaxError, ValueError) as exc:
            report.errors.append(f"{rel}: {type(exc).__name__}: {exc}")
            continue
        fs = _FileScan(rel, text.splitlines())
        fs.visit(tree)
        scans.append(fs)
    report.files_scanned = len(scans)

    # Tools named in a schema, a tools=[...] list or a dispatch table may live in another file.
    defs: dict[str, tuple[_FileScan, ast.AST]] = {}
    for fs in scans:
        for name, node in fs.functions.items():
            defs.setdefault(name, (fs, node))
    seen = {(t.file, t.name) for fs in scans for t in fs.tools}
    linked: list[CodeSite] = []
    for fs in scans:
        for name, line, how in fs.tool_refs:
            if name in defs:
                dfs, node = defs[name]
                if (dfs.rel, name) in seen:
                    continue
                seen.add((dfs.rel, name))
                where = f"{how} at {fs.rel}:{line}"
                site = dfs._site("tool", name, node, [where] + risk_signals(name), end=node.end_lineno)
                site.function = ""
                linked.append(site)

    known = {"openai", "anthropic", "litellm", "crewai", "langchain", "langchain_openai", "langgraph",
             "llama_index", "google", "vertexai", "ollama", "mistralai", "cohere", "groq", "autogen",
             "semantic_kernel", "agents", "transformers", "fastapi", "flask", "streamlit", "gradio"}
    report.frameworks = sorted({f for fs in scans for f in fs.frameworks} & known)
    for fs in scans:
        report.llm_calls += fs.llm_calls
        report.tools += fs.tools
        report.prompts += fs.prompts
        # Entry points matter only if they are not tools themselves.
        report.entry_points += fs.entry_points
    report.tools += linked
    tool_names = {t.name for t in report.tools}
    report.entry_points = [e for e in report.entry_points if e.name not in tool_names]
    return report
