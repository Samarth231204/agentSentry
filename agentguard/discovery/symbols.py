"""Per-file AST extraction. Pure Python `ast`, no code is imported or run."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

# Import prefix -> framework label. Used to recognise the user's stack, which
# can be any of the frameworks listed in the plan (detection, not usage).
FRAMEWORK_PREFIXES: dict[str, str] = {
    "crewai": "crewai",
    "google.adk": "google-adk",
    "google.genai": "google-genai",
    "langchain": "langchain",
    "langgraph": "langgraph",
    "agents": "openai-agents",
    "openai": "openai",
    "anthropic": "anthropic",
    "litellm": "litellm",
    "groq": "groq",
    "fastapi": "fastapi",
    "flask": "flask",
    "django": "django",
    "chromadb": "rag",
    "faiss": "rag",
    "pinecone": "rag",
    "weaviate": "rag",
    "qdrant_client": "rag",
    "mem0": "memory",
    "agentguard": "agentguard",
}

LLM_CALL_SUFFIXES = (
    "chat", "completion", "acompletion", "completions.create", "messages.create",
    "generate_content", "generate_content_async", "run_async", "kickoff", "invoke",
    "ainvoke", "Runner", "Agent", "Crew", "chat_completion",
)
ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "route", "websocket"}
ROUTE_OBJECTS = {"app", "router", "api", "bp"}
TOOL_DECORATORS = {"tool", "function_tool", "ai_tool", "watch"}  # "watch" is AgentGuard's own marker
EXPOSE_DECORATOR = "expose"
# Library retrieval APIs. An app function named retrieve() is found by its name instead,
# so a caller of retrieve() is not mistaken for the retriever.
RETRIEVAL_CALLS = {"similarity_search", "as_retriever", "get_relevant_documents"}
MEMORY_CALLS = {"memory.add", "memory.search", "memory.get_all", "remember", "recall"}
OUTBOUND_PREFIXES = ("requests.", "httpx.", "urllib.request.", "smtplib.", "boto3.", "socket.", "aiohttp.")
SINK_CALLS = {
    "os.system", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "shutil.move",
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
    "smtplib.SMTP", "smtplib.SMTP_SSL",
}
SQL_WRITE_VERBS = ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE")


@dataclass
class FunctionInfo:
    qualname: str
    name: str
    lineno: int
    end_lineno: int
    is_async: bool
    args: list[str] = field(default_factory=list)
    first_arg_annotation: Optional[str] = None
    decorators: list[str] = field(default_factory=list)
    route_paths: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    has_llm_call: bool = False
    sink_calls: list[str] = field(default_factory=list)
    sql_write: bool = False
    outbound_calls: list[str] = field(default_factory=list)
    is_method: bool = False
    doc: str = ""  # first line of the docstring, if any


@dataclass
class FileInfo:
    path: str
    module: str
    imports: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    tool_refs: list[str] = field(default_factory=list)  # names passed as tools=[...]
    value_refs: list[str] = field(default_factory=list)  # names used as values (registries, dicts, lists)
    parse_error: Optional[str] = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "FileInfo":
        funcs = [FunctionInfo(**f) for f in data.get("functions", [])]
        return cls(**{**data, "functions": funcs})


def _dotted(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return None


def _annotation(node: Optional[ast.AST]) -> Optional[str]:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return None


def _module_name(rel_path: str) -> str:
    parts = rel_path[:-3].split("/") if rel_path.endswith(".py") else rel_path.split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _route_path(call: ast.Call) -> Optional[str]:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return None


def _function_info(node: ast.AST, qualname: str, is_method: bool) -> FunctionInfo:
    assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    decorators: list[str] = []
    route_paths: list[str] = []
    for dec in node.decorator_list:
        name = _dotted(dec) or "?"
        decorators.append(name)
        if isinstance(dec, ast.Call) and "." in name:
            obj, method = name.rsplit(".", 1)
            if method in ROUTE_METHODS and obj.split(".")[0] in ROUTE_OBJECTS:
                path = _route_path(dec)
                if path:
                    route_paths.append(path)

    calls: list[str] = []
    sink_calls: list[str] = []
    outbound: list[str] = []
    has_llm = False
    sql_write = False
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _dotted(child.func)
            if not name:
                continue
            calls.append(name)
            if name in SINK_CALLS:
                sink_calls.append(name)
            if name.startswith(OUTBOUND_PREFIXES):
                outbound.append(name)
            if name.split(".")[-1] in LLM_CALL_SUFFIXES or any(name.endswith(s) for s in ("completions.create", "messages.create")):
                has_llm = True
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            upper = child.value.upper()
            if any(f" {verb} " in f" {upper} " for verb in SQL_WRITE_VERBS) and "SELECT" not in upper:
                sql_write = True

    args = [a.arg for a in node.args.args]
    first_ann = _annotation(node.args.args[0].annotation) if node.args.args else None
    return FunctionInfo(
        qualname=qualname,
        name=node.name,
        lineno=node.lineno,
        end_lineno=getattr(node, "end_lineno", node.lineno),
        is_async=isinstance(node, ast.AsyncFunctionDef),
        args=args,
        first_arg_annotation=first_ann,
        decorators=decorators,
        route_paths=route_paths,
        calls=sorted(set(calls)),
        has_llm_call=has_llm,
        sink_calls=sorted(set(sink_calls)),
        sql_write=sql_write,
        outbound_calls=sorted(set(outbound)),
        is_method=is_method,
        doc=_first_doc_line(node),
    )


def _first_doc_line(node: ast.AST) -> str:
    doc = ast.get_docstring(node) or ""
    return doc.strip().splitlines()[0][:200] if doc.strip() else ""


def analyse_source(source: str, rel_path: str) -> FileInfo:
    info = FileInfo(path=rel_path, module=_module_name(rel_path))
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        info.parse_error = f"SyntaxError line {exc.lineno}: {exc.msg}"
        return info

    imports: set[str] = set()
    frameworks: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            imports.add(name)
            for prefix, label in FRAMEWORK_PREFIXES.items():
                if name == prefix or name.startswith(prefix + "."):
                    frameworks.add(label)

    tool_refs: set[str] = set()
    value_refs: set[str] = set()
    call_funcs = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and id(node) not in call_funcs:
            value_refs.add(node.id)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "tools" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Name):
                            tool_refs.add(elt.id)

    functions: list[FunctionInfo] = []

    def visit(body: list[ast.stmt], prefix: str, in_class: bool) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{stmt.name}"
                functions.append(_function_info(stmt, qual, is_method=in_class))
                visit(stmt.body, f"{qual}.", in_class=False)
            elif isinstance(stmt, ast.ClassDef):
                visit(stmt.body, f"{prefix}{stmt.name}.", in_class=True)

    visit(tree.body, "", in_class=False)

    info.imports = sorted(imports)
    info.frameworks = sorted(frameworks)
    info.functions = functions
    info.tool_refs = sorted(tool_refs)
    info.value_refs = sorted(value_refs)
    return info
