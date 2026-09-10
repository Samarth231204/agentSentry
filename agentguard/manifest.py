"""Static analysis: what can a target project do?

Never executes the target. `Manifest.from_yaml` is a permanent escape
hatch — build it first, use it whenever AST+Chroma synthesis is slow,
unavailable, or wrong.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

DESTRUCTIVE_HINTS = (
    "transfer", "send", "pay", "delete", "remove", "drop", "write",
    "update", "execute", "exec", "run_command", "shell", "purchase",
    "buy", "withdraw", "post", "publish", "email", "notify",
)


@dataclass
class ToolInfo:
    name: str
    args: list[str] = field(default_factory=list)
    destructive: bool = False
    doc: Optional[str] = None
    file: Optional[str] = None


@dataclass
class Manifest:
    tools: list[ToolInfo] = field(default_factory=list)
    rag: dict = field(default_factory=lambda: {"present": False, "ingestion": None})
    memory: dict = field(default_factory=lambda: {"present": False})
    multi_agent: bool = False

    def to_yaml(self, path: str | Path) -> None:
        data = {
            "capabilities": {
                "tools": [vars(t) for t in self.tools],
                "rag": self.rag,
                "memory": self.memory,
                "multi_agent": self.multi_agent,
            }
        }
        Path(path).write_text(yaml.safe_dump(data, sort_keys=False))

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Manifest":
        data = yaml.safe_load(Path(path).read_text()) or {}
        cap = data.get("capabilities", {})
        tools = [ToolInfo(**t) for t in cap.get("tools", [])]
        return cls(
            tools=tools,
            rag=cap.get("rag", {"present": False, "ingestion": None}),
            memory=cap.get("memory", {"present": False}),
            multi_agent=bool(cap.get("multi_agent", False)),
        )

    def routing(self) -> list[str]:
        """Which attacker categories does this manifest justify?"""
        categories = ["prompt_injection", "secret_extraction"]
        if any(t.destructive for t in self.tools):
            categories.append("tool_misuse")
        if self.rag.get("present"):
            categories.append("rag_poisoning")
        if self.memory.get("present"):
            categories.append("memory_persistence")
        return categories


# ---------------------------------------------------------------------------
# AST scan: finds structural candidates. Can't judge danger by itself.
# ---------------------------------------------------------------------------

RAG_IMPORT_HINTS = ("chroma", "pinecone", "faiss", "weaviate", "qdrant", "vectorstore")
RAG_FUNCNAME_HINTS = ("retrieve", "search_docs", "query_docs", "lookup_docs")
MEMORY_IMPORT_HINTS = ("memory", "mem0")
AGENT_CALL_HINTS = ("Agent", "Task", "Crew")
TOOL_DECORATOR_HINTS = ("tool", "watch")


def scan_project(path: str | Path) -> dict[str, Any]:
    """Walk .py files under `path`, return structural candidates via AST."""
    candidates: dict[str, Any] = {
        "tools": [],
        "rag_signals": [],
        "memory_signals": [],
        "agent_call_count": 0,
    }

    for py_file in sorted(Path(path).rglob("*.py")):
        try:
            src = py_file.read_text()
            tree = ast.parse(src)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                decs = [ast.unparse(d) for d in node.decorator_list]
                if any(any(h in d.lower() for h in TOOL_DECORATOR_HINTS) for d in decs):
                    candidates["tools"].append({
                        "name": node.name,
                        "args": [a.arg for a in node.args.args],
                        "doc": ast.get_docstring(node),
                        "file": str(py_file),
                    })
                if any(h in node.name.lower() for h in RAG_FUNCNAME_HINTS):
                    candidates["rag_signals"].append(node.name)

            elif isinstance(node, ast.Call):
                fname = ast.unparse(node.func) if hasattr(node, "func") else ""
                if any(h in fname for h in AGENT_CALL_HINTS):
                    candidates["agent_call_count"] += 1
                if any(h in fname.lower() for h in RAG_IMPORT_HINTS):
                    candidates["rag_signals"].append(fname)

            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    low = alias.name.lower()
                    mod = (getattr(node, "module", "") or "").lower()
                    if any(h in low or h in mod for h in RAG_IMPORT_HINTS):
                        candidates["rag_signals"].append(alias.name)
                    if any(h in low or h in mod for h in MEMORY_IMPORT_HINTS):
                        candidates["memory_signals"].append(alias.name)

    return candidates


def _heuristic_destructive(name: str, doc: Optional[str]) -> bool:
    text = f"{name} {doc or ''}".lower()
    return any(h in text for h in DESTRUCTIVE_HINTS)


def heuristic_manifest(path: str | Path) -> Manifest:
    """AST-only synthesis, no LLM/Chroma involved. Deterministic fallback."""
    candidates = scan_project(path)
    tools = [
        ToolInfo(
            name=t["name"],
            args=t["args"],
            destructive=_heuristic_destructive(t["name"], t["doc"]),
            doc=t["doc"],
            file=t["file"],
        )
        for t in candidates["tools"]
    ]
    return Manifest(
        tools=tools,
        rag={"present": bool(candidates["rag_signals"]), "ingestion": None},
        memory={"present": bool(candidates["memory_signals"])},
        multi_agent=candidates["agent_call_count"] > 1,
    )


# ---------------------------------------------------------------------------
# Chroma indexing. Uses a small dependency-free hashing embedder rather than
# chromadb's default ONNX model — that model is a ~80MB on-demand download
# and proved slow/flaky in this environment. Good enough for keyword-level
# retrieval of "context around a candidate", which is all synthesis needs.
# ---------------------------------------------------------------------------

_HASH_DIM = 256


def _hash_embed(text: str) -> list[float]:
    vec = [0.0] * _HASH_DIM
    for word in text.lower().split():
        h = int(hashlib.md5(word.encode()).hexdigest(), 16)
        vec[h % _HASH_DIM] += 1.0
    norm = sum(v * v for v in vec) ** 0.5 or 1.0
    return [v / norm for v in vec]


def _make_hash_embedding_function():
    """Build a chromadb EmbeddingFunction with no model download required."""
    from chromadb.api.types import EmbeddingFunction

    class _HashEmbeddingFunction(EmbeddingFunction):
        def __init__(self) -> None:
            pass

        def __call__(self, input: list[str]) -> list[list[float]]:  # noqa: A002
            return [_hash_embed(t) for t in input]

        def name(self) -> str:
            return "agentguard-hash-embedder"

        @staticmethod
        def build_from_config(config: dict) -> "_HashEmbeddingFunction":
            return _HashEmbeddingFunction()

        def get_config(self) -> dict:
            return {}

    return _HashEmbeddingFunction()


def build_index(path: str | Path, collection_name: str = "agentguard-manifest"):
    """Chunk target source into a Chroma collection for retrieval around candidates."""
    import chromadb

    client = chromadb.EphemeralClient()
    collection = client.get_or_create_collection(
        collection_name, embedding_function=_make_hash_embedding_function()
    )

    docs, ids, metas = [], [], []
    for py_file in sorted(Path(path).rglob("*.py")):
        try:
            src = py_file.read_text()
        except UnicodeDecodeError:
            continue
        # chunk by top-level def/class blocks; fall back to whole file
        chunks = src.split("\ndef ") if "\ndef " in src else [src]
        for i, chunk in enumerate(chunks):
            if not chunk.strip():
                continue
            docs.append(chunk[:2000])
            ids.append(f"{py_file}::{i}")
            metas.append({"file": str(py_file)})

    if docs:
        collection.add(documents=docs, ids=ids, metadatas=metas)
    return collection


def retrieve_context(collection, query: str, n_results: int = 3) -> str:
    if collection.count() == 0:
        return ""
    n = min(n_results, collection.count())
    results = collection.query(query_texts=[query], n_results=n)
    docs = results.get("documents", [[]])[0]
    return "\n---\n".join(docs)


# ---------------------------------------------------------------------------
# LLM synthesis: AST finds candidates, the model judges danger.
# ---------------------------------------------------------------------------

SYNTHESIS_PROMPT = """You are a static-analysis assistant for an AI agent \
security scanner. Given a candidate tool's name, arguments, and docstring, \
plus source context retrieved from the project, decide if calling this \
tool has a real-world side effect that would be bad to trigger without \
authorization (moving money, sending messages, deleting data, executing \
code, etc).

Tool: {name}
Args: {args}
Docstring: {doc}
Source context:
{context}

Respond with exactly one word: DESTRUCTIVE or SAFE."""


def synthesize(path: str | Path, use_llm: bool = True) -> Manifest:
    """Full pipeline: AST scan -> Chroma retrieval -> LLM judgment per tool.

    Falls back to heuristic_manifest() if use_llm is False or any LLM call
    fails, so a flaky/rate-limited provider never blocks manifest generation.
    """
    candidates = scan_project(path)

    if not use_llm:
        return heuristic_manifest(path)

    try:
        collection = build_index(path)
    except Exception:
        return heuristic_manifest(path)

    from agentguard.llm import chat

    tools = []
    for t in candidates["tools"]:
        context = retrieve_context(collection, t["name"])
        destructive = _heuristic_destructive(t["name"], t["doc"])
        try:
            resp = chat(
                [{
                    "role": "user",
                    "content": SYNTHESIS_PROMPT.format(
                        name=t["name"], args=t["args"], doc=t["doc"] or "",
                        context=context or "(none)",
                    ),
                }],
                max_tokens=10,
                temperature=0.0,
            )
            verdict = resp["choices"][0]["message"]["content"].strip().upper()
            if "DESTRUCTIVE" in verdict:
                destructive = True
            elif "SAFE" in verdict:
                destructive = False
        except Exception:
            pass  # keep heuristic verdict — a flaky LLM call shouldn't block synthesis

        tools.append(ToolInfo(
            name=t["name"], args=t["args"], destructive=destructive,
            doc=t["doc"], file=t["file"],
        ))

    return Manifest(
        tools=tools,
        rag={"present": bool(candidates["rag_signals"]), "ingestion": None},
        memory={"present": bool(candidates["memory_signals"])},
        multi_agent=candidates["agent_call_count"] > 1,
    )
