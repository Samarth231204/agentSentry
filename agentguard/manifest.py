"""Static analysis: what can a target project do?

Never executes the target. `Manifest.from_yaml` is a permanent escape
hatch — build it first, use it whenever AST+Chroma synthesis is slow,
unavailable, or wrong.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.logging import get_logger

logger = get_logger("manifest")

DESTRUCTIVE_HINTS = (
    "transfer", "send", "pay", "delete", "remove", "drop", "write",
    "update", "execute", "exec", "run_command", "shell", "purchase",
    "buy", "withdraw", "post", "publish", "email", "notify",
)

DATA_EXFILTRATION_HINTS = (
    "send", "mail", "post", "notify", "webhook", "publish", "export",
    "transfer", "write", "upload", "transmit", "dump",
)

PRIVILEGE_HINTS = (
    "admin", "role", "manage", "permission", "grant", "sudo", "auth",
    "override", "config", "debug", "root", "supervisor",
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
        Path(path).write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        logger.info("Saved manifest to %s", path)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Manifest":
        content = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
        cap = data.get("capabilities", {})
        tools = [ToolInfo(**t) for t in cap.get("tools", [])]
        logger.debug("Loaded manifest from %s with %d tools", path, len(tools))
        return cls(
            tools=tools,
            rag=cap.get("rag", {"present": False, "ingestion": None}),
            memory=cap.get("memory", {"present": False}),
            multi_agent=bool(cap.get("multi_agent", False)),
        )

    def privileged_tools(self) -> list[ToolInfo]:
        """State-changing tools whose names say they change roles, permissions or admin settings."""
        return [t for t in self.tools if t.destructive and any(h in t.name.lower() for h in PRIVILEGE_HINTS)]

    def routing(self) -> list[str]:
        """Which attacker categories does this manifest justify?"""
        categories = ["prompt_injection", "secret_extraction"]
        privileged = {t.name for t in self.privileged_tools()}
        if any(t.destructive and t.name not in privileged for t in self.tools):
            categories.append("tool_misuse")
        if any(any(h in t.name.lower() for h in DATA_EXFILTRATION_HINTS) for t in self.tools):
            categories.append("data_exfiltration")
        if self.multi_agent or privileged:
            categories.append("privilege_escalation")
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
    logger.debug("Scanning Python files under %s", path)
    candidates: dict[str, Any] = {
        "tools": [],
        "rag_signals": [],
        "memory_signals": [],
        "agent_call_count": 0,
    }

    for py_file in sorted(Path(path).rglob("*.py")):
        try:
            src = py_file.read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            logger.debug("Skipping file %s during AST scan: %s", py_file, exc)
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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

    logger.debug(
        "Scan candidates found: %d tools, %d RAG signals, %d memory signals",
        len(candidates["tools"]),
        len(candidates["rag_signals"]),
        len(candidates["memory_signals"]),
    )
    return candidates


def _heuristic_destructive(name: str, doc: Optional[str]) -> bool:
    text = f"{name} {doc or ''}".lower()
    return any(h in text for h in DESTRUCTIVE_HINTS)


def heuristic_manifest(path: str | Path) -> Manifest:
    """AST-only synthesis, no LLM/Chroma involved. Deterministic fallback."""
    logger.debug("Generating heuristic manifest for %s", path)
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
# Chroma indexing.
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
            src = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        # chunk by top-level def/async def/class blocks; fall back to whole file
        if "\ndef " in src or "\nclass " in src or "\nasync def " in src:
            raw_chunks = re.split(r"\n(?=(?:def |async def |class ))", src)
        else:
            raw_chunks = [src]

        for i, chunk in enumerate(raw_chunks):
            stripped = chunk.strip()
            if not stripped:
                continue
            docs.append(stripped[:2500])
            ids.append(f"{py_file}::{i}")
            metas.append({"file": str(py_file), "chunk_id": i})

    if docs:
        collection.add(documents=docs, ids=ids, metadatas=metas)
    logger.debug("Indexed %d source chunks in Chroma for %s", len(docs), path)
    return collection


def retrieve_context(collection, query: str, n_results: int = 3) -> str:
    """Retrieve top matches for a single query formatted as markdown."""
    if collection.count() == 0:
        return ""
    n = min(n_results, collection.count())
    results = collection.query(query_texts=[query], n_results=n)
    docs = results.get("documents", [[]])[0]
    return "\n---\n".join(docs)


def retrieve_chunks(collection, queries: list[str], n_results: int = 3) -> list[dict]:
    """Query Chroma with multiple search queries and return deduplicated chunks."""
    if collection.count() == 0 or not queries:
        return []
    seen_ids: set[str] = set()
    collected_chunks: list[dict] = []

    clean_queries = [q for q in queries if q and q.strip()]
    if not clean_queries:
        return []

    try:
        n = min(n_results, collection.count())
        res = collection.query(query_texts=clean_queries, n_results=n)
        all_docs = res.get("documents", [])
        all_ids = res.get("ids", [])
        all_metas = res.get("metadatas", [])

        for q_idx in range(len(clean_queries)):
            docs = all_docs[q_idx] if q_idx < len(all_docs) else []
            doc_ids = all_ids[q_idx] if q_idx < len(all_ids) else []
            metas = all_metas[q_idx] if q_idx < len(all_metas) else []

            for doc, doc_id, meta in zip(docs, doc_ids, metas):
                if doc_id not in seen_ids:
                    seen_ids.add(doc_id)
                    collected_chunks.append({
                        "id": doc_id,
                        "file": meta.get("file", "unknown"),
                        "text": doc,
                    })
    except Exception as exc:
        logger.warning("Chroma chunk retrieval failed: %s", exc)

    return collected_chunks


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
    logger.info("Synthesizing manifest for %s (use_llm=%s)", path, use_llm)
    candidates = scan_project(path)

    if not use_llm:
        return heuristic_manifest(path)

    try:
        collection = build_index(path)
    except Exception as exc:
        logger.warning("Failed to build Chroma index (%s), falling back to heuristic", exc)
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
                max_tokens=256,  # one word, but reasoning models think first
                temperature=0.0,
            )
            verdict = resp["choices"][0]["message"]["content"].strip().upper()
            logger.debug("LLM verdict for tool '%s': %s", t["name"], verdict)
            if "DESTRUCTIVE" in verdict:
                destructive = True
            elif "SAFE" in verdict:
                destructive = False
        except Exception as exc:
            logger.warning(
                "LLM synthesis check failed for tool '%s' (%s), using heuristic verdict (%s)",
                t["name"], exc, destructive
            )

        tools.append(ToolInfo(
            name=t["name"], args=t["args"], destructive=destructive,
            doc=t["doc"], file=t["file"],
        ))

    manifest = Manifest(
        tools=tools,
        rag={"present": bool(candidates["rag_signals"]), "ingestion": None},
        memory={"present": bool(candidates["memory_signals"])},
        multi_agent=candidates["agent_call_count"] > 1,
    )
    logger.info("Synthesized manifest: %d tools, routing=%s", len(tools), manifest.routing())
    return manifest
