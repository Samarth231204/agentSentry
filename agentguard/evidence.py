"""Evidence for the dashboard: which parts of the user's agent an attack got through, and the code behind them.

Everything here is read from files the run already wrote (findings, plan, discovery,
report) and from the project's own source. Code is only ever shown from real files at
real line numbers. A location the AI report names is kept only when that file and line
exist in the project. Nothing is imported or executed.
"""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator, Optional

from agentguard.discovery.walker import SKIP_DIRS, _is_agentguard_package

VULNERABLE = ("confirmed", "suspected")
TEXT_SUFFIXES = {".py", ".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".toml", ".html", ".jsonl", ".rst"}
MAX_TEXT_BYTES = 500_000
MAX_SNIPPET_LINES = 40
CONTEXT = 2

# Which kinds of code each attack category is about. Tools that were actually called are
# always included; these roles add the parts that category goes through.
CATEGORY_ROLES = {
    "rag_poisoning": ("watch_retrieval",),
    "memory_persistence": ("watch_memory",),
    "data_exfiltration": ("watch_outbound",),
}
PROMPT_CATEGORIES = {"prompt_injection", "secret_extraction", "privilege_escalation", "data_exfiltration"}
PROMPT_KWARGS = {"system", "system_prompt", "system_message", "instructions", "instruction", "backstory", "preamble"}
PROMPT_NAME = re.compile(r"(system|prompt|instruction|persona|backstory)", re.I)
QUOTED = re.compile(r"'([^']{6,})'|\"([^\"]{6,})\"")
REPORT_REF = re.compile(r"^\s*([^:\s][^:]*?):(\d+)")
ROLE_LABEL = {
    "watch": "Tool",
    "watch_retrieval": "Retrieval function",
    "watch_memory": "Memory function",
    "watch_outbound": "Outbound call",
    "watch_llm": "LLM call",
    "expose": "Entry point",
}


# ---------------------------------------------------------------------------
# project files
# ---------------------------------------------------------------------------

def _is_secret_file(name: str) -> bool:
    low = name.lower()
    return low.startswith(".env") or low.endswith(".env") or low in {"credentials.json", "secrets.json"}


def iter_text_files(root: Path) -> Iterator[Path]:
    """The project's own text files, skipping environments, AgentGuard itself and secret files."""
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
            and not (current / d / "pyvenv.cfg").exists() and not _is_agentguard_package(current / d)
        )
        for name in sorted(filenames):
            path = current / name
            if _is_secret_file(name) or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_TEXT_BYTES:
                    continue
            except OSError:
                continue
            yield path


class _Source:
    """Lazy, cached access to project files by relative path, confined to the project root."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._lines: dict[str, Optional[list[str]]] = {}
        self._files: Optional[list[str]] = None

    def resolve(self, rel: str) -> Optional[str]:
        rel = rel.strip().strip("`'\"")
        path = Path(rel)
        if not path.is_absolute():
            path = self.root / path
        try:
            path = path.resolve()
            relative = path.relative_to(self.root)
        except (OSError, ValueError):
            return None
        if _is_secret_file(path.name) or not path.is_file():
            return None
        rel_posix = relative.as_posix()
        if rel_posix not in self.files():
            return None  # outside the scanned project (a venv, AgentGuard itself, ...)
        return rel_posix

    def files(self) -> list[str]:
        if self._files is None:
            self._files = [p.relative_to(self.root).as_posix() for p in iter_text_files(self.root)]
        return self._files

    def lines(self, rel: str) -> Optional[list[str]]:
        if rel not in self._lines:
            try:
                self._lines[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._lines[rel] = None
        return self._lines[rel]


def _location(src: _Source, rel: str, start: int, end: int, highlight: list[int], why: str,
              part: Optional[str], origin: str) -> Optional[dict[str, Any]]:
    lines = src.lines(rel)
    if not lines or start < 1 or start > len(lines):
        return None
    end = max(start, min(end, len(lines)))
    first = max(1, start - CONTEXT)
    last = min(len(lines), end + CONTEXT, first + MAX_SNIPPET_LINES - 1)
    return {
        "file": rel,
        "start_line": first,
        "end_line": last,
        "highlight": [n for n in highlight if first <= n <= last],
        "lines": [{"n": n, "text": lines[n - 1]} for n in range(first, last + 1)],
        "why": why,
        "part": part,
        "origin": origin,  # "located" (found by AgentGuard) or "report" (named by the AI report, verified)
    }


# ---------------------------------------------------------------------------
# locators
# ---------------------------------------------------------------------------

def _called_tools(finding: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for turn in finding.get("turns") or []:
        for call in turn.get("tool_calls") or []:
            name = call.get("name")
            if name and name not in names:
                names.append(name)
    return names


def _fragments(detail: str) -> list[str]:
    out = []
    for a, b in QUOTED.findall(detail or ""):
        frag = (a or b).strip()
        if len(frag) >= 6 and not frag.startswith(("{", "[")) and frag not in out:
            out.append(frag)
    return out


def _search_text(src: _Source, fragment: str) -> Optional[tuple[str, int]]:
    """First file and line that contains `fragment` (case and spacing ignored)."""
    needle = " ".join(fragment.lower().split())
    if len(needle) > 60:
        needle = needle[:60]
    for rel in src.files():
        lines = src.lines(rel) or []
        for i, line in enumerate(lines, start=1):
            if needle in " ".join(line.lower().split()):
                return rel, i
    return None


def _str_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) >= 20
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return _str_value(node.left) or _str_value(node.right)
    return False


def _system_prompts(src: _Source, limit: int = 2) -> list[tuple[str, int, int]]:
    """Where the agent's instructions are written: role=system messages, system=/instructions= args,
    and string constants named like a prompt."""
    found: list[tuple[int, str, int, int]] = []  # (rank, file, start, end)
    for rel in src.files():
        if not rel.endswith(".py"):
            continue
        try:
            tree = ast.parse("\n".join(src.lines(rel) or []))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                keys = {k.value: v for k, v in zip(node.keys, node.values)
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                role = keys.get("role")
                if isinstance(role, ast.Constant) and role.value == "system" and "content" in keys:
                    v = keys["content"]
                    found.append((0, rel, v.lineno, getattr(v, "end_lineno", v.lineno)))
            elif isinstance(node, ast.keyword) and node.arg in PROMPT_KWARGS and _str_value(node.value):
                found.append((1, rel, node.value.lineno, getattr(node.value, "end_lineno", node.value.lineno)))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if node.value is not None and any(PROMPT_NAME.search(n) for n in names) and _str_value(node.value):
                    found.append((2, rel, node.lineno, getattr(node, "end_lineno", node.lineno)))
    found.sort()
    return [(f, s, e) for _, f, s, e in found[:limit]]


def _candidates(run_dir: Path) -> list[dict[str, Any]]:
    """Functions AgentGuard found and watched in this run: plan items, with end lines from discovery."""
    def read(name: str) -> dict[str, Any]:
        try:
            return json.loads((run_dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    ends = {(c.get("file"), c.get("qualname")): c.get("end_line") for c in read("discovery.json").get("candidates", [])}
    items = [i for i in read("plan.json").get("items", []) if i.get("include", True)]
    if not items:
        items = read("discovery.json").get("candidates", [])
    for item in items:
        item.setdefault("end_line", ends.get((item.get("file"), item.get("qualname"))) or item.get("line"))
    return items


def _function_location(src: _Source, cand: dict[str, Any], why: str, part: str) -> Optional[dict[str, Any]]:
    rel = src.resolve(cand.get("file") or "")
    line = int(cand.get("line") or 0)
    if not rel or line < 1:
        return None
    end = int(cand.get("end_line") or line)
    return _location(src, rel, line, end, list(range(line, end + 1)), why, part, "located")


def _overlaps(locs: list[dict[str, Any]], rel: str, line: int) -> bool:
    return any(l["file"] == rel and l["start_line"] <= line <= l["end_line"] for l in locs)


def locate(finding: dict[str, Any], src: _Source, candidates: list[dict[str, Any]],
           prompts: list[tuple[str, int, int]]) -> tuple[list[str], list[dict[str, Any]]]:
    """The vulnerable parts of the agent for one successful attack, and their code."""
    category = finding.get("category", "")
    detail = finding.get("oracle_detail") or ""
    parts: list[str] = []
    locs: list[dict[str, Any]] = []

    def add(loc: Optional[dict[str, Any]]) -> None:
        if loc and not _overlaps(locs, loc["file"], loc["highlight"][0] if loc["highlight"] else loc["start_line"]):
            locs.append(loc)
            if loc["part"] and loc["part"] not in parts:
                parts.append(loc["part"])

    by_name: dict[str, list[dict[str, Any]]] = {}
    for c in candidates:
        by_name.setdefault(c.get("name") or "", []).append(c)

    # 1. tools the attack made the agent call
    for name in _called_tools(finding) + [n for n in by_name if n and f"'{n}'" in detail]:
        for c in by_name.get(name, []):
            if c.get("role", "").startswith("watch"):
                label = ROLE_LABEL.get(c.get("role"), "Function")
                add(_function_location(
                    src, c, f"The attack made the agent call {name}. It ran without a check that would stop it.",
                    f"{label} {name}"))

    # 2. text the oracle quoted (a leaked secret, prompt text, a planted document line)
    for frag in _fragments(detail):
        if frag in by_name:
            continue
        hit = _search_text(src, frag)
        if hit:
            rel, line = hit
            part = "System prompt" if rel.endswith(".py") and category in PROMPT_CATEGORIES else f"File {rel}"
            if rel.endswith(".py") and any(p[0] == rel and p[1] <= line <= p[2] for p in prompts):
                part = "System prompt"
            add(_location(src, rel, line, line, [line],
                          f"This is where the text the attack got out of the agent lives: “{frag[:80]}”.",
                          part, "located"))

    # 3. the parts this category goes through (retrieval, memory, outbound)
    for role in CATEGORY_ROLES.get(category, ()):
        for c in candidates:
            if c.get("role") == role:
                label = ROLE_LABEL.get(role, "Function")
                add(_function_location(
                    src, c, f"{label} the attack went through. Content it returns or stores reaches the model "
                            "as if it were trusted.", f"{label} {c.get('name')}"))

    # 4. the instructions the attack overrode or leaked
    if category in PROMPT_CATEGORIES or not locs:
        for rel, start, end in prompts:
            add(_location(src, rel, start, end, list(range(start, end + 1)),
                          "The agent's instructions. The attack overrode or extracted them, so they are not "
                          "enforced against user input.", "System prompt", "located"))

    # 5. where the attack came in, when nothing more specific was found
    if not locs:
        for c in candidates:
            if c.get("role") == "expose":
                add(_function_location(src, c, "Entry point that received the attack message.",
                                       f"Entry point {c.get('name')}"))

    # 6. lines the AI report named, kept only when they exist in the project
    for ref in finding.get("code_references") or []:
        m = REPORT_REF.match(str(ref))
        if not m:
            continue
        rel = src.resolve(m.group(1))
        line = int(m.group(2))
        if rel and not _overlaps(locs, rel, line):
            loc = _location(src, rel, line, line, [line], "Named by the AI report.", None, "report")
            if loc:
                locs.append(loc)
    return parts, locs


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def build_evidence(project_root: Path, run_dir: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Evidence for every successful attack in a run, grouped by attack category."""
    src = _Source(project_root)
    candidates = _candidates(run_dir)
    vulnerable = [f for f in findings if f.get("status") in VULNERABLE]
    prompts = _system_prompts(src) if vulnerable else []

    items = []
    by_category: dict[str, dict[str, Any]] = {}
    for f in vulnerable:
        parts, code = locate(f, src, candidates, prompts)
        items.append({
            "id": f.get("id"),
            "category": f.get("category"),
            "status": f.get("status"),
            "oracle": f.get("oracle"),
            "oracle_detail": f.get("oracle_detail"),
            "confidence": f.get("confidence"),
            "capability_targeted": f.get("capability_targeted"),
            "severity": f.get("severity"),
            "remediation": f.get("remediation"),
            "owasp": f.get("owasp"),
            "turns": f.get("turns") or [],
            "parts": parts,
            "code": code,
        })
        row = by_category.setdefault(f.get("category") or "unknown",
                                     {"findings": 0, "confirmed": 0, "parts": []})
        row["findings"] += 1
        row["confirmed"] += f.get("status") == "confirmed"
        for p in parts:
            if p not in row["parts"]:
                row["parts"].append(p)
    return {
        "total_attempts": len(findings),
        "vulnerable": len(vulnerable),
        "by_category": by_category,
        "findings": items,
    }
