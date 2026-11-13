"""Import hook: applies the approved plan while the user's modules load.

The source file on disk is never changed. When a module named in the plan is
imported, its source is parsed, a recording decorator is appended to each
planned function (innermost, so framework decorators such as @tool and route
decorators still see the original function), and the result is executed. Lines
are not moved, so the line numbers in the plan still match.
"""

from __future__ import annotations

import ast
import importlib.abc
import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from agentguard.discovery.plan import InstrumentationPlan, PlanItem
from agentguard.instrument.wrappers import wrap

HOOK_NAME = "__agentguard_wrap__"
ROLE_TO_WRAPPER = {
    "watch": "tool",
    "watch_retrieval": "retrieval",
    "watch_memory": "memory",
    "watch_llm": "llm",
    "watch_outbound": "outbound",
}


def _apply(tree: ast.Module, items: Sequence[PlanItem]) -> int:
    by_line = {item.line: item for item in items if item.role in ROLE_TO_WRAPPER}
    applied = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        item = by_line.get(node.lineno)
        if item is None or item.name != node.name:
            continue
        decorator = ast.Call(
            func=ast.Name(id=HOOK_NAME, ctx=ast.Load()),
            args=[ast.Constant(ROLE_TO_WRAPPER[item.role]), ast.Constant(bool(item.sandbox))],
            keywords=[],
        )
        node.decorator_list.append(decorator)  # last = applied first = innermost
        applied += 1
    return applied


class PlanLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, fullname: str, path: str, items: Sequence[PlanItem]) -> None:
        super().__init__(fullname, path)
        self.items = list(items)
        self.applied = 0

    def get_code(self, fullname: str) -> Any:  # bypass the bytecode cache: it would skip the rewrite
        return self.source_to_code(self.get_data(self.path), self.path)

    def source_to_code(self, data: Any, path: Any, *, _optimize: int = -1) -> Any:
        tree = ast.parse(data, filename=str(path))
        self.applied = _apply(tree, self.items)
        ast.fix_missing_locations(tree)
        return compile(tree, str(path), "exec", dont_inherit=True, optimize=_optimize)

    def exec_module(self, module: Any) -> None:
        module.__dict__[HOOK_NAME] = wrap
        exec(self.get_code(module.__name__), module.__dict__)


class PlanHook(importlib.abc.MetaPathFinder):
    def __init__(self, plan: InstrumentationPlan, project_root: Path) -> None:
        self.project_root = Path(project_root)
        self.modules: dict[str, tuple[Path, list[PlanItem]]] = {}
        for item in plan.items:
            if not item.include or item.role == "expose":
                continue
            path = self.project_root / item.file
            self.modules.setdefault(item.module, (path, []))[1].append(item)

    def find_spec(self, fullname: str, path: Optional[Sequence[str]], target: Any = None):
        if fullname not in self.modules:
            return None
        file, items = self.modules[fullname]
        loader = PlanLoader(fullname, str(file), items)
        return importlib.util.spec_from_file_location(fullname, str(file), loader=loader)


def install(plan_path: str | Path, project_root: str | Path) -> PlanHook:
    """Installs the hook for the modules in plan_path. Call before importing the user's code."""
    plan = InstrumentationPlan.load(Path(plan_path))
    hook = PlanHook(plan, Path(project_root))
    sys.meta_path.insert(0, hook)
    return hook
