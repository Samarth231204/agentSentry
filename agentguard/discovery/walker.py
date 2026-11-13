"""Finds the project's Python files, skipping environments, caches and AgentGuard itself.

Respects simple .gitignore lines (name patterns only). Files are read as text,
never imported or executed. Parse results are cached by content hash in
.agentguard/cache/discovery/, so a re-run only re-parses changed files.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from pathlib import Path
from typing import Iterator, Optional

from agentguard.discovery.symbols import FileInfo, analyse_source

CACHE_VERSION = "2"
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__",
    "build", "dist", ".agentguard", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "site-packages", ".next", ".integration",
}


def _gitignore_patterns(root: Path) -> list[str]:
    path = root / ".gitignore"
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")) or "/" in line.rstrip("/"):
            continue
        patterns.append(line.rstrip("/"))
    return patterns


def _is_agentguard_package(directory: Path) -> bool:
    """True for the AgentGuard checkout itself, so we never instrument our own code."""
    pyproject = directory / "pyproject.toml"
    if not pyproject.exists():
        return False
    try:
        text = pyproject.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return 'name = "agentguard"' in text


def _is_test_file(name: str) -> bool:
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def iter_python_files(root: Path) -> Iterator[Path]:
    root = root.resolve()
    patterns = _gitignore_patterns(root)
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        kept = []
        for d in dirnames:
            if d in SKIP_DIRS or d.startswith(".") or d in ("tests", "test"):
                continue
            if any(fnmatch.fnmatch(d, p) for p in patterns):
                continue
            if (current / d / "pyvenv.cfg").exists() or _is_agentguard_package(current / d):
                continue
            kept.append(d)
        dirnames[:] = sorted(kept)
        for name in sorted(filenames):
            if not name.endswith(".py") or _is_test_file(name):
                continue
            if any(fnmatch.fnmatch(name, p) for p in patterns):
                continue
            path = current / name
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def analyse_file(path: Path, root: Path, cache_dir: Optional[Path] = None) -> FileInfo:
    rel = path.relative_to(root).as_posix()
    data = path.read_bytes()
    digest = hashlib.sha256(CACHE_VERSION.encode() + data).hexdigest()
    cache_file = cache_dir / f"{digest}.json" if cache_dir else None
    if cache_file and cache_file.exists():
        try:
            return FileInfo.from_json(json.loads(cache_file.read_text(encoding="utf-8")))
        except (ValueError, TypeError, KeyError):
            pass
    info = analyse_source(data.decode("utf-8", errors="replace"), rel)
    if cache_file:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(info.to_json()), encoding="utf-8")
    return info
