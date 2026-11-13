"""Versioned seed probes per attack category (YAML next to this file).

The attacker starts from these seeds and adapts them to the target. Replay runs
send an earlier run's probes in the same order instead of generating new ones.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PROBES_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def load_library(category: str) -> dict[str, Any]:
    path = PROBES_DIR / f"{category}.yaml"
    if not path.exists():
        return {"category": category, "version": 0, "seeds": []}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    seeds = [str(s).strip() for s in data.get("seeds", []) if str(s).strip()]
    return {"category": category, "version": int(data.get("version", 1)), "seeds": seeds}


def seeds_for(category: str, limit: int = 5) -> list[str]:
    return load_library(category)["seeds"][:limit]


def categories() -> list[str]:
    return sorted(p.stem for p in PROBES_DIR.glob("*.yaml"))
