"""Cost estimates: token usage x price per million tokens.

Prices are Anthropic first-party list prices (Haiku 5.5: prompts up to 100K tokens). The Groq price is
an estimate; set AGENTGUARD_PRICES='{"model": [input_per_M, output_per_M], ...}' to override any of them.
"""

from __future__ import annotations

import json
import os

PRICES: dict[str, tuple[float, float]] = {   # USD per 1M tokens: (input, output)
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-opus-5-5": (4.00, 20.00),
    "openai/gpt-oss-120b": (0.15, 0.60),       # Groq, estimate
    "openai/gpt-oss-20b": (0.075, 0.30),       # Groq, estimate
}


def _prices() -> dict[str, tuple[float, float]]:
    out = dict(PRICES)
    try:
        out.update({k: tuple(v) for k, v in json.loads(os.environ.get("AGENTGUARD_PRICES", "{}")).items()})
    except (ValueError, TypeError):
        pass
    return out


def price_of(model: str) -> tuple[float, float]:
    """Matches 'anthropic/claude-haiku-5-5', 'groq/openai/gpt-oss-120b', ... to a price."""
    prices = _prices()
    name = model or ""
    for _ in range(3):
        if name in prices:
            return prices[name]
        if "/" not in name:
            break
        name = name.split("/", 1)[1]
    return (0.0, 0.0)


def usd(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    pin, pout = price_of(model)
    return round((prompt_tokens or 0) / 1e6 * pin + (completion_tokens or 0) / 1e6 * pout, 6)
