"""Target-side shim: turns a Python entrypoint into a uniform HTTP surface.

Usage, from the target application:

    from agentguard import expose, watch

    @expose
    def run(input_text, session_id=None):
        return my_crew.kickoff(inputs={"input": input_text})

    @watch
    def transfer_funds(to, amount):
        return bank.send(to, amount)

Then run it with `agentguard.adapter.serve()` or `uvicorn <module>:app`.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import time
from typing import Any, Callable, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from agentguard.logging import get_logger

logger = get_logger("adapter")
app = FastAPI(title="agentguard-adapter")

_entrypoint: Optional[Callable[..., Any]] = None
_calls: contextvars.ContextVar[Optional[list]] = contextvars.ContextVar("calls", default=None)
_observations: contextvars.ContextVar[dict] = contextvars.ContextVar("observations")


class InvokeRequest(BaseModel):
    input_text: str
    session_id: Optional[str] = None


def _bind(fn: Callable, args: tuple, kwargs: dict) -> dict:
    """Best-effort mapping of positional/keyword call args to parameter names."""
    try:
        sig = inspect.signature(fn)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        # Signature didn't match at runtime (e.g. *args/**kwargs) — fall back
        # to something inspectable rather than dropping the call entirely.
        return {"args": list(args), "kwargs": kwargs}


def expose(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Mark `fn` as the target's entrypoint, served at POST /invoke."""
    global _entrypoint
    _entrypoint = fn
    logger.info("Registered @expose entrypoint: %s", fn.__name__)
    return fn


def watch(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Mark `fn` as observable: each call is recorded on the active request's log."""
    from agentguard.instrument.wrappers import wrap

    return wrap("tool", sandbox=False)(fn)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "entrypoint_registered": _entrypoint is not None}


@app.post("/invoke")
def invoke(req: InvokeRequest) -> dict:
    if _entrypoint is None:
        logger.warning("POST /invoke rejected: no @expose entrypoint registered")
        return {
            "output": None,
            "tool_calls": [],
            "error": {"type": "AdapterError", "detail": "no @expose entrypoint registered"},
            "latency_ms": 0.0,
        }

    token = _calls.set([])
    obs_token = _observations.set({})
    t0 = time.perf_counter()
    output: Any = None
    error: Optional[dict] = None
    try:
        sig = inspect.signature(_entrypoint)
        if "session_id" in sig.parameters:
            output = _entrypoint(req.input_text, session_id=req.session_id)
        else:
            output = _entrypoint(req.input_text)
    except Exception as e:  # noqa: BLE001 - deliberately broad; capture as data
        error = {"type": type(e).__name__, "detail": str(e)}
        logger.warning("Target entrypoint exception: %s: %s", type(e).__name__, e)
    finally:
        calls = _calls.get() or []
        observations = _observations.get({})
        _calls.reset(token)
        _observations.reset(obs_token)

    latency_ms = (time.perf_counter() - t0) * 1000
    logger.debug("POST /invoke completed in %.2f ms (tools recorded: %d)", latency_ms, len(calls))
    return {
        "output": output,
        "tool_calls": calls,
        "observations": observations,
        "error": error,
        "latency_ms": latency_ms,
    }


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the adapter's FastAPI app. Binds to localhost only."""
    import uvicorn

    logger.info("Serving agentguard-adapter on http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port)
