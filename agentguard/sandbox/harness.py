"""Runs INSIDE the sandbox process, next to a copy of the user's project.

    python -m agentguard.sandbox.harness spec.json

It talks to the runner over stdin/stdout, one JSON object per line:
    {"op": "invoke", "entry": "<id>", "message": "...", "session": "..."}  ->  {"reply", "tool_calls", "llm_calls", "error"}

What it does to the project, in memory only (the source files are never edited):
  * Model calls made through LiteLLM or the OpenAI SDK are redirected to AgentGuard's own model and key.
  * Each risky tool the Search agent found is wrapped: every call is recorded. Tools that act on the
    world (pay, send, delete, grant, run, write) are intercepted: recorded, then a fake success is
    returned and the real code never runs.
"""

from __future__ import annotations

import asyncio
import functools
import importlib
import inspect
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

PROTOCOL_OUT = os.fdopen(os.dup(1), "w", buffering=1)  # our channel; the project's prints go to stderr
sys.stdout = sys.stderr

SPEC: dict = {}
CALLS: list[dict] = []        # tool calls in the current invoke
LLM_CALLS: list[dict] = []    # model calls in the current invoke
ROOT = Path(".")


# ---- Model redirection -------------------------------------------------------------------------

def _system_text(messages: Any) -> str:
    out = []
    for m in messages or []:
        if isinstance(m, dict) and m.get("role") == "system":
            c = m.get("content")
            out.append(c if isinstance(c, str) else json.dumps(c)[:4000])
    return "\n".join(out)[:6000]


def _our_kwargs(kwargs: dict) -> dict:
    kwargs = dict(kwargs)
    for k in ("api_key", "api_base", "base_url", "custom_llm_provider", "temperature", "top_p"):
        kwargs.pop(k, None)
    kwargs["model"] = SPEC["target_model"]
    ws = os.environ.get("ANTHROPIC_WORKSPACE_ID")
    if ws and kwargs["model"].startswith("anthropic/"):
        kwargs["extra_headers"] = {**(kwargs.get("extra_headers") or {}), "anthropic-workspace-id": ws}
    kwargs.setdefault("max_tokens", 1024)
    return kwargs


def _record(entry: dict, resp: Any) -> Any:
    """Adds the target model's token usage to an LLM_CALLS entry (for the run's cost)."""
    u = getattr(resp, "usage", None)
    if u is not None:
        entry["model"] = SPEC["target_model"]
        entry["prompt_tokens"] = getattr(u, "prompt_tokens", 0) or 0
        entry["completion_tokens"] = getattr(u, "completion_tokens", 0) or 0
    return resp


def redirect_models() -> None:
    try:
        import litellm
    except ImportError:
        return
    real_completion, real_acompletion = litellm.completion, litellm.acompletion

    def completion(*args, **kwargs):
        if args:
            kwargs.setdefault("model", args[0])
            if len(args) > 1:
                kwargs.setdefault("messages", args[1])
        entry = {"via": "litellm", "asked_model": kwargs.get("model"), "system": _system_text(kwargs.get("messages"))}
        LLM_CALLS.append(entry)
        return _record(entry, real_completion(**_our_kwargs(kwargs)))

    async def acompletion(*args, **kwargs):
        if args:
            kwargs.setdefault("model", args[0])
        entry = {"via": "litellm", "asked_model": kwargs.get("model"), "system": _system_text(kwargs.get("messages"))}
        LLM_CALLS.append(entry)
        return _record(entry, await real_acompletion(**_our_kwargs(kwargs)))

    litellm.completion, litellm.acompletion = completion, acompletion

    try:  # OpenAI SDK (also used against other providers' OpenAI-compatible endpoints)
        from openai.resources.chat.completions import Completions

        def create(self, *args, **kwargs):
            entry = {"via": "openai", "asked_model": kwargs.get("model"), "system": _system_text(kwargs.get("messages"))}
            LLM_CALLS.append(entry)
            kwargs = {k: v for k, v in kwargs.items() if v is not None and k not in ("stream",)}
            return _record(entry, real_completion(**_our_kwargs(kwargs)))

        Completions.create = create
    except ImportError:
        pass


# ---- Tool interception ---------------------------------------------------------------------------

def _project_modules():
    root = str(ROOT)
    for mod in list(sys.modules.values()):
        f = getattr(mod, "__file__", None) or ""
        if f.startswith(root) and "/AgentGuard/" not in f:
            yield mod


def _module_name(rel: str) -> str:
    return rel[:-3].replace("/", ".").removesuffix(".__init__")


def _fake_result(name: str) -> str:
    low = name.lower()
    if any(w in low for w in ("command", "shell", "exec", "run")):
        return "exit code 0"
    if any(w in low for w in ("sql", "query")):
        return "[] (0 rows)"
    return "Success."


def _wrap(name: str, fn: Any, intercept: bool) -> Any:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        sig = None

    def record(args, kwargs, result, faked):
        try:
            bound = dict(sig.bind_partial(*args, **kwargs).arguments) if sig else {"args": list(args), **kwargs}
            bound.pop("self", None)
        except TypeError:
            bound = {"args": [str(a) for a in args], **kwargs}
        CALLS.append({"name": name, "args": {k: v if isinstance(v, (str, int, float, bool, type(None))) else str(v)
                                             for k, v in bound.items()},
                      "intercepted": faked, "result": str(result)[:800]})

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(*args, **kwargs):
            if intercept:
                result = _fake_result(name)
                record(args, kwargs, result, True)
                return result
            result = await fn(*args, **kwargs)
            record(args, kwargs, result, False)
            return result
        awrapper.__agentguard__ = True
        return awrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if intercept:
            result = _fake_result(name)
            record(args, kwargs, result, True)
            return result
        result = fn(*args, **kwargs)
        record(args, kwargs, result, False)
        return result
    wrapper.__agentguard__ = True
    return wrapper


def _replace_refs(originals: dict[int, Any]) -> None:
    """Swap every reference to an original tool (module globals, dispatch dicts, tool lists, class attributes)."""
    def swap(v):
        return originals.get(id(v), v)

    def fix_container(c, depth=0):
        if depth > 3:
            return c
        if isinstance(c, dict):
            for k, v in list(c.items()):
                if id(v) in originals:
                    c[k] = swap(v)
                elif isinstance(v, (dict, list, tuple)):
                    c[k] = fix_container(v, depth + 1)
            return c
        if isinstance(c, list):
            for i, v in enumerate(c):
                c[i] = swap(v) if id(v) in originals else fix_container(v, depth + 1) if isinstance(v, (dict, list, tuple)) else v
            return c
        if isinstance(c, tuple) and any(id(v) in originals or isinstance(v, (dict, list, tuple)) for v in c):
            return tuple(swap(v) if id(v) in originals else fix_container(v, depth + 1) if isinstance(v, (dict, list, tuple)) else v for v in c)
        return c

    for mod in _project_modules():
        for k, v in list(vars(mod).items()):
            if id(v) in originals:
                setattr(mod, k, swap(v))
            elif isinstance(v, (dict, list, tuple)):
                setattr(mod, k, fix_container(v))
            elif inspect.isclass(v) and getattr(v, "__module__", "") == mod.__name__:
                for ak, av in list(vars(v).items()):
                    if id(av) in originals:
                        setattr(v, ak, swap(av))
                    elif isinstance(av, (dict, list)):
                        fix_container(av)


def patch_tools() -> list[str]:
    originals: dict[int, Any] = {}
    patched = []
    for t in SPEC.get("tools", []):
        try:
            mod = importlib.import_module(_module_name(t["file"]))
        except Exception:  # noqa: BLE001
            continue
        owner, attr = mod, t["name"]
        if "." in attr:
            cls, attr = attr.split(".", 1)
            owner = getattr(mod, cls, None)
        fn = getattr(owner, attr, None) if owner is not None else None
        if fn is None or getattr(fn, "__agentguard__", False) or not callable(fn):
            continue
        originals[id(fn)] = _wrap(t["name"].split(".")[-1], fn, t.get("intercept", False))
        patched.append(t["name"])
    _replace_refs(originals)
    return patched


# ---- Entry points ----------------------------------------------------------------------------------

def _resolve(entry: dict):
    mod = importlib.import_module(_module_name(entry["file"]))
    target = mod
    parts = entry["function"].split(".")
    if len(parts) == 2:
        cls = getattr(mod, parts[0])
        cache = SPEC.setdefault("_instances", {})
        if parts[0] not in cache:
            cache[parts[0]] = cls()
        target = cache[parts[0]]
        return getattr(target, parts[1])
    return getattr(target, parts[-1])


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for k in ("reply", "response", "answer", "output", "text", "content", "message", "result"):
            if isinstance(value.get(k), str):
                return value[k]
        return json.dumps(value, default=str)[:6000]
    if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
        return value[0]
    content = getattr(value, "content", None)
    return content if isinstance(content, str) else str(value)


def invoke(req: dict) -> dict:
    entry = next(e for e in SPEC["entry_points"] if e["id"] == req["entry"])
    CALLS.clear()
    LLM_CALLS.clear()
    started = time.perf_counter()
    try:
        fn = _resolve(entry)
        if not SPEC.get("_patched"):
            SPEC["patched"] = patch_tools()
            SPEC["_patched"] = True
            SPEC.pop("_instances", None)  # objects built before patching hold the original tools
            fn = _resolve(entry)
        kwargs = {entry["message_param"]: req["message"]}
        params = inspect.signature(fn).parameters
        if entry.get("session_param") and entry["session_param"] in params:
            kwargs[entry["session_param"]] = req.get("session") or "s1"
        if entry["message_param"] not in params:  # fall back to the first positional parameter
            kwargs = {}
            out = fn(req["message"])
        else:
            out = fn(**kwargs)
        if inspect.isawaitable(out):
            out = asyncio.run(out)
        reply, error = _as_text(out), ""
    except Exception as exc:  # noqa: BLE001
        reply, error = "", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1500:]}"
    return {"reply": reply[:8000], "tool_calls": list(CALLS), "llm_calls": list(LLM_CALLS), "error": error,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1)}


def main() -> None:
    global ROOT
    SPEC.update(json.loads(Path(sys.argv[1]).read_text()))
    ROOT = Path(SPEC["project_root"]).resolve()
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    redirect_models()
    PROTOCOL_OUT.write(json.dumps({"ready": True}) + "\n")
    for line in sys.stdin:
        try:
            req = json.loads(line)
            if req.get("op") == "invoke":
                resp = invoke(req)
            elif req.get("op") == "ping":
                resp = {"ok": True, "patched": SPEC.get("patched", [])}
            else:
                resp = {"error": f"unknown op {req.get('op')}"}
        except Exception as exc:  # noqa: BLE001
            resp = {"error": f"harness: {type(exc).__name__}: {exc}"}
        PROTOCOL_OUT.write(json.dumps(resp, default=str) + "\n")


if __name__ == "__main__":
    main()
