"""FastAPI app for the local dashboard.

Phase 1 is read-only: every endpoint reads files that the CLI already writes.
The server binds to 127.0.0.1 (see `agentguard up`) and only accepts browser
requests from the dashboard origin(s), so other websites cannot read results.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import json

from agentguard import __version__
from agentguard.server import keys as keystore
from agentguard.server.runner import RunBusy, RunManager, RunRejected, RunSpec
from agentguard.server.settings import SettingsIn, current_settings, write_settings
from agentguard.server.store import Run, RunStore

SSE_POLL_SECONDS = 0.5
SSE_KEEPALIVE_SECONDS = 15.0


def read_new_lines(path: Path, position: int) -> tuple[list[str], int]:
    """Complete lines appended to `path` after byte `position`.

    A partially written last line is left for the next call. If the file shrank
    (it was rotated or truncated), reading restarts from the beginning.

    Limitation: a file that is rewritten to the same or a larger size than the
    old read position is not detected. trace.jsonl is append-only, so this does
    not happen in practice.
    """
    if not path.exists():
        return [], position
    size = path.stat().st_size
    if size < position:
        position = 0
    if size == position:
        return [], position
    with open(path, "rb") as fh:
        fh.seek(position)
        chunk = fh.read(size - position)
    end = chunk.rfind(b"\n")
    if end == -1:
        return [], position
    complete = chunk[: end + 1]
    lines = [ln for ln in complete.decode("utf-8", errors="replace").splitlines() if ln.strip()]
    return lines, position + len(complete)


def _require_run(store: RunStore, run_id: str) -> Run:
    run = store.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Unknown run '{run_id}'")
    return run


class KeyIn(BaseModel):
    provider: str = Field(max_length=32)
    api_key: str = Field(max_length=600)


class KeyTestIn(BaseModel):
    provider: str = Field(max_length=32)
    api_key: Optional[str] = Field(default=None, max_length=600)


class RunIn(BaseModel):
    target_app: Optional[str] = Field(default=None, max_length=200)
    target_url: Optional[str] = Field(default=None, max_length=300)
    canaries: list[str] = Field(default_factory=list, max_length=10)
    max_probes: Optional[int] = Field(default=None, ge=1, le=50)
    max_llm_calls: Optional[int] = Field(default=None, ge=1, le=100000)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=100000000)
    mock: bool = False
    review_plan: bool = True
    replay_run_id: Optional[str] = Field(default=None, max_length=80)


class PlanEditIn(BaseModel):
    candidate_id: str = Field(max_length=32)
    include: Optional[bool] = None
    sandbox: Optional[bool] = None


class PlanApproveIn(BaseModel):
    edits: list[PlanEditIn] = Field(default_factory=list, max_length=500)


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def create_app(
    project_root: Path,
    run_dirs: Optional[list[Path]] = None,
    allowed_origins: Optional[list[str]] = None,
) -> FastAPI:
    store = RunStore(project_root, run_dirs)
    origins = allowed_origins or ["http://localhost:3000", "http://127.0.0.1:3000"]
    manager = RunManager(Path(project_root))
    keystore.apply_to_environ(Path(project_root))

    app = FastAPI(title="AgentGuard backend", version=__version__)
    app.state.store = store
    app.state.runs = manager
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/project")
    def project() -> dict[str, Any]:
        runs = store.scan()
        return {
            "project_root": str(store.project_root),
            "agentguard_version": __version__,
            "run_count": len(runs),
            "run_dirs": [str(p) for p in store.run_dirs],
        }

    @app.get("/api/runs")
    def list_runs() -> list[dict[str, Any]]:
        return [store.summary(run) for run in store.scan()]

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        run = _require_run(store, run_id)
        return {
            **store.summary(run),
            "llm_usage": store.llm_usage(run),
            "mcp_usage": store.mcp_usage(run),
            "event_counts": store.event_type_counts(run),
        }

    @app.get("/api/runs/{run_id}/findings")
    def get_findings(run_id: str) -> list[dict[str, Any]]:
        return store.findings(_require_run(store, run_id))

    @app.get("/api/runs/{run_id}/report")
    def get_report(run_id: str) -> dict[str, Any]:
        run = _require_run(store, run_id)
        return {
            "markdown": store.report_markdown(run),
            "json": store.report_json(run),
        }

    @app.get("/api/runs/{run_id}/manifest")
    def get_manifest(run_id: str) -> dict[str, Any]:
        return {"manifest": store.manifest(_require_run(store, run_id))}

    @app.get("/api/runs/{run_id}/trace")
    def get_trace(
        run_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(200, ge=1, le=1000),
    ) -> dict[str, Any]:
        run = _require_run(store, run_id)
        events, total = store.read_trace(run, offset=offset, limit=limit)
        return {"events": events, "total": total, "offset": offset,
                "next_offset": offset + len(events)}

    @app.get("/api/runs/{run_id}/events")
    async def stream_events(run_id: str, from_start: bool = Query(True)) -> StreamingResponse:
        """Server-sent events: one `trace` event per line of trace.jsonl.

        Replays the existing trace, then follows new lines as the CLI appends
        them. Keepalive comments stop proxies and the browser from timing out.
        """
        run = _require_run(store, run_id)
        path = run.path / "trace.jsonl"
        position = 0 if from_start else (path.stat().st_size if path.exists() else 0)

        async def generator():
            nonlocal position
            yield ": connected\n\n"
            idle = 0.0
            while True:
                lines, position = read_new_lines(path, position)
                for line in lines:
                    yield f"event: trace\ndata: {line}\n\n"
                if lines:
                    idle = 0.0
                else:
                    idle += SSE_POLL_SECONDS
                    if idle >= SSE_KEEPALIVE_SECONDS:
                        idle = 0.0
                        yield ": keepalive\n\n"
                await asyncio.sleep(SSE_POLL_SECONDS)

        headers = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
        return StreamingResponse(generator(), media_type="text/event-stream", headers=headers)

    # ----- settings and API keys (Phase 2) -----------------------------------

    @app.get("/api/settings")
    def get_settings(response: Response) -> dict[str, Any]:
        _no_store(response)
        return {
            "settings": current_settings(Path(project_root)),
            "providers": keystore.key_status(Path(project_root)),
        }

    @app.put("/api/settings")
    def put_settings(body: SettingsIn, response: Response) -> dict[str, Any]:
        _no_store(response)
        write_settings(Path(project_root), body)
        return {"settings": current_settings(Path(project_root))}

    @app.post("/api/settings/keys")
    def save_key(body: KeyIn, response: Response) -> dict[str, Any]:
        _no_store(response)
        try:
            return keystore.save_key(Path(project_root), body.provider, body.api_key)
        except keystore.KeyInputError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/settings/keys/test")
    def test_key(body: KeyTestIn, response: Response) -> dict[str, Any]:
        _no_store(response)
        key = body.api_key
        if not key:
            stored = keystore.read_keys(Path(project_root)).get(body.provider)
            if not stored:
                raise HTTPException(status_code=400, detail="No key saved for this provider and none was given.")
            key = stored
        try:
            return keystore.test_key(body.provider, key)
        except keystore.KeyInputError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.delete("/api/settings/keys/{provider}")
    def remove_key(provider: str, response: Response) -> dict[str, Any]:
        _no_store(response)
        try:
            return keystore.delete_key(Path(project_root), provider)
        except keystore.KeyInputError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # ----- runs started from the dashboard (Phase 2) -------------------------

    @app.post("/api/runs", status_code=201)
    def start_run(body: RunIn) -> dict[str, Any]:
        spec = RunSpec(
            target_app=body.target_app or None,
            target_url=body.target_url or None,
            canaries=[c for c in body.canaries if c.strip()],
            max_probes=body.max_probes,
            max_llm_calls=body.max_llm_calls,
            max_tokens=body.max_tokens,
            mock=body.mock,
            review_plan=body.review_plan,
            replay_run_id=body.replay_run_id or None,
        )
        try:
            handle = manager.start(spec)
        except RunRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except RunBusy as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return handle.as_dict()

    @app.get("/api/active-run")
    def active_run() -> Optional[dict[str, Any]]:
        handle = manager.active()
        return handle.as_dict() if handle else None

    @app.get("/api/runs/{run_id}/status")
    def run_status(run_id: str) -> dict[str, Any]:
        handle = manager.get(run_id)
        if handle is None:
            raise HTTPException(status_code=404, detail="No live status for this run (it may predate this server).")
        return handle.as_dict()

    @app.get("/api/runs/{run_id}/plan")
    def get_plan(run_id: str) -> dict[str, Any]:
        handle = manager.get(run_id)
        plan_file = Path(project_root) / ".agentguard" / "runs" / Path(handle.run_dir).name / "plan.json" \
            if handle else None
        if handle is None:
            run = _require_run(store, run_id)
            plan_file = run.path / "plan.json"
            discovery_file = run.path / "discovery.json"
        else:
            discovery_file = handle.run_dir / "discovery.json"
        if not plan_file or not plan_file.exists():
            raise HTTPException(status_code=404, detail="No plan for this run yet.")
        plan = json.loads(plan_file.read_text(encoding="utf-8"))
        candidates = []
        if discovery_file.exists():
            candidates = json.loads(discovery_file.read_text(encoding="utf-8")).get("candidates", [])
        return {"plan": plan, "candidates": candidates}

    @app.post("/api/runs/{run_id}/plan/approve")
    def approve_plan(run_id: str, body: PlanApproveIn) -> dict[str, Any]:
        try:
            handle = manager.approve_plan(run_id, [e.model_dump(exclude_none=True) for e in body.edits])
        except KeyError:
            raise HTTPException(status_code=404, detail="No live run with that id.")
        except (RunRejected, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return handle.as_dict()

    @app.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str) -> dict[str, Any]:
        try:
            return manager.cancel(run_id).as_dict()
        except KeyError:
            raise HTTPException(status_code=404, detail="No live status for this run.")

    return app
