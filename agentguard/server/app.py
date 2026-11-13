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

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from agentguard import __version__
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


def create_app(
    project_root: Path,
    run_dirs: Optional[list[Path]] = None,
    allowed_origins: Optional[list[str]] = None,
) -> FastAPI:
    store = RunStore(project_root, run_dirs)
    origins = allowed_origins or ["http://localhost:3000", "http://127.0.0.1:3000"]

    app = FastAPI(title="AgentGuard backend", version=__version__)
    app.state.store = store
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

    return app
