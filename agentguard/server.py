"""Local dashboard server: http://127.0.0.1:8765

  GET  /                          the dashboard (static/index.html)
  GET  /api/status                project, model, key present, active run
  POST /api/runs                  start a Search run
  GET  /api/runs                  list runs
  POST /api/runs/{id}/resume      continue a failed or stopped run from its last checkpoint
  GET  /api/runs/{id}             run + scan + search result
  GET  /api/runs/{id}/events      the trace as Server-Sent Events (live while running)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from agentguard import runs
from agentguard.llm import has_key, model_name
from agentguard.mcp.semgrep import semgrep_spec

STATIC = Path(__file__).resolve().parent / "static"


def create_app(project: str | Path) -> FastAPI:
    project = Path(project).resolve()
    app = FastAPI(title="AgentGuard")
    runs.mark_orphans(project)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/status")
    def status() -> dict:
        spec, reason = semgrep_spec()
        return {"project": str(project), "model": model_name(), "has_key": has_key(),
                "semgrep": "ok" if spec else reason, "active_run": runs.active_run()}

    @app.get("/api/runs")
    def list_runs() -> list[dict]:
        return runs.list_runs(project)

    @app.post("/api/runs")
    def start() -> dict:
        if not has_key():
            raise HTTPException(400, "No API key: add ANTHROPIC_API_KEY to AgentGuard/.env")
        try:
            return {"id": runs.start_run(project)}
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/runs/{run_id}/resume")
    def resume(run_id: str) -> dict:
        run = runs.get_run(project, run_id)
        if run is None:
            raise HTTPException(404, "no such run")
        if run.get("status") == "done":
            raise HTTPException(400, "this run already finished")
        try:
            return {"id": runs.start_run(project, resume=run_id)}
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict:
        run = runs.get_run(project, run_id)
        if run is None:
            raise HTTPException(404, "no such run")
        return run

    @app.get("/api/runs/{run_id}/events")
    async def events(run_id: str) -> StreamingResponse:
        run_dir = runs.runs_dir(project) / Path(run_id).name
        if not run_dir.exists():
            raise HTTPException(404, "no such run")

        async def stream():
            path = run_dir / "trace.jsonl"
            pos = 0
            while True:
                if path.exists():
                    with open(path, encoding="utf-8") as f:
                        f.seek(pos)
                        chunk = f.read()
                        pos = f.tell()
                    for line in chunk.splitlines():
                        if line.strip():
                            yield f"data: {line}\n\n"
                meta = runs.read_json(run_dir / "run.json") or {}
                if meta.get("status") != "running":
                    yield f"event: end\ndata: {json.dumps({'status': meta.get('status')})}\n\n"
                    return
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream")

    return app
