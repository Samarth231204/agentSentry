"""Local dashboard server: http://127.0.0.1:8765

  GET  /                          the dashboard (static/index.html)
  GET  /api/status                project, model, key present, active run
  POST /api/runs                  start a Search run
  GET  /api/runs                  list runs
  POST /api/runs/{id}/resume      continue a failed or stopped run from its last checkpoint
  GET  /api/runs/{id}             run + scan + search result
  GET  /api/runs/{id}/events      the trace as Server-Sent Events (live while running)
  GET  /healthz                   liveness, no login needed

Login: when AGENTGUARD_DASHBOARD_TOKEN is set, every other path needs it. Open the dashboard once
with ?token=<token>: the server checks it, stores it in an HttpOnly cookie and redirects to the same
URL without the token (so it does not stay in the address bar or history). Scripts can send
`Authorization: Bearer <token>` instead.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse

from agentguard import runs
from agentguard.llm import has_key, model_name
from agentguard.mcp.semgrep import semgrep_spec

STATIC = Path(__file__).resolve().parent / "static"
TOKEN_ENV = "AGENTGUARD_DASHBOARD_TOKEN"
COOKIE = "agentguard_token"
OPEN_PATHS = {"/healthz"}


def dashboard_token() -> str:
    return os.environ.get(TOKEN_ENV, "").strip()


def _same(given: str | None, token: str) -> bool:
    return bool(given) and hmac.compare_digest(given.encode(), token.encode())


def _add_login(app: FastAPI, token: str) -> None:
    @app.middleware("http")
    async def login(request: Request, call_next):
        if request.url.path in OPEN_PATHS:
            return await call_next(request)
        given = request.query_params.get("token")
        if given is not None:
            if not _same(given, token):
                return _denied(request)
            rest = urlencode([(k, v) for k, v in request.query_params.multi_items() if k != "token"])
            resp = RedirectResponse(request.url.path + (f"?{rest}" if rest else ""), status_code=303)
            resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", max_age=30 * 24 * 3600,
                            secure=request.url.scheme == "https")
            return resp
        bearer = request.headers.get("authorization", "")
        if _same(request.cookies.get(COOKIE), token) or _same(bearer.removeprefix("Bearer ").strip(), token):
            return await call_next(request)
        return _denied(request)


def _denied(request: Request):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "login needed: open the dashboard with ?token=<your token>"}, status_code=401)
    return PlainTextResponse("AgentGuard: login needed. Open this page with ?token=<your token>.", status_code=401)


def create_app(project: str | Path) -> FastAPI:
    project = Path(project).resolve()
    app = FastAPI(title="AgentGuard")
    runs.mark_orphans(project)
    token = dashboard_token()
    if token:
        _add_login(app, token)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

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

    @app.get("/api/runs/{run_id}/report.md", response_class=PlainTextResponse)
    def report_md(run_id: str) -> str:
        path = runs.runs_dir(project) / Path(run_id).name / "report.md"
        if not path.exists():
            raise HTTPException(404, "no report for this run yet")
        return path.read_text()

    @app.get("/api/a2a")
    def a2a_cards() -> dict:
        """The Agent Cards of the two A2A services (if they are running)."""
        import httpx

        from agentguard.a2a.cards import attack_url, review_url
        out = {}
        for name, url in (("attack", attack_url()), ("review", review_url())):
            try:
                out[name] = httpx.get(f"{url}/.well-known/agent-card.json", timeout=2).json()
            except Exception:  # noqa: BLE001
                out[name] = {"url": url, "running": False}
        return out

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
