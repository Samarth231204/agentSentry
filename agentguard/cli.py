"""agentguard up    start the local dashboard (default)
agentguard scan  run the Search agent in the terminal and print the result
"""

from __future__ import annotations

import json
import threading
import webbrowser
from pathlib import Path

import click


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    if ctx.invoked_subcommand is None:
        ctx.invoke(up)


@main.command()
@click.option("--project", default=".", type=click.Path(exists=True, file_okay=False), help="Project to test")
@click.option("--port", default=8765, show_default=True)
@click.option("--no-browser", is_flag=True)
@click.option("--host", default="127.0.0.1", show_default=True,
              help="0.0.0.0 in a container or on a server (the dashboard has no login: restrict who can reach it)")
def up(project: str, port: int, no_browser: bool, host: str) -> None:
    """Start the dashboard (default: 127.0.0.1 only)."""
    import uvicorn

    from agentguard.server import create_app

    url = f"http://127.0.0.1:{port}"
    click.echo(f"AgentGuard dashboard: {url}  (project: {Path(project).resolve()})  Ctrl+C to stop")
    if not no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(create_app(project), host=host, port=port, log_level="warning")


@main.command()
@click.option("--project", default=".", type=click.Path(exists=True, file_okay=False))
def scan(project: str) -> None:
    """Run the Search agent once, without the dashboard."""
    from agentguard import runs
    from agentguard.events import get_event_bus

    def show(event) -> None:
        p = event.payload
        if event.event_type == "action":
            click.echo(f"  action  {p.get('tool')} {p.get('input', '')[:120]}")
        elif event.event_type == "thought" and p.get("text"):
            click.echo(f"  thought {p['text'][:160]}")
        elif event.event_type in ("step_started", "scan_done", "error"):
            click.echo(f"[{event.event_type}] {json.dumps(p)[:300]}")

    get_event_bus().subscribe(show)
    run_id = runs.start_run(project, background=False)
    run = runs.get_run(project, run_id) or {}
    click.echo(json.dumps(run.get("search") or {"error": run.get("error")}, indent=2))
    click.echo(f"\nRun folder: {runs.runs_dir(project) / run_id}")



@main.command("a2a-attack")
@click.option("--host", default="0.0.0.0", show_default=True)
def a2a_attack(host: str) -> None:
    """Serve the ADK attack team as an A2A service (port from AGENTGUARD_A2A_ATTACK_URL)."""
    from agentguard.a2a.servers import serve_forever
    serve_forever("attack", host)


@main.command("a2a-review")
@click.option("--host", default="0.0.0.0", show_default=True)
def a2a_review(host: str) -> None:
    """Serve the CrewAI review crew as an A2A service (port from AGENTGUARD_A2A_REVIEW_URL)."""
    from agentguard.a2a.servers import serve_forever
    serve_forever("review", host)


if __name__ == "__main__":
    main()
