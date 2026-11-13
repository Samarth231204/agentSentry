import json
from pathlib import Path
from typing import Optional

import click

from agentguard import __version__
from agentguard.attackers import run_attack_suite_sync
from agentguard.budget import BudgetConfig, BudgetTracker
from agentguard.config import AgentGuardConfig, get_config, set_config
from agentguard.events import JSONLFileSink, get_event_bus
from agentguard.logging import get_logger, setup_logging
from agentguard.manifest import Manifest, synthesize
from agentguard.reporters import compute_scorecard, generate_report
from agentguard.schemas import TargetProfile
from agentguard.target import Target

logger = get_logger("cli")


@click.group()
@click.version_option(__version__, prog_name="agentguard")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose debug logging.")
@click.option("-q", "--quiet", is_flag=True, help="Enable quiet mode (errors only).")
@click.option("--config", "config_file", type=click.Path(exists=True, dir_okay=False), help="Path to custom agentguard.yaml configuration file.")
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool, config_file: Optional[str]) -> None:
    """AgentGuard — automated red-teaming for AI agent applications."""
    ctx.ensure_object(dict)
    setup_logging(verbose=verbose, quiet=quiet)
    cfg = AgentGuardConfig.load(config_path=config_file)
    set_config(cfg)
    ctx.obj["config"] = cfg


@main.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False))
@click.option("--manifest-out", default=None,
              help="Where to write the generated manifest.yaml (default: <project_path>/manifest.yaml)")
@click.option("--no-llm", is_flag=True, help="Skip LLM synthesis, use AST-only heuristic verdicts.")
def init(project_path: str, manifest_out: str | None, no_llm: bool) -> None:
    """Statically scan PROJECT_PATH and write a capability manifest.

    Never executes the target — pure static analysis. Safe to run against
    any project before deciding whether to run `agentguard test` against it.
    """
    out_path = Path(manifest_out) if manifest_out else Path(project_path) / "manifest.yaml"
    click.echo(f"Scanning {project_path} ...")
    manifest = synthesize(project_path, use_llm=not no_llm)
    manifest.to_yaml(out_path)

    click.echo(f"Wrote {out_path}")
    click.echo(f"  tools: {[t.name for t in manifest.tools]} "
               f"(destructive: {[t.name for t in manifest.tools if t.destructive]})")
    click.echo(f"  rag: {manifest.rag.get('present')}  memory: {manifest.memory.get('present')}")
    click.echo(f"  attacker categories this manifest routes to: {manifest.routing()}")


@main.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False))
@click.option("--target-url", required=True, help="URL of the already-running target (see agentguard.adapter.serve()).")
@click.option("--manifest", "manifest_path", default=None,
              help="Path to an existing manifest.yaml (default: <project_path>/manifest.yaml, generated if missing).")
@click.option("--findings-out", default="findings.json", help="Where to write findings.json.")
@click.option("--report-out", default="report.md", help="Where to write report.md.")
@click.option("--canary", "canaries", multiple=True, help="Known canary string(s) to check for in target responses. Repeatable.")
@click.option("--max-probes", default=None, type=int, help="Max probes per attacker category (default: from config).")
@click.option("--attacker-model", default=None, help="Override LLM model used by attacker agents.")
@click.option("--reporter-model", default=None, help="Override LLM model used by reporter agents.")
@click.option("--max-llm-calls", default=None, type=click.IntRange(min=1),
              help="Hard ceiling on attacker + judge LLM calls for this run (default: unlimited).")
@click.option("--max-tokens", default=None, type=click.IntRange(min=1),
              help="Hard ceiling on attacker + judge LLM tokens for this run (default: unlimited).")
def test(project_path: str, target_url: str, manifest_path: str | None,
         findings_out: str, report_out: str, canaries: tuple[str, ...],
         max_probes: Optional[int], attacker_model: Optional[str],
         reporter_model: Optional[str], max_llm_calls: Optional[int],
         max_tokens: Optional[int]) -> None:
    """Run the full pipeline against a live target: manifest -> attack -> report.

    The target must already be running and reachable at --target-url (start
    it separately with `uvicorn <your_app>:app`, where your_app used
    @expose/@watch from agentguard.adapter). This command never starts a
    target process itself.
    """
    get_event_bus().subscribe(JSONLFileSink("trace.jsonl"))
    manifest_file = Path(manifest_path) if manifest_path else Path(project_path) / "manifest.yaml"
    if manifest_file.exists():
        click.echo(f"Loading manifest from {manifest_file}")
        manifest = Manifest.from_yaml(manifest_file)
    else:
        click.echo(f"No manifest found at {manifest_file}, generating one first...")
        manifest = synthesize(project_path)
        manifest.to_yaml(manifest_file)
        click.echo(f"Wrote {manifest_file}")

    click.echo(f"Routing to attacker categories: {manifest.routing()}")

    target = Target(target_url)
    try:
        health = target.health()
    except Exception as exc:
        raise click.ClickException(f"Could not connect to target at {target_url}: {exc}")

    if not health.get("entrypoint_registered"):
        raise click.ClickException(
            f"Target at {target_url} has no @expose entrypoint registered — check it's the right process."
        )

    probes = max_probes if max_probes is not None else get_config().max_probes
    profile = TargetProfile(
        tools=[tool.name for tool in manifest.tools],
        has_rag=bool(manifest.rag.get("present")),
        has_memory=bool(manifest.memory.get("present")),
    )

    # Always track usage (so it lands in trace.jsonl and findings.json);
    # ceilings apply only when the flags are given. The CrewAI reporter's
    # calls are not counted: CrewAI calls its LLM directly.
    budget = BudgetTracker(BudgetConfig(max_calls_total=max_llm_calls, max_tokens_total=max_tokens))

    click.echo(f"Attacking {target_url} ...")
    sink = None
    try:
        sink = run_attack_suite_sync(
            target,
            manifest,
            canaries=list(canaries),
            max_probes=probes,
            model=attacker_model,
            budget=budget,
            profile=profile,
        )
    finally:
        if sink is not None:
            findings_data = {
                "target": sink.target_desc,
                "manifest_summary": sink.manifest_summary,
                "attempts": sink.session_state.get("findings", [a.model_dump(mode="json") for a in sink.attempts]),
                "budget_usage": budget.usage_report(),
            }
            Path(findings_out).write_text(json.dumps(findings_data, indent=2), encoding="utf-8")
            click.echo(f"Wrote {findings_out}")

    usage = budget.usage_report()
    click.echo(f"LLM usage (attacker + judge): {usage['total']['calls']} calls, "
               f"{usage['total']['prompt_tokens'] + usage['total']['completion_tokens']} tokens"
               + (" — BUDGET EXHAUSTED, later categories were skipped" if budget.exhausted else ""))
    for role, row in usage["by_role"].items():
        click.echo(f"  {role}: {row['calls']} calls, {row['prompt_tokens'] + row['completion_tokens']} tokens")

    scorecard = compute_scorecard(findings_data)
    click.echo(f"Scorecard: {scorecard['total_successes']}/{scorecard['total_attempts']} "
               f"attacks succeeded ({scorecard['success_rate']:.0%})")
    for cat, row in scorecard["by_category"].items():
        click.echo(f"  {cat}: {row['succeeded']}/{row['attempted']}")

    click.echo("Generating report (offline, no further contact with the target)...")
    generate_report(
        findings_out,
        report_out,
        manifest_path=str(manifest_file),
        model=reporter_model,
        project_path=project_path,
    )
    click.echo(f"Wrote {report_out}")


@main.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False))
@click.option("--findings", "findings_path", default="findings.json", show_default=True,
              type=click.Path(exists=True, dir_okay=False),
              help="findings.json written by an earlier `agentguard test` run.")
@click.option("--output", "report_out", default="report.md", show_default=True,
              help="Where to write report.md (report.json is written alongside it).")
@click.option("--manifest", "manifest_path", default=None,
              help="Path to manifest.yaml (default: <project_path>/manifest.yaml if it exists).")
@click.option("--reporter-model", default=None, help="Override LLM model used by reporter agents.")
def report(project_path: str, findings_path: str, report_out: str,
           manifest_path: Optional[str], reporter_model: Optional[str]) -> None:
    """Regenerate the report from an existing findings.json.

    Never contacts the target and runs no attacks, so it costs only reporter
    LLM calls. Useful after the reporter model hit a quota, or to try a
    different --reporter-model on the same findings.
    """
    get_event_bus().subscribe(JSONLFileSink("trace.jsonl"))
    manifest_file = Path(manifest_path) if manifest_path else Path(project_path) / "manifest.yaml"
    if manifest_path and not manifest_file.exists():
        raise click.ClickException(f"Manifest not found: {manifest_file}")

    click.echo(f"Generating report from {findings_path} (offline, no contact with any target)...")
    generate_report(
        findings_path,
        report_out,
        manifest_path=str(manifest_file) if manifest_file.exists() else None,
        model=reporter_model,
        project_path=project_path,
    )
    click.echo(f"Wrote {report_out} and {Path(report_out).with_suffix('.json')}")


@main.command()
@click.option("--project", "project_path", default=".", show_default="current directory",
              type=click.Path(exists=True, file_okay=False),
              help="Project whose runs the dashboard shows (its .agentguard/runs and root outputs).")
@click.option("--port", default=8787, show_default=True, type=click.IntRange(1, 65535),
              help="Port for the local backend (bound to 127.0.0.1).")
@click.option("--dashboard-port", default=3000, show_default=True, type=click.IntRange(1, 65535),
              help="Port for the dashboard dev server.")
@click.option("--run-dir", "run_dirs", multiple=True, type=click.Path(exists=True, file_okay=False),
              help="Extra folder to show as one run (repeatable).")
@click.option("--no-dashboard", is_flag=True, help="Start only the backend API.")
@click.option("--no-browser", is_flag=True, help="Do not open the dashboard in a browser.")
@click.option("--no-mcp", is_flag=True, help="Do not start AgentGuard's MCP servers.")
def up(project_path: str, port: int, dashboard_port: int, run_dirs: tuple[str, ...],
       no_dashboard: bool, no_browser: bool, no_mcp: bool) -> None:
    """Start the local backend and dashboard, then open the dashboard.

    Serves the API at http://127.0.0.1:PORT and the dashboard at
    http://localhost:DASHBOARD_PORT. Stop both with Ctrl+C.
    """
    import threading
    import webbrowser

    import uvicorn

    from agentguard.server import launcher
    from agentguard.server.app import create_app

    backend_url = f"http://127.0.0.1:{port}"
    dashboard_url = f"http://localhost:{dashboard_port}"
    app = create_app(
        Path(project_path),
        [Path(p) for p in run_dirs],
        allowed_origins=[f"http://localhost:{dashboard_port}", f"http://127.0.0.1:{dashboard_port}"],
    )

    import os as _os
    _os.environ["AGENTGUARD_A2A_URL"] = backend_url  # the runner reaches the A2A agents on the same backend

    mcp_servers = []
    if not no_mcp:
        from agentguard.mcp import launch
        try:
            mcp_servers = launch.start_all(Path(project_path))
            for server in mcp_servers:
                click.echo(f"MCP {server.name} at {server.url} ({len(server.tools)} tools)")
        except RuntimeError as exc:
            click.echo(f"MCP servers not started: {exc}. Runs will use the built-in fallbacks.")

    dashboard_proc = None
    from agentguard.server.app import static_dashboard_ready
    if not no_dashboard and static_dashboard_ready():
        click.echo(f"Dashboard at {backend_url}/ (served by the backend; no Node needed)")
        if not no_browser:
            threading.Timer(1.5, webbrowser.open, args=(f"{backend_url}/",)).start()
    elif not no_dashboard:
        ready, reason = launcher.dashboard_status()
        if ready:
            dashboard_proc = launcher.start_dashboard(backend_url, dashboard_port)
            click.echo(f"Dashboard starting at {dashboard_url} ...")
        else:
            click.echo(f"Dashboard not started: {reason}. API only.")

    click.echo(f"Backend API at {backend_url}  (project: {Path(project_path).resolve()})")
    if dashboard_proc is not None and not no_browser:
        threading.Timer(4.0, webbrowser.open, args=(dashboard_url,)).start()
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    finally:
        launcher.stop_dashboard(dashboard_proc)
        from agentguard.mcp import launch as _launch
        _launch.stop_all(mcp_servers)


@main.group()
def mcp() -> None:
    """Run or check AgentGuard's MCP servers (code intelligence and security knowledge)."""


@mcp.command("list")
@click.argument("project_path", default=".", type=click.Path(exists=True, file_okay=False))
def mcp_list(project_path: str) -> None:
    """Start both servers for PROJECT_PATH, print their tools, and stop them again."""
    from agentguard.mcp import launch
    from agentguard.mcp.semgrep import semgrep_spec

    servers = launch.start_all(Path(project_path))
    try:
        for server in servers:
            click.echo(f"{server.name}: {server.url}")
            for tool in server.tools:
                click.echo(f"  - {tool}")
    finally:
        launch.stop_all(servers)
    _, reason = semgrep_spec()
    click.echo(f"semgrep (external): {'available' if reason == 'ok' else reason}")


@mcp.command("serve")
@click.argument("name", type=click.Choice(["codeintel", "security-kb"]))
@click.option("--project", default=".", type=click.Path(exists=True, file_okay=False),
              help="Project for the codeintel server.")
@click.option("--port", default=None, type=click.IntRange(1, 65535))
def mcp_serve(name: str, project: str, port: Optional[int]) -> None:
    """Run one server in the foreground (Streamable HTTP on 127.0.0.1)."""
    import sys as _sys

    argv = ["agentguard-mcp", "--port", str(port or (8790 if name == "codeintel" else 8791))]
    if name == "codeintel":
        argv += ["--project", str(Path(project).resolve())]
        from agentguard.mcp.codeintel_server import main as serve_main
    else:
        from agentguard.mcp.security_kb_server import main as serve_main
    _sys.argv = argv
    serve_main()


@main.command()
@click.option("--project", "project_path", default=".", type=click.Path(exists=True, file_okay=False),
              help="The project that will contain the AgentGuard folder.")
def bootstrap(project_path: str) -> None:
    """Keep AgentGuard's files out of git: adds this clone and .agentguard/ to the project's .gitignore."""
    project = Path(project_path).resolve()
    clone = Path(__file__).resolve().parents[1]
    entries: list[str] = []
    try:
        entries.append(clone.relative_to(project).as_posix() + "/")
    except ValueError:
        click.echo(f"Note: AgentGuard is not inside {project}; only .agentguard/ will be ignored.")
    entries.append(".agentguard/")
    gitignore = project / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8").splitlines() if gitignore.exists() else []
    missing = [e for e in entries if e not in {line.strip() for line in existing}]
    if missing:
        block = ["", "# AgentGuard (added by `agentguard bootstrap`)"] + missing
        gitignore.write_text("\n".join(existing + block) + "\n", encoding="utf-8")
        click.echo(f"Added to {gitignore}: {', '.join(missing)}")
    else:
        click.echo(f"{gitignore} already ignores AgentGuard.")
    (project / ".agentguard").mkdir(exist_ok=True)
    click.echo(f"Next: agentguard up --project {project}")


@main.command()
def doctor() -> None:
    """Checks what AgentGuard needs on this machine. Prints presence only, never key values."""
    import os as _os
    import shutil as _shutil
    import socket as _socket
    import sys as _sys

    from agentguard.server.app import static_dashboard_ready
    from agentguard.server.keys import PROVIDERS, read_keys
    from agentguard.mcp.semgrep import semgrep_spec

    def line(ok: bool, label: str, hint: str = "") -> None:
        click.echo(f"[{'ok' if ok else 'missing'}] {label}" + (f" — {hint}" if hint and not ok else ""))

    line(_sys.version_info >= (3, 10), f"Python {_sys.version.split()[0]} (3.10+ required)")
    line(static_dashboard_ready(), "dashboard build", "run scripts/build_dashboard.sh (developers only)")
    line(_shutil.which("node") is not None, "Node.js (optional: only for dashboard development)")
    line(_shutil.which("uvx") is not None, "uvx (for Semgrep's MCP server)", "install uv: https://docs.astral.sh/uv/")
    spec, reason = semgrep_spec()
    line(spec is not None, "Semgrep (sink evidence, optional)", reason)

    project = Path(".").resolve()
    stored = read_keys(project)
    for pid, meta in PROVIDERS.items():
        present = pid in stored or bool(_os.environ.get(meta["env"]))
        line(present, f"{meta['label']} key {'set' if present else 'not set'} (optional, one is needed for live runs)")

    for port in (8787, 8790, 8791, 3000):
        with _socket.socket() as s:
            busy = s.connect_ex(("127.0.0.1", port)) == 0
        line(not busy, f"port {port} free", "something is already listening; stop it or pick another port")


if __name__ == "__main__":
    main()
