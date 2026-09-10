import json
from pathlib import Path

import click

from agentguard.attackers import run_attack_suite_sync
from agentguard.manifest import Manifest, synthesize
from agentguard.reporters import compute_scorecard, generate_report
from agentguard.target import Target


@click.group()
def main() -> None:
    """AgentGuard — automated red-teaming for AI agent applications."""


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
@click.option("--max-probes", default=6, help="Max probes per attacker category.")
def test(project_path: str, target_url: str, manifest_path: str | None,
         findings_out: str, report_out: str, canaries: tuple[str, ...],
         max_probes: int) -> None:
    """Run the full pipeline against a live target: manifest -> attack -> report.

    The target must already be running and reachable at --target-url (start
    it separately with `uvicorn <your_app>:app`, where your_app used
    @expose/@watch from agentguard.adapter). This command never starts a
    target process itself.
    """
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
    health = target.health()
    if not health.get("entrypoint_registered"):
        raise click.ClickException(
            f"Target at {target_url} has no @expose entrypoint registered — check it's the right process."
        )

    click.echo(f"Attacking {target_url} ...")
    sink = run_attack_suite_sync(target, manifest, findings_out, canaries=list(canaries), max_probes=max_probes)
    click.echo(f"Wrote {findings_out}")

    scorecard = compute_scorecard(json.loads(Path(findings_out).read_text()))
    click.echo(f"Scorecard: {scorecard['total_successes']}/{scorecard['total_attempts']} "
               f"attacks succeeded ({scorecard['success_rate']:.0%})")
    for cat, row in scorecard["by_category"].items():
        click.echo(f"  {cat}: {row['succeeded']}/{row['attempted']}")

    click.echo("Generating report (offline, no further contact with the target)...")
    generate_report(findings_out, report_out, manifest_path=str(manifest_file))
    click.echo(f"Wrote {report_out}")


if __name__ == "__main__":
    main()
