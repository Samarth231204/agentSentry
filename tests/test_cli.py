from pathlib import Path
from click.testing import CliRunner
from agentguard.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "AgentGuard" in result.output
    assert "init" in result.output
    assert "test" in result.output


def test_cli_init_no_llm(tmp_path: Path):
    runner = CliRunner()
    manifest_out = tmp_path / "out_manifest.yaml"
    result = runner.invoke(
        main,
        ["-v", "init", "samples/unsafe_tool", "--no-llm", "--manifest-out", str(manifest_out)],
    )
    assert result.exit_code == 0
    assert manifest_out.exists()
    assert "Wrote" in result.output
    assert "transfer_funds" in result.output


def test_cli_test_help():
    runner = CliRunner()
    result = runner.invoke(main, ["test", "--help"])
    assert result.exit_code == 0
    assert "--target-url" in result.output
    assert "--attacker-model" in result.output
    assert "--reporter-model" in result.output


def test_cli_lists_report_command():
    result = CliRunner().invoke(main, ["--help"])
    assert "report" in result.output


def test_cli_test_has_budget_flags():
    result = CliRunner().invoke(main, ["test", "--help"])
    assert "--max-llm-calls" in result.output
    assert "--max-tokens" in result.output


def test_cli_report_regenerates_from_findings(tmp_path: Path, monkeypatch):
    import json

    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"attempts": [{
        "id": "tool_misuse-1", "category": "tool_misuse", "capability_targeted": "destructive_tool",
        "status": "confirmed", "confidence": 1.0, "turns": [],
    }]}), encoding="utf-8")

    class BrokenCrew:
        def kickoff(self):
            raise RuntimeError("no LLM in tests")

    monkeypatch.setattr("agentguard.reporters.build_crew", lambda *a, **k: BrokenCrew())
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out.md"
    result = CliRunner().invoke(main, ["report", str(Path(__file__).parent.parent / "samples" / "unsafe_tool"),
                                       "--findings", str(findings), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists() and out.with_suffix(".json").exists()
    assert "LLM06" in out.read_text()
