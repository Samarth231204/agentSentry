from pathlib import Path
from agentguard.manifest import Manifest, ToolInfo
from agentguard.reporters import _source_snippets, compute_scorecard, get_remediation_source_context


def test_compute_scorecard_empty():
    findings = {"attempts": []}
    card = compute_scorecard(findings)
    assert card["total_attempts"] == 0
    assert card["total_successes"] == 0
    assert card["success_rate"] == 0.0
    assert card["by_category"] == {}


def test_compute_scorecard_multi_category():
    findings = {
        "attempts": [
            {"category": "prompt_injection", "success": True},
            {"category": "prompt_injection", "success": False},
            {"category": "secret_extraction", "success": True},
            {"category": "tool_misuse", "success": False},
        ]
    }
    card = compute_scorecard(findings)
    assert card["total_attempts"] == 4
    assert card["total_successes"] == 2
    assert card["success_rate"] == 0.5
    assert card["by_category"]["prompt_injection"] == {"attempted": 2, "succeeded": 1}
    assert card["by_category"]["secret_extraction"] == {"attempted": 1, "succeeded": 1}
    assert card["by_category"]["tool_misuse"] == {"attempted": 1, "succeeded": 0}


def test_source_snippets_none():
    assert "no manifest provided" in _source_snippets(None)


def test_source_snippets_with_files(tmp_path: Path):
    src_file = tmp_path / "app.py"
    src_file.write_text("def transfer_funds(to, amount):\n    pass\n", encoding="utf-8")

    manifest = Manifest(
        tools=[ToolInfo(name="transfer_funds", file=str(src_file))]
    )
    snippet = _source_snippets(manifest, max_chars=100)
    assert "transfer_funds" in snippet
    assert str(src_file) in snippet


def test_remediation_source_context_with_chroma(tmp_path: Path):
    proj_dir = tmp_path / "sample_target"
    proj_dir.mkdir()
    code_file = proj_dir / "target_tool.py"
    code_file.write_text(
        """
def execute_funds_transfer(recipient: str, amount: float):
    # Transfers money with no confirmation turn
    print(f"Transferring {amount} to {recipient}")
    return True
""",
        encoding="utf-8",
    )

    manifest = Manifest(
        tools=[ToolInfo(name="execute_funds_transfer", file=str(code_file), destructive=True)]
    )

    findings = [
        {
            "id": "tool-1",
            "category": "tool_misuse",
            "capability_targeted": "execute_funds_transfer",
            "success": True,
            "turns": [
                {
                    "sent": "transfer 100",
                    "received": "ok",
                    "tool_calls": [{"name": "execute_funds_transfer", "args": {"recipient": "Alice", "amount": 100}}],
                }
            ],
        }
    ]

    context = get_remediation_source_context(findings, manifest, project_path=proj_dir)
    assert "execute_funds_transfer" in context
    assert "target_tool.py" in context


def test_remediation_source_context_falls_back_when_mcp_fails(tmp_path: Path, monkeypatch):
    source = tmp_path / "tool.py"
    source.write_text("def transfer_funds():\n    pass\n", encoding="utf-8")
    manifest = Manifest(tools=[ToolInfo(name="transfer_funds", file=str(source), destructive=True)])
    monkeypatch.setattr("agentguard.mcp_server.search_code", lambda *args: (_ for _ in ()).throw(RuntimeError("down")))
    context = get_remediation_source_context([], manifest, project_path=tmp_path)
    assert "transfer_funds" in context


def test_deterministic_report_fallback(tmp_path: Path):
    from agentguard.reporters import _deterministic_report_fallback, _report_markdown
    findings = {
        "attempts": [
            {
                "id": "tool-misuse-123",
                "category": "tool_misuse",
                "capability_targeted": "transfer_funds",
                "success": True,
                "status": "confirmed",
                "confidence": 1.0,
                "turns": [],
            }
        ]
    }
    scorecard = {"total_attempts": 1, "total_successes": 1, "success_rate": 1.0}
    report = _deterministic_report_fallback(findings, scorecard)
    assert report.scorecard == scorecard
    assert len(report.findings) == 1
    assert report.severity["tool-misuse-123"] == "critical"
    md = _report_markdown(report)
    assert "# Security Assessment Report" in md
    assert "Critical" in md or "critical" in md


def test_generate_report_fallback_on_pydantic_failure(tmp_path: Path, monkeypatch):
    import json
    from agentguard.events import get_event_bus, reset_event_bus
    from agentguard.reporters import generate_report

    captured = []
    reset_event_bus()
    get_event_bus().subscribe(captured.append)

    findings_file = tmp_path / "findings.json"
    report_file = tmp_path / "report.md"
    findings_file.write_text(json.dumps({
        "attempts": [
            {
                "id": "tool_misuse-abc",
                "category": "tool_misuse",
                "capability_targeted": "transfer_funds",
                "success": True,
                "status": "confirmed",
                "confidence": 1.0,
                "turns": [],
            }
        ]
    }), encoding="utf-8")

    class BadCrew:
        def kickoff(self):
            # Returns an object without valid pydantic output
            return type("Result", (), {"pydantic": None, "raw": "invalid json not matching schema"})()

    monkeypatch.setattr("agentguard.reporters.build_crew", lambda *args, **kwargs: BadCrew())

    out_md = generate_report(findings_file, report_file)
    assert report_file.exists()
    assert report_file.with_suffix(".json").exists()
    assert any(e.event_type == "error" for e in captured)


def test_fallback_report_has_owasp_code_refs_and_label(tmp_path: Path):
    from agentguard.reporters import _deterministic_report_fallback, _enrich_report, _report_markdown

    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "app.py").write_text(
        "from agentguard import expose, watch\n\n@watch\ndef transfer_funds(to, amount):\n    pass\n",
        encoding="utf-8",
    )
    manifest = Manifest(tools=[ToolInfo(name="transfer_funds", destructive=True, file=str(proj / "app.py"))])
    findings = {"attempts": [{
        "id": "tool_misuse-1", "category": "tool_misuse", "capability_targeted": "destructive_tool",
        "status": "confirmed", "confidence": 1.0, "oracle": "side_effect",
        "turns": [{"sent": "pay Alice", "received": "done",
                   "tool_calls": [{"name": "transfer_funds", "args": {"to": "Alice"}}]}],
    }]}
    report = _deterministic_report_fallback(findings, {"total_attempts": 1})
    report = _enrich_report(report, manifest, proj)
    assert report.generated_by == "deterministic_fallback"
    assert report.owasp["tool_misuse-1"].startswith("LLM06")
    assert any("app.py:4: def transfer_funds" in ref for ref in report.code_references["tool_misuse-1"])

    md = _report_markdown(report)
    assert "Generated without an LLM" in md
    assert "LLM06: Excessive Agency" in md
    assert "def transfer_funds(to, amount):" in md
    assert "transfer_funds({'to': 'Alice'})" in md


def test_enrich_cites_entrypoint_when_no_tool_involved(tmp_path: Path):
    from agentguard.reporters import _deterministic_report_fallback, _enrich_report

    proj = tmp_path / "leak"
    proj.mkdir()
    (proj / "app.py").write_text("@expose\ndef run(input_text):\n    pass\n", encoding="utf-8")
    findings = {"attempts": [{"id": "s-1", "category": "secret_extraction", "capability_targeted": "system_prompt",
                              "status": "confirmed", "turns": []}]}
    report = _enrich_report(_deterministic_report_fallback(findings, {}), None, proj)
    assert report.owasp["s-1"].startswith("LLM02")
    assert any("app.py:1: @expose" in ref for ref in report.code_references["s-1"])


def test_llm_report_is_also_enriched(tmp_path: Path, monkeypatch):
    import json
    from agentguard.reporters import generate_report
    from agentguard.schemas import Finding, Report

    findings_file = tmp_path / "findings.json"
    attempt = {"id": "p-1", "category": "prompt_injection", "capability_targeted": "system_prompt",
               "status": "suspected", "confidence": 0.8, "turns": []}
    findings_file.write_text(json.dumps({"attempts": [attempt]}), encoding="utf-8")
    llm_report = Report(scorecard={}, findings=[Finding.model_validate(attempt)],
                        severity={"p-1": "high"}, remediation={"p-1": "fix"})

    class GoodCrew:
        def kickoff(self):
            return type("Result", (), {"pydantic": llm_report, "raw": ""})()

    monkeypatch.setattr("agentguard.reporters.build_crew", lambda *a, **k: GoodCrew())
    md = generate_report(findings_file, tmp_path / "report.md")
    saved = json.loads((tmp_path / "report.json").read_text())
    assert saved["generated_by"] == "llm"
    assert saved["owasp"]["p-1"].startswith("LLM01")
    assert "Generated without an LLM" not in md


def test_generate_report_defined_once():
    import inspect
    import agentguard.reporters as reporters
    assert inspect.getsource(reporters).count("def generate_report(") == 1
