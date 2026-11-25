"""Review crew guardrails and fallbacks, the final report, costs and evals, without calling a model."""

from types import SimpleNamespace

from agentguard import evals
from agentguard.a2a.cards import attack_card, review_card
from agentguard.a2a.review_service import parse_handoff
from agentguard.costs import usd
from agentguard.review.crew import (RetestTool, assemble, code_draft, code_triage, draft_guardrail, lead_digest,
                                    triage_guardrail)
from agentguard.review.report import to_markdown
from agentguard.schemas import (AttackFinding, AttackReport, LeadPlan, Probe, QAReview, ReportDraft, ReportSection,
                                TriagedFinding, TriageResult)


def report() -> AttackReport:
    p = lambda m: Probe(entry_point="bank", session="s1", message=m, reply="ok")  # noqa: E731
    return AttackReport(findings=[
        AttackFinding(category="tool_misuse", title="Tool misuse", owasp="LLM06", status="confirmed",
                      detail="paid attacker", probes=[p("pay x"), p("pay y")], evidence=1, entry_point="bank"),
        AttackFinding(category="sql_injection", title="SQL injection", owasp="LLM05", status="suspected",
                      probes=[p("select *")]),
        AttackFinding(category="prompt_injection", title="Prompt injection", owasp="LLM01", status="resisted",
                      probes=[p("2+2")])])


def out(model):
    return SimpleNamespace(pydantic=model)


def tf(cat, status, sev, rank, ev=()):
    return TriagedFinding(category=cat, title=cat, status=status, severity=sev, rank=rank, rationale="r", evidence=list(ev))


def test_triage_guardrail_keeps_oracle_verdicts_and_real_evidence():
    check = triage_guardrail(report())
    good = TriageResult(overall_risk="high", findings=[tf("tool_misuse", "confirmed", "high", 1, ["tool_misuse#2"]),
                                                       tf("sql_injection", "suspected", "medium", 2),
                                                       tf("prompt_injection", "resisted", "info", 3)])
    assert check(out(good))[0]
    bad = good.model_copy(deep=True)
    bad.findings[1].status = "confirmed"          # upgraded by the model: rejected
    bad.findings[0].evidence = ["tool_misuse#9"]  # invented probe id: rejected
    ok, msg = check(out(bad))
    assert not ok and "oracle" in msg and "do not exist" in msg
    missing = TriageResult(overall_risk="high", findings=good.findings[:1])
    assert "missing" in check(out(missing))[1]


def test_draft_guardrail_needs_a_cited_section_for_every_confirmed_finding():
    check = draft_guardrail(report())
    assert not check(out(ReportDraft(title="t", executive_summary="s", sections=[])))[0]
    ok = ReportDraft(title="t", executive_summary="s",
                     sections=[ReportSection(category="tool_misuse", what_happened="w", impact="i", evidence=["tool_misuse#2"])])
    assert check(out(ok))[0]


def test_retest_tool_only_for_suspected_and_upgrades_on_oracle_confirmation():
    r = report()
    new = AttackFinding(category="sql_injection", title="SQL", owasp="LLM05", status="confirmed", detail="ran DROP",
                        probes=[Probe(entry_point="db", session="s1", message="drop", reply="done")], evidence=0,
                        oracle="sql_injection", entry_point="db")
    tool = RetestTool(retest=lambda c, h: new, report=r)
    assert "only suspected" in tool._run("tool_misuse", "x")
    tool._run("sql_injection", "try DROP")
    f = {x.category: x for x in r.findings}["sql_injection"]
    assert f.status == "confirmed" and len(f.probes) == 2 and f.evidence == 1
    assert tool.log[0].status_before == "suspected" and tool.log[0].status_after == "confirmed"
    assert "only suspected" in tool._run("sql_injection", "again")


def test_code_fallbacks_and_report():
    r = report()
    t, d = code_triage(r), code_draft(r)
    assert t.findings[0].category == "tool_misuse" and t.overall_risk == "high"
    assert triage_guardrail(r)(out(t))[0] and draft_guardrail(r)(out(d))[0]
    final = assemble(r, LeadPlan(), t, d, QAReview(approved=True), 0)
    assert final.findings[0].evidence == ["tool_misuse#2"] and any(e.oracle for e in final.evidence)
    md = to_markdown(final)
    assert "| 1 | Tool misuse |" in md and "tool_misuse#2" in md
    assert "pay x" not in lead_digest(r)  # the Lead never sees raw payloads


def test_costs_cards_handoff_and_eval():
    assert usd("anthropic/claude-sonnet-5-5", 1_000_000, 100_000) == 3.0
    assert usd("groq/openai/gpt-oss-120b", 0, 0) == 0 and usd("unknown/model", 10, 10) == 0
    assert {s.id for s in attack_card().skills} >= {"attack", "retest", "tool_misuse", "indirect_injection"}
    assert review_card().skills[0].id == "security_review"
    info, rep = parse_handoff('x <<RUN>>{"run_dir": "/r"}<<END_RUN>> <<ATTACK_REPORT>>' + report().model_dump_json() + "<<END>>")
    assert info["run_dir"] == "/r" and len(rep.findings) == 3
    spec = {"dataset": "t", "expected": {"tool_misuse": "confirmed", "sql_injection": "confirmed", "prompt_injection": "resisted"}}
    res = evals.score_against(spec, report())
    assert res["detection_rate"] == 0.5 and res["false_alarms"] == 0


def test_draft_guardrail_accepts_titles_as_category_names():
    check = draft_guardrail(report())
    d = ReportDraft(title="t", executive_summary="s", sections=[
        ReportSection(category="Tool misuse (LLM06 Excessive Agency)", what_happened="w", impact="i", evidence=["tool_misuse#1"])])
    ok, res = check(out(d))
    assert ok and res.pydantic.sections[0].category == "tool_misuse"
