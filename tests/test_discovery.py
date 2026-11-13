"""Deterministic discovery, plan validation and the agent's answer parsing. No LLM calls."""

import json
from pathlib import Path

import pytest

from agentguard.discovery import discover
from agentguard.discovery.agent import parse_decisions
from agentguard.discovery.candidates import AUTO, AMBIGUOUS
from agentguard.discovery.plan import InstrumentationPlan, PlanItem, apply_user_edits, build_plan

REPO = Path(__file__).resolve().parents[1]


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _roles(result, name=None):
    return {(c.role, c.name, c.bucket) for c in result.candidates if name is None or c.name == name}


def test_sample_with_decorators_is_found_as_entry_and_destructive_tool(tmp_path):
    _write(tmp_path, "app.py", (REPO / "samples/unsafe_tool/app.py").read_text().replace("@watch\n", "").replace("@expose\n", ""))
    result = discover(tmp_path)
    assert ("expose", "run", "auto") in _roles(result)
    transfer = next(c for c in result.candidates if c.name == "transfer_funds")
    assert transfer.role == "watch" and transfer.destructive and transfer.bucket == "auto"


def test_explicit_decorators_are_recognised(tmp_path):
    _write(tmp_path, "app.py", (REPO / "samples/unsafe_tool/app.py").read_text())
    result = discover(tmp_path)
    assert ("expose", "run", "auto") in _roles(result)
    assert any(c.name == "transfer_funds" and c.bucket == "auto" for c in result.candidates)


def test_rag_sample_retrieval_is_ambiguous_not_auto(tmp_path):
    _write(tmp_path, "app.py", (REPO / "samples/rag_leaky/app.py").read_text())
    result = discover(tmp_path)
    retrieval = [c for c in result.candidates if c.role == "watch_retrieval"]
    assert retrieval and all(c.bucket == "ambiguous" for c in retrieval)
    assert all(AMBIGUOUS <= c.confidence < AUTO for c in retrieval)


def test_skips_tests_envs_and_agentguard_itself(tmp_path):
    _write(tmp_path, "app.py", "def run(input_text):\n    return chat(input_text)\n")
    _write(tmp_path, "tests/test_x.py", "def run(input_text):\n    return chat(input_text)\n")
    _write(tmp_path, ".venv/lib/x.py", "def run(input_text):\n    return chat(input_text)\n")
    _write(tmp_path, "test_app.py", "def run(input_text):\n    return chat(input_text)\n")
    _write(tmp_path, "vendor/pyvenv.cfg", "")
    _write(tmp_path, "vendor/lib.py", "def run(input_text):\n    return chat(input_text)\n")
    _write(tmp_path, "clone/pyproject.toml", '[project]\nname = "agentguard"\n')
    _write(tmp_path, "clone/agentguard/x.py", "def run(input_text):\n    return chat(input_text)\n")
    _write(tmp_path, "ignored_dir/a.py", "def run(input_text):\n    return chat(input_text)\n")
    (tmp_path / ".gitignore").write_text("ignored_dir\n", encoding="utf-8")
    result = discover(tmp_path)
    files = {c.file for c in result.candidates}
    assert files == {"app.py"}


def test_syntax_errors_are_reported_not_fatal(tmp_path):
    _write(tmp_path, "broken.py", "def run(:\n")
    _write(tmp_path, "ok.py", "def run(input_text):\n    return chat(input_text)\n")
    result = discover(tmp_path)
    assert any(e["file"] == "broken.py" for e in result.errors)
    assert any(c.file == "ok.py" for c in result.candidates)


def test_candidate_ids_are_stable_and_cache_is_used(tmp_path):
    _write(tmp_path, "app.py", "def run(input_text):\n    return chat(input_text)\n")
    cache = tmp_path / "cache"
    first = discover(tmp_path, cache_dir=cache)
    second = discover(tmp_path, cache_dir=cache)
    assert [c.id for c in first.candidates] == [c.id for c in second.candidates]
    assert list(cache.glob("*.json")), "parse results should be cached by content hash"


def test_routes_are_not_entrypoints(tmp_path):
    _write(tmp_path, "api.py",
           "from fastapi import FastAPI\napp = FastAPI()\n\n@app.post('/chat')\n"
           "def chat_route(input_text: str):\n    return chat(input_text)\n")
    result = discover(tmp_path)
    assert not any(c.role == "expose" for c in result.candidates)


def test_build_plan_picks_one_entrypoint_and_defaults_sandbox_for_destructive(tmp_path):
    _write(tmp_path, "app.py", (REPO / "samples/unsafe_tool/app.py").read_text().replace("@expose\n", ""))
    result = discover(tmp_path)
    plan = build_plan(result)
    assert plan.validate(result) == []
    assert plan.entrypoint is not None and plan.entrypoint.name == "run"
    transfer = next(i for i in plan.items if i.name == "transfer_funds")
    assert transfer.sandbox is True


def test_plan_validation_rejects_unknown_and_mismatched_items(tmp_path):
    _write(tmp_path, "app.py", "def run(input_text):\n    return chat(input_text)\n")
    result = discover(tmp_path)
    plan = build_plan(result)
    good = plan.items[0]
    bogus = good.model_copy(update={"candidate_id": "c-deadbeef"})
    assert any("unknown candidate" in e for e in InstrumentationPlan(
        project_root=result.root, items=[bogus]).validate(result))
    wrong_line = good.model_copy(update={"line": good.line + 5})
    assert any("does not match" in e for e in InstrumentationPlan(
        project_root=result.root, items=[wrong_line]).validate(result))
    assert any("exactly one entrypoint" in e for e in InstrumentationPlan(
        project_root=result.root, items=[]).validate(result))


def test_user_edits_are_transactional(tmp_path):
    _write(tmp_path, "app.py", (REPO / "samples/unsafe_tool/app.py").read_text())
    result = discover(tmp_path)
    plan = build_plan(result)
    entry_id = plan.entrypoint.candidate_id
    with pytest.raises(ValueError):
        apply_user_edits(plan, [{"candidate_id": entry_id, "include": False}], result)
    assert plan.entrypoint is not None  # the original is untouched


def test_agent_answers_are_filtered_to_known_ids():
    known = {"c-aaaaaaaa"}
    text = json.dumps({"decisions": [
        {"candidate_id": "c-aaaaaaaa", "include": True, "sandbox": True, "reason": "tool"},
        {"candidate_id": "c-bbbbbbbb", "include": True, "reason": "invented"},
        {"candidate_id": "../../etc/passwd", "include": True, "reason": "bad"},
    ]})
    decisions = parse_decisions(f"Here you go:\n{text}\n", known)
    assert set(decisions) == {"c-aaaaaaaa"}
    assert decisions["c-aaaaaaaa"].sandbox is True


@pytest.mark.parametrize("answer", ["", "not json", "{}", '{"decisions": "nope"}', '{"decisions": [{"x": 1}]}'])
def test_malformed_agent_answers_are_ignored(answer):
    assert parse_decisions(answer, {"c-aaaaaaaa"}) == {}
