"""The import hook applies wrappers without editing the user's file."""

import sys
import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard import adapter
from agentguard.discovery import discover
from agentguard.discovery.plan import build_plan
from agentguard.instrument.hook import install
from agentguard.instrument.target import write_target


APP = textwrap.dedent('''
    LEDGER = {"checking": 5000.0}

    def tool(fn):  # stand-in decorator; discovery recognises the name "tool"
        return fn

    def chat(messages):  # stand-in LLM client; discovery recognises the name "chat"
        return "ok"

    @tool
    def transfer_funds(to, amount):
        LEDGER["checking"] -= amount
        return f"Transferred {amount} to {to}"

    def run(input_text):
        chat([input_text])
        return transfer_funds("bob", 5.0)
''')


@pytest.fixture
def bare_project(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(APP, encoding="utf-8")
    monkeypatch.setenv("AGENTGUARD_LLM_MOCK", "1")
    monkeypatch.delitem(sys.modules, "app", raising=False)
    monkeypatch.delitem(sys.modules, "agentguard_target", raising=False)
    yield project
    for name in ("app", "agentguard_target"):
        sys.modules.pop(name, None)
    sys.meta_path[:] = [f for f in sys.meta_path if type(f).__name__ != "PlanHook"]
    adapter._entrypoint = None


def _generate(project: Path, run_dir: Path, sandbox_transfer: bool = True):
    result = discover(project)
    plan = build_plan(result)
    if not sandbox_transfer:
        for item in plan.items:
            if item.name == "transfer_funds":
                item.sandbox = False
    plan.save(run_dir / "plan.json")
    write_target(run_dir, plan, project)
    return plan


def test_hook_does_not_touch_the_source_file(bare_project, tmp_path):
    before = (bare_project / "app.py").read_text()
    run_dir = tmp_path / "run"
    _generate(bare_project, run_dir)
    sys.path[:0] = [str(run_dir), str(bare_project)]
    install(run_dir / "plan.json", bare_project)
    import app  # noqa: F401 - loaded through the hook
    assert (bare_project / "app.py").read_text() == before
    assert "@watch" not in before


def test_sandboxed_tool_is_recorded_but_not_executed(bare_project, tmp_path):
    run_dir = tmp_path / "run"
    _generate(bare_project, run_dir, sandbox_transfer=True)
    sys.path[:0] = [str(run_dir), str(bare_project)]
    install(run_dir / "plan.json", bare_project)
    import agentguard_target  # noqa: F401
    import app as user_app

    client = TestClient(adapter.app)
    body = client.post("/invoke", json={"input_text": "transfer 5 to bob"}).json()
    assert [c["name"] for c in body["tool_calls"]] == ["transfer_funds"]
    assert body["tool_calls"][0]["sandboxed"] is True
    assert user_app.LEDGER["checking"] == 5000.0  # not executed


def test_live_tool_executes_and_is_recorded(bare_project, tmp_path):
    run_dir = tmp_path / "run"
    _generate(bare_project, run_dir, sandbox_transfer=False)
    sys.path[:0] = [str(run_dir), str(bare_project)]
    install(run_dir / "plan.json", bare_project)
    import agentguard_target  # noqa: F401
    import app as user_app

    client = TestClient(adapter.app)
    body = client.post("/invoke", json={"input_text": "transfer 5 to bob"}).json()
    assert body["tool_calls"][0]["sandboxed"] is False
    assert user_app.LEDGER["checking"] == 4995.0


def test_only_planned_lines_are_wrapped(tmp_path):
    from agentguard.instrument.hook import PlanLoader, _apply
    import ast
    from agentguard.discovery.plan import PlanItem

    source = textwrap.dedent('''
        def helper(x):
            return x

        def transfer(to):
            return to
    ''')
    tree = ast.parse(source)
    item = PlanItem(candidate_id="c-00000000", role="watch", file="m.py", module="m",
                    qualname="transfer", name="transfer", line=5, confidence=0.9, sandbox=True)
    assert _apply(tree, [item]) == 1
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert funcs["helper"].decorator_list == []
    assert len(funcs["transfer"].decorator_list) == 1


def test_wrapper_factory_rejects_unknown_roles():
    from agentguard.instrument.wrappers import wrap
    with pytest.raises(ValueError):
        wrap("unknown")


def test_retrieval_observations_are_returned_in_invoke(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_LLM_MOCK", "1")
    from agentguard.instrument.wrappers import wrap

    def search_docs(q):
        return f"doc for {q}"

    search_docs = wrap("retrieval")(search_docs)

    @adapter.expose
    def handler(input_text):
        return search_docs(input_text)

    client = TestClient(adapter.app)
    body = client.post("/invoke", json={"input_text": "refunds"}).json()
    assert body["output"] == "doc for refunds"
    assert body["observations"]["retrieval"][0]["name"] == "search_docs"
    adapter._entrypoint = None
