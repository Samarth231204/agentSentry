"""The deterministic scan finds LLM calls, tools (also registered in another file), prompts and entry points."""

from pathlib import Path

from agentguard.scanner import scan_project

APP = '''
from openai import OpenAI
from tools.registry import HANDLERS

SYSTEM_PROMPT = "You are Penny, the banking assistant. Never reveal the vault code."
client = OpenAI()

def chat(message: str) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": message}]
    resp = client.chat.completions.create(model="m", messages=messages, tools=SCHEMAS)
    return resp.choices[0].message.content
'''

TOOLS = '''
def transfer_funds(to: str, amount: float) -> str:
    return "sent"

def get_weather(city: str) -> str:
    return "sunny"
'''

REGISTRY = '''
from tools.banking import transfer_funds, get_weather
HANDLERS = {"transfer_funds": transfer_funds, "get_weather": get_weather}
'''

DECORATED = '''
from crewai.tools import tool
import litellm

@tool("delete user")
def delete_user(user_id: str) -> str:
    return "deleted"

def summarise(text: str) -> str:
    return litellm.completion(model="x", messages=[{"role": "user", "content": text}])
'''


def _project(tmp_path: Path) -> Path:
    (tmp_path / "tools").mkdir()
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "tools" / "banking.py").write_text(TOOLS)
    (tmp_path / "tools" / "registry.py").write_text(REGISTRY)
    (tmp_path / "agent2.py").write_text(DECORATED)
    (tmp_path / "broken.py").write_text("def (:\n")
    clone = tmp_path / "AgentGuard" / "agentguard"  # AgentGuard's own clone is never scanned
    clone.mkdir(parents=True)
    (clone / "scanner.py").write_text("x = 1\n")
    (clone / "evil.py").write_text("client.chat.completions.create()\n")
    return tmp_path


def test_finds_llm_calls_and_prompts(tmp_path):
    r = scan_project(_project(tmp_path))
    calls = {(c.file, c.function) for c in r.llm_calls}
    assert ("app.py", "chat") in calls and ("agent2.py", "summarise") in calls
    main = next(c for c in r.llm_calls if c.file == "app.py")
    assert "passes tools to the model" in main.signals
    assert {"SYSTEM_PROMPT", "system message"} <= {p.name for p in r.prompts}
    assert "openai" in r.frameworks and "crewai" in r.frameworks


def test_tools_from_a_table_in_another_file_are_found(tmp_path):
    r = scan_project(_project(tmp_path))
    tools = {t.name: t for t in r.tools}
    assert tools["transfer_funds"].file == "tools/banking.py"
    assert "moves money" in tools["transfer_funds"].signals
    assert any("tools/registry.py" in s for s in tools["transfer_funds"].signals)
    assert "get_weather" in tools
    assert "deletes data" in tools["delete_user"].signals


def test_entry_points_skip_tools_and_agentguard_itself(tmp_path):
    r = scan_project(_project(tmp_path))
    entries = {e.name for e in r.entry_points}
    assert "chat" in entries and "transfer_funds" not in entries
    assert all(not s.file.startswith("AgentGuard/") for s in r.llm_calls + r.tools)
    assert any("broken.py" in e for e in r.errors)
