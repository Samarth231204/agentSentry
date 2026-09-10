"""Dummy target app for Phase 1 adapter validation.

Run with: uvicorn tests.dummy_app:app --host 127.0.0.1 --port 8000
"""

from agentguard import expose, watch


@watch
def lookup_balance(account: str) -> float:
    if account == "boom":
        raise RuntimeError("account service unavailable")
    return 1234.56


@expose
def run(input_text: str, session_id: str = None) -> str:
    balance = lookup_balance(input_text)
    return f"session={session_id} balance={balance} for '{input_text}'"


from agentguard.adapter import app  # noqa: E402  (re-exported for uvicorn)
