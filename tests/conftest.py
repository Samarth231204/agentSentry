"""Shared test setup."""

import pytest


@pytest.fixture(autouse=True)
def _no_dashboard_token(monkeypatch):
    """The developer's .env may hold a real dashboard login token; tests set their own when they need one."""
    monkeypatch.delenv("AGENTGUARD_DASHBOARD_TOKEN", raising=False)
