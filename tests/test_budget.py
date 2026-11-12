"""Tests for agentguard.budget."""

import pytest
from agentguard.budget import BudgetConfig, BudgetExceededError, BudgetTracker


def test_budget_max_calls_total():
    tracker = BudgetTracker(BudgetConfig(max_calls_total=2))
    tracker.record("attacker", prompt_tokens=10, completion_tokens=5)
    tracker.record("judge", prompt_tokens=10, completion_tokens=5)
    with pytest.raises(BudgetExceededError, match="max_calls_total=2 exceeded"):
        tracker.record("attacker", prompt_tokens=5, completion_tokens=5)


def test_budget_max_tokens_total():
    tracker = BudgetTracker(BudgetConfig(max_tokens_total=100))
    tracker.record("attacker", prompt_tokens=40, completion_tokens=20)  # total: 60
    tracker.record("judge", prompt_tokens=20, completion_tokens=10)   # total: 90
    with pytest.raises(BudgetExceededError, match="max_tokens_total=100 exceeded"):
        tracker.record("attacker", prompt_tokens=10, completion_tokens=10)  # would be 110


def test_budget_max_calls_per_role():
    tracker = BudgetTracker(BudgetConfig(max_calls_per_role={"attacker": 1}))
    tracker.record("attacker", prompt_tokens=10, completion_tokens=5)

    # Calling judge alongside should not raise
    tracker.record("judge", prompt_tokens=10, completion_tokens=5)
    tracker.record("judge", prompt_tokens=10, completion_tokens=5)

    # Second attacker call must raise
    with pytest.raises(BudgetExceededError, match=r"max_calls_per_role\[attacker\]=1 exceeded"):
        tracker.record("attacker", prompt_tokens=5, completion_tokens=5)


def test_budget_usage_report():
    tracker = BudgetTracker()
    tracker.record("attacker", prompt_tokens=10, completion_tokens=5)
    tracker.record("attacker", prompt_tokens=15, completion_tokens=10)
    tracker.record("judge", prompt_tokens=20, completion_tokens=30)

    report = tracker.usage_report()
    assert report["total"]["calls"] == 3
    assert report["total"]["prompt_tokens"] == 45
    assert report["total"]["completion_tokens"] == 45

    assert report["by_role"]["attacker"]["calls"] == 2
    assert report["by_role"]["attacker"]["prompt_tokens"] == 25
    assert report["by_role"]["attacker"]["completion_tokens"] == 15

    assert report["by_role"]["judge"]["calls"] == 1
    assert report["by_role"]["judge"]["prompt_tokens"] == 20
    assert report["by_role"]["judge"]["completion_tokens"] == 30


def test_budget_no_ceiling_never_raises():
    tracker = BudgetTracker(BudgetConfig())
    for _ in range(100):
        tracker.record("attacker", prompt_tokens=50, completion_tokens=50)
    report = tracker.usage_report()
    assert report["total"]["calls"] == 100


def test_budget_emits_usage_and_exceeded_events():
    from agentguard.events import get_event_bus, reset_event_bus

    reset_event_bus()
    captured = []
    get_event_bus().subscribe(captured.append)
    tracker = BudgetTracker(BudgetConfig(max_calls_total=1))
    assert not tracker.exhausted
    tracker.record("judge", prompt_tokens=7, completion_tokens=3)
    with pytest.raises(BudgetExceededError):
        tracker.record("judge", prompt_tokens=1, completion_tokens=1)
    assert tracker.exhausted
    types = [e.event_type for e in captured]
    assert types == ["llm_usage", "budget_exceeded"]
    assert captured[0].payload["total_tokens"] == 10
    # A rejected call is not charged.
    assert tracker.usage_report()["total"]["calls"] == 1
