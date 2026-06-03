import json
import pytest
from rampart.app.dashboard import aggregate_dashboard_data


@pytest.fixture
def events_file(tmp_path):
    path = tmp_path / "events.jsonl"
    events = [
        {"timestamp": "2026-06-03T10:00:00+00:00", "client_id": "ask-sage", "user": "alice@test.com", "decision": "accept", "applied_policies": ["no-pii"], "violations": [], "model": "gpt-4", "eval_ms": 30},
        {"timestamp": "2026-06-03T10:05:00+00:00", "client_id": "ask-sage", "user": "bob@test.com", "decision": "fail", "applied_policies": ["no-pii", "no-creds"], "violations": [{"policy_id": "no-pii", "severity": "high", "category": "pii", "source": "deterministic"}], "model": "gpt-4", "eval_ms": 5},
        {"timestamp": "2026-06-03T11:00:00+00:00", "client_id": "internal", "user": "alice@test.com", "decision": "fail", "applied_policies": ["harmful-content"], "violations": [{"policy_id": "harmful-content", "severity": "high", "category": "harmful", "source": "llm"}], "model": "gpt-3.5", "eval_ms": 150},
        {"timestamp": "2026-06-03T11:30:00+00:00", "client_id": "ask-sage", "user": None, "decision": "accept", "applied_policies": ["no-pii"], "violations": [], "model": "gpt-4", "eval_ms": 25},
    ]
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return str(path)


def test_aggregate_stats(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    assert data["stats"]["total_requests"] == 4
    assert data["stats"]["total_violations"] == 2
    assert data["stats"]["active_users"] >= 2


def test_aggregate_policy_hits(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    hits = {h["policy_id"]: h["count"] for h in data["policy_hits"]}
    assert hits["no-pii"] == 1
    assert hits["harmful-content"] == 1


def test_aggregate_model_usage(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    assert data["model_usage"]["gpt-4"] == 3
    assert data["model_usage"]["gpt-3.5"] == 1


def test_aggregate_eval_sources(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    assert data["eval_sources"]["deterministic"] == 1
    assert data["eval_sources"]["llm"] == 1


def test_aggregate_top_users(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    top = {u["user"]: u["count"] for u in data["top_users"]}
    assert top["alice@test.com"] == 2


def test_aggregate_empty_file(tmp_path):
    path = str(tmp_path / "empty.jsonl")
    data = aggregate_dashboard_data(path, range_hours=24)
    assert data["stats"]["total_requests"] == 0
