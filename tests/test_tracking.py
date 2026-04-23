import json

from fastapi.testclient import TestClient
import yaml

from rampart.app.main import app
from rampart.app.models import EvaluationResponse, Violation
from rampart.app.tracking import ClientContext, load_evaluation_events, summarize_customers, summarize_policies, write_evaluation_event


def test_write_event_and_summarize_by_customer(tmp_path):
    log_path = tmp_path / "evaluations.jsonl"
    response = EvaluationResponse(
        decision="fail",
        violations=[
            Violation(policy_id="No-PII-Data", severity="high", category="pii_phi", message="PII detected."),
            Violation(policy_id="Tool-Allowlist", severity="medium", category="tool_policy", message="Tool denied."),
        ],
    )
    config = _tracking_config(str(log_path))

    write_evaluation_event(
        config,
        ClientContext(customer="Acme", client_id="support-console", owner="ops@example.com", request_id="req-1"),
        response,
        ["No-PII-Data", "Tool-Allowlist"],
    )

    events = load_evaluation_events(str(log_path))
    customer_summary = summarize_customers(events)
    policy_summary = summarize_policies(events, customer="Acme", client_id="support-console")

    assert customer_summary[0].customer == "Acme"
    assert customer_summary[0].client_id == "support-console"
    assert customer_summary[0].failed_requests == 1
    assert customer_summary[0].violation_count == 2
    assert customer_summary[0].high_critical_count == 1
    assert {item.policy_id for item in policy_summary} == {"No-PII-Data", "Tool-Allowlist"}


def test_tracking_does_not_log_accepted_by_default(tmp_path):
    log_path = tmp_path / "evaluations.jsonl"
    response = EvaluationResponse(decision="accept", violations=[])

    write_evaluation_event(
        _tracking_config(str(log_path)),
        ClientContext(customer="Acme", client_id="clean-app"),
        response,
        ["No-PII-Data"],
    )

    assert not log_path.exists()


def test_evaluate_endpoint_writes_customer_client_event(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.yaml"
    log_path = tmp_path / "evaluations.jsonl"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "llm_evaluator": {"enabled": False},
                "tracking": {"enabled": True, "log_path": str(log_path), "log_accepted_requests": False},
                "policies": [
                    {
                        "id": "No-PII-Data",
                        "enabled": True,
                        "severity": "high",
                        "category": "pii_phi",
                        "description": "Block PII.",
                        "action": "block",
                        "checks": [{"type": "regex", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"}],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))

    client = TestClient(app)
    response = client.post(
        "/v1/rampart/evaluate",
        headers={
            "X-RAMPART-Customer": "Acme",
            "X-RAMPART-Client-Id": "support-console",
            "X-RAMPART-Owner": "ops@example.com",
            "X-Request-ID": "req-123",
        },
        json={
            "request": {
                "model": "gpt-4.1",
                "messages": [{"role": "user", "content": "Find user for SSN 123-45-6789"}],
            }
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "fail"
    event = json.loads(log_path.read_text(encoding="utf-8"))
    assert event["customer"] == "Acme"
    assert event["client_id"] == "support-console"
    assert event["owner"] == "ops@example.com"
    assert event["request_id"] == "req-123"
    assert event["violations"][0]["policy_id"] == "No-PII-Data"
    assert "sanitized_request" not in event


def _tracking_config(log_path):
    from rampart.app.config import TrackingConfig

    return TrackingConfig(enabled=True, log_path=log_path, log_accepted_requests=False)
