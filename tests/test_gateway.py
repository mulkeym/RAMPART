import json

from fastapi.testclient import TestClient
import httpx
import yaml

from rampart.app.client_store import create_client
from rampart.app.main import app


def test_chat_completions_blocks_with_openai_error(monkeypatch, tmp_path):
    policy_path = _write_policy(
        tmp_path,
        policies=[
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
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))

    response = TestClient(app).post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4.1",
            "messages": [{"role": "user", "content": "SSN 123-45-6789"}],
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["type"] == "policy_violation"
    assert body["error"]["violations"][0]["policy_id"] == "No-PII-Data"


def test_chat_completions_accepts_and_proxies(monkeypatch, tmp_path):
    captured = {}

    async def fake_post(self, url, json, headers):
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(
            200,
            json={"id": "chatcmpl-test", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    policy_path = _write_policy(
        tmp_path,
        policies=[
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
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))

    payload = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "hello"}]}
    response = TestClient(app).post("/v1/chat/completions", json=payload)

    assert response.status_code == 200
    assert response.json()["id"] == "chatcmpl-test"
    assert captured["url"] == "http://upstream.test/chat/completions"
    assert captured["json"] == payload


def test_warn_violation_forwards_sanitized_request(monkeypatch, tmp_path):
    captured = {}

    async def fake_post(self, url, json, headers):
        captured["json"] = json
        return httpx.Response(
            200,
            json={"id": "chatcmpl-test", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    policy_path = _write_policy(
        tmp_path,
        policies=[
            {
                "id": "Warn-PII",
                "enabled": True,
                "severity": "high",
                "category": "pii_phi",
                "description": "Warn on PII.",
                "action": "warn",
                "checks": [{"type": "regex", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"}],
            }
        ],
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))

    response = TestClient(app).post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4.1",
            "messages": [{"role": "user", "content": "SSN 123-45-6789"}],
        },
    )

    assert response.status_code == 200
    assert captured["json"]["messages"][0]["content"] == "SSN [REDACTED]"


def test_chat_completions_uses_client_specific_upstream(monkeypatch, tmp_path):
    captured = {}

    async def fake_post(self, url, json, headers):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return httpx.Response(
            200,
            json={"id": "chatcmpl-client", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    store_path = tmp_path / "clients.json"
    created = create_client(
        "support-console",
        "Acme Health",
        "Support Console",
        upstream_base_url="http://client-upstream.test/v1",
        upstream_model="client-model",
        upstream_api_key="client-secret",
        upstream_timeout_seconds=30,
        path=str(store_path),
    )
    policy_path = _write_policy(
        tmp_path,
        policies=[
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
        clients_path=str(store_path),
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))

    response = TestClient(app).post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {created.api_key}"},
        json={"model": "gpt-4.1", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 200
    assert captured["url"] == "http://client-upstream.test/v1/chat/completions"
    assert captured["headers"]["authorization"] == "Bearer client-secret"
    assert captured["json"]["model"] == "client-model"


def _write_policy(tmp_path, policies, clients_path=None):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "llm_evaluator": {"enabled": False},
                "tracking": {"enabled": True, "log_path": str(tmp_path / "events.jsonl"), "log_accepted_requests": True},
                "clients": {"path": str(clients_path or tmp_path / "clients.json")},
                "upstream": {"enabled": True, "base_url": "http://upstream.test", "timeout_seconds": 10},
                "policies": policies,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return policy_path
