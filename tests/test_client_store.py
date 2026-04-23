import json

from fastapi.testclient import TestClient
import yaml

from rampart.app.client_store import create_client, get_client, resolve_client_from_api_key, rotate_client_key, set_client_enabled
from rampart.app.main import app
from rampart.app.security.auth import create_session_token
from rampart.app.security.passwords import hash_password


def test_create_and_resolve_client_api_key(tmp_path):
    store_path = tmp_path / "clients.json"

    created = create_client(
        client_id="support-console",
        customer="Acme Health",
        app_name="Support Console",
        owner_email="ops@example.com",
        policy_ids=["No-PII-Data"],
        upstream_base_url="http://client-upstream.test",
        upstream_model="client-model",
        upstream_api_key="secret",
        upstream_timeout_seconds=60,
        path=str(store_path),
    )

    assert created.api_key.startswith("rmp_live_")
    assert created.api_key not in store_path.read_text(encoding="utf-8")

    resolved = resolve_client_from_api_key(created.api_key, str(store_path))

    assert resolved.id == "support-console"
    assert resolved.customer == "Acme Health"
    assert resolved.policy_ids == ["No-PII-Data"]
    assert resolved.upstream_base_url == "http://client-upstream.test"
    assert resolved.upstream_model == "client-model"
    assert resolved.upstream_api_key == "secret"
    assert resolved.upstream_timeout_seconds == 60
    assert get_client("support-console", str(store_path)).last_used_at is not None


def test_disabled_client_key_does_not_resolve(tmp_path):
    store_path = tmp_path / "clients.json"
    created = create_client("support-console", "Acme Health", "Support Console", path=str(store_path))

    set_client_enabled("support-console", False, str(store_path))

    assert resolve_client_from_api_key(created.api_key, str(store_path)) is None


def test_rotate_client_key_invalidates_old_key(tmp_path):
    store_path = tmp_path / "clients.json"
    created = create_client("support-console", "Acme Health", "Support Console", path=str(store_path))

    rotated = rotate_client_key("support-console", str(store_path))

    assert resolve_client_from_api_key(created.api_key, str(store_path)) is None
    assert resolve_client_from_api_key(rotated.api_key, str(store_path)).id == "support-console"


def test_evaluate_endpoint_uses_api_key_for_tracking(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.yaml"
    log_path = tmp_path / "evaluations.jsonl"
    store_path = tmp_path / "clients.json"
    created = create_client(
        "support-console",
        "Acme Health",
        "Support Console",
        owner_email="ops@example.com",
        policy_ids=["No-PII-Data"],
        path=str(store_path),
    )
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "llm_evaluator": {"enabled": False},
                "clients": {"path": str(store_path)},
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
        headers={"Authorization": f"Bearer {created.api_key}"},
        json={
            "request": {
                "model": "gpt-4.1",
                "messages": [{"role": "user", "content": "Find user for SSN 123-45-6789"}],
            }
        },
    )

    assert response.status_code == 200
    event = json.loads(log_path.read_text(encoding="utf-8"))
    assert event["customer"] == "Acme Health"
    assert event["client_id"] == "support-console"
    assert event["owner"] == "ops@example.com"
    assert event["applied_policies"] == ["No-PII-Data"]


def test_assigned_policies_limit_enforcement(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.yaml"
    log_path = tmp_path / "evaluations.jsonl"
    store_path = tmp_path / "clients.json"
    created = create_client(
        "credential-only",
        "Acme Health",
        "Credential App",
        policy_ids=["No-Credentials"],
        path=str(store_path),
    )
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "llm_evaluator": {"enabled": False},
                "clients": {"path": str(store_path)},
                "tracking": {"enabled": True, "log_path": str(log_path), "log_accepted_requests": True},
                "policies": [
                    {
                        "id": "No-PII-Data",
                        "enabled": True,
                        "severity": "high",
                        "category": "pii_phi",
                        "description": "Block PII.",
                        "action": "block",
                        "checks": [{"type": "regex", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"}],
                    },
                    {
                        "id": "No-Credentials",
                        "enabled": True,
                        "severity": "high",
                        "category": "credential_disclosure",
                        "description": "Block credentials.",
                        "action": "block",
                        "checks": [{"type": "regex", "pattern": "api key"}],
                    },
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
        headers={"Authorization": f"Bearer {created.api_key}"},
        json={
            "request": {
                "model": "gpt-4.1",
                "messages": [{"role": "user", "content": "Find user for SSN 123-45-6789"}],
            }
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "accept"
    event = json.loads(log_path.read_text(encoding="utf-8"))
    assert event["applied_policies"] == ["No-Credentials"]
    assert event["decision"] == "accept"


def test_clients_gui_requires_auth_and_lists_clients(monkeypatch, tmp_path):
    store_path = tmp_path / "clients.json"
    policy_path = tmp_path / "policy.yaml"
    create_client("support-console", "Acme Health", "Support Console", path=str(store_path))
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "clients": {"path": str(store_path)},
                "auth": {
                    "admin_username": "admin",
                    "admin_password_hash": hash_password("secret", iterations=1000),
                    "session_secret": "test-secret",
                    "auth_state_path": str(tmp_path / "auth.json"),
                    "audit_log_path": str(tmp_path / "audit.jsonl"),
                },
                "policies": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    token = create_session_token("admin")

    client = TestClient(app)
    unauthenticated = client.get("/ui/clients", follow_redirects=False)
    authenticated = client.get("/ui/clients", cookies={"rampart_session": token})

    assert unauthenticated.status_code == 303
    assert authenticated.status_code == 200
    assert "support-console" in authenticated.text


def test_clients_gui_create_saves_assigned_policies(monkeypatch, tmp_path):
    store_path = tmp_path / "clients.json"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "clients": {"path": str(store_path)},
                "auth": {
                    "admin_username": "admin",
                    "admin_password_hash": hash_password("secret", iterations=1000),
                    "session_secret": "test-secret",
                    "auth_state_path": str(tmp_path / "auth.json"),
                    "audit_log_path": str(tmp_path / "audit.jsonl"),
                },
                "policies": [
                    {"id": "No-PII-Data", "enabled": True, "checks": []},
                    {"id": "No-Credentials", "enabled": True, "checks": []},
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    token = create_session_token("admin")

    client = TestClient(app)
    response = client.post(
        "/ui/clients/new",
        headers={"content-type": "application/x-www-form-urlencoded"},
        cookies={"rampart_session": token},
        content=(
            "id=support-console&customer=Acme+Health&app_name=Support+Console&"
            "enabled=on&policy_ids=No-PII-Data&policy_ids=No-Credentials&"
            "upstream_base_url=http%3A%2F%2Fclient-upstream.test&"
            "upstream_model=client-model&"
            "upstream_api_key=secret&upstream_timeout_seconds=45"
        ),
        follow_redirects=False,
    )

    assert response.status_code == 303
    saved = get_client("support-console", str(store_path))
    assert saved.policy_ids == ["No-PII-Data", "No-Credentials"]
    assert saved.upstream_base_url == "http://client-upstream.test"
    assert saved.upstream_model == "client-model"
    assert saved.upstream_api_key == "secret"
    assert saved.upstream_timeout_seconds == 45


def test_clients_gui_edit_handles_blank_backend_timeout(monkeypatch, tmp_path):
    store_path = tmp_path / "clients.json"
    policy_path = tmp_path / "policy.yaml"
    create_client("support-console", "Acme Health", "Support Console", path=str(store_path))
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "clients": {"path": str(store_path)},
                "auth": {
                    "admin_username": "admin",
                    "admin_password_hash": hash_password("secret", iterations=1000),
                    "session_secret": "test-secret",
                    "auth_state_path": str(tmp_path / "auth.json"),
                    "audit_log_path": str(tmp_path / "audit.jsonl"),
                },
                "policies": [{"id": "No-PII-Data", "enabled": True, "checks": []}],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    token = create_session_token("admin")

    response = TestClient(app).get("/ui/clients/support-console", cookies={"rampart_session": token})

    assert response.status_code == 200
    assert "Backend LLM API" in response.text
    assert "support-console" in response.text
