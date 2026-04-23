import json

from fastapi.testclient import TestClient

from rampart.app.config import AuthConfig
from rampart.app.main import app
from rampart.app.security.auth import authenticate, create_session_token
from rampart.app.security.audit import audit_event
from rampart.app.security.credentials import INITIAL_PASSWORD, change_password, get_credential_state, password_change_required
from rampart.app.security.passwords import hash_password, verify_password


def test_password_hash_roundtrip():
    encoded = hash_password("correct horse battery staple", iterations=1000)

    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)


def test_authenticate_uses_configured_admin_hash():
    auth_config = AuthConfig(
        admin_username="admin",
        admin_password_hash=hash_password("secret", iterations=1000),
        session_secret="test-secret",
    )

    assert authenticate("admin", "secret", auth_config)
    assert not authenticate("admin", "bad", auth_config)
    assert not authenticate("other", "secret", auth_config)


def test_session_token_roundtrip(monkeypatch):
    auth_config = AuthConfig(
        admin_username="admin",
        admin_password_hash=hash_password("secret", iterations=1000),
        session_secret="test-secret",
    )
    token = create_session_token("admin", auth_config)

    monkeypatch.setenv("RAMPART_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RAMPART_ADMIN_PASSWORD_HASH", auth_config.admin_password_hash)
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")

    client = TestClient(app)
    response = client.get("/ui/policies", cookies={"rampart_session": token})

    assert response.status_code == 200
    assert "Policies" in response.text


def test_policy_ui_requires_login(monkeypatch, tmp_path):
    monkeypatch.setenv("RAMPART_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RAMPART_ADMIN_PASSWORD_HASH", hash_password("secret", iterations=1000))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("RAMPART_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    client = TestClient(app)
    response = client.get("/ui/policies", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/ui/policies"


def test_login_success_sets_cookie_and_writes_audit(monkeypatch, tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("RAMPART_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RAMPART_ADMIN_PASSWORD_HASH", hash_password("secret", iterations=1000))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("RAMPART_AUDIT_LOG", str(audit_path))

    client = TestClient(app)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "secret", "next": "/ui/policies"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/ui/policies"
    assert "rampart_session" in response.headers["set-cookie"]

    audit_record = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    assert audit_record["action"] == "auth.login"
    assert audit_record["actor"] == "admin"
    assert audit_record["result"] == "success"


def test_audit_event_writes_jsonl(monkeypatch, tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("RAMPART_AUDIT_LOG", str(audit_path))

    audit_event(None, "policy.update", actor="admin", target="No-PII-Data", result="success")

    event = json.loads(audit_path.read_text(encoding="utf-8"))
    assert event["action"] == "policy.update"
    assert event["actor"] == "admin"
    assert event["target"] == "No-PII-Data"


def test_local_credentials_seed_initial_password_and_require_change(tmp_path):
    auth_config = AuthConfig(auth_state_path=str(tmp_path / "auth.json"), session_secret="test-secret")

    state = get_credential_state(auth_config)

    assert state.username == "admin"
    assert authenticate("admin", INITIAL_PASSWORD, auth_config)
    assert password_change_required("admin", auth_config)


def test_local_password_change_clears_required_flag(tmp_path):
    auth_config = AuthConfig(auth_state_path=str(tmp_path / "auth.json"), session_secret="test-secret")

    error = change_password("admin", INITIAL_PASSWORD, "new-password-123", auth_config)

    assert error is None
    assert not authenticate("admin", INITIAL_PASSWORD, auth_config)
    assert authenticate("admin", "new-password-123", auth_config)
    assert not password_change_required("admin", auth_config)


def test_first_login_redirects_to_change_password(monkeypatch, tmp_path):
    monkeypatch.delenv("RAMPART_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("RAMPART_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RAMPART_AUTH_STATE", str(tmp_path / "auth.json"))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("RAMPART_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    client = TestClient(app)
    response = client.post(
        "/login",
        data={"username": "admin", "password": INITIAL_PASSWORD, "next": "/ui/policies"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/change-password"
    assert "rampart_session" in response.headers["set-cookie"]


def test_change_password_unlocks_policy_ui(monkeypatch, tmp_path):
    monkeypatch.delenv("RAMPART_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("RAMPART_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RAMPART_AUTH_STATE", str(tmp_path / "auth.json"))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("RAMPART_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    client = TestClient(app)
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": INITIAL_PASSWORD, "next": "/ui/policies"},
        follow_redirects=False,
    )
    assert login_response.status_code == 303

    change_response = client.post(
        "/change-password",
        data={
            "current_password": INITIAL_PASSWORD,
            "new_password": "new-password-123",
            "confirm_password": "new-password-123",
        },
        follow_redirects=False,
    )

    assert change_response.status_code == 303
    assert change_response.headers["location"] == "/ui/policies?message=Password+changed"

    ui_response = client.get("/ui/policies")
    assert ui_response.status_code == 200
    assert "Policies" in ui_response.text
