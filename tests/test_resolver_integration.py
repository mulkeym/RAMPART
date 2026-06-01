import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from fastapi.testclient import TestClient
from rampart.app.main import app
from rampart.app.config import (
    AppConfig, PolicyConfig, CheckConfig, UserGroupResolverConfig, KeycloakConfig,
)
from rampart.app.group_store import GroupRecord


def _config_with_resolver(policies, groups, mappings):
    cfg = AppConfig(
        policies=policies,
        user_group_resolver=UserGroupResolverConfig(
            enabled=True,
            provider="keycloak",
            keycloak=KeycloakConfig(
                base_url="https://kc.test",
                realm="test",
                client_id="cid",
                client_secret="csec",
            ),
        ),
    )
    return cfg


@pytest.fixture
def client():
    return TestClient(app)


def test_user_field_resolves_policies(client):
    """When user field present and resolver succeeds, use resolved policies."""
    policies = [
        PolicyConfig(id="baseline-policy", enabled=True, severity="high", action="block",
                     checks=[CheckConfig(type="regex", pattern="BLOCKED")]),
        PolicyConfig(id="clinical-policy", enabled=True, severity="high", action="block",
                     checks=[CheckConfig(type="regex", pattern="SECRET_CLINICAL")]),
    ]
    config = _config_with_resolver(policies, [], [])

    with patch("rampart.app.main.get_config", return_value=config), \
         patch("rampart.app.main._resolve_client_record", return_value=None), \
         patch("rampart.app.main.resolve_policies_for_user", new_callable=AsyncMock, return_value=[policies[1]]) as mock_resolve, \
         patch("rampart.app.main.write_evaluation_event"):
        resp = client.post("/v1/rampart/evaluate", json={
            "request": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello SECRET_CLINICAL"}], "user": "jsmith@dha.mil"}
        })
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "fail"
    mock_resolve.assert_called_once()


def test_no_user_field_uses_fallback(client):
    """When user field is absent, use existing policy resolution."""
    policies = [
        PolicyConfig(id="baseline-policy", enabled=True, severity="high", action="block",
                     checks=[CheckConfig(type="regex", pattern="BLOCKED")]),
    ]
    config = AppConfig(policies=policies)

    with patch("rampart.app.main.get_config", return_value=config), \
         patch("rampart.app.main._resolve_client_record", return_value=None), \
         patch("rampart.app.main.write_evaluation_event"):
        resp = client.post("/v1/rampart/evaluate", json={
            "request": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello BLOCKED"}]}
        })
    assert resp.status_code == 200
    assert resp.json()["decision"] == "fail"


def test_resolver_failure_falls_back(client):
    """When resolver raises, fall back to API key policies."""
    policies = [
        PolicyConfig(id="baseline-policy", enabled=True, severity="high", action="block",
                     checks=[CheckConfig(type="regex", pattern="BLOCKED")]),
    ]
    config = _config_with_resolver(policies, [], [])

    with patch("rampart.app.main.get_config", return_value=config), \
         patch("rampart.app.main._resolve_client_record", return_value=None), \
         patch("rampart.app.main.resolve_policies_for_user", new_callable=AsyncMock, side_effect=Exception("Keycloak down")), \
         patch("rampart.app.main.write_evaluation_event"):
        resp = client.post("/v1/rampart/evaluate", json={
            "request": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello BLOCKED"}], "user": "jsmith@dha.mil"}
        })
    assert resp.status_code == 200
    assert resp.json()["decision"] == "fail"
