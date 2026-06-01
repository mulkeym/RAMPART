import pytest
from rampart.app.group_providers import GroupProvider


def test_group_provider_is_abstract():
    with pytest.raises(TypeError):
        GroupProvider()


@pytest.mark.asyncio
async def test_group_provider_subclass_works():
    class FakeProvider(GroupProvider):
        async def lookup_groups(self, user_id: str) -> list[str]:
            return ["group-a", "group-b"]

    provider = FakeProvider()
    groups = await provider.lookup_groups("test@example.com")
    assert groups == ["group-a", "group-b"]


import httpx
from unittest.mock import AsyncMock, patch
from rampart.app.group_providers.keycloak import KeycloakGroupProvider


def _make_response(status_code: int, json_body) -> httpx.Response:
    """Build an httpx.Response with a dummy request attached (required for raise_for_status)."""
    req = httpx.Request("GET", "https://example.com")
    resp = httpx.Response(status_code, json=json_body, request=req)
    return resp


@pytest.fixture
def keycloak_provider():
    return KeycloakGroupProvider(
        base_url="https://keycloak.example.com",
        realm="dha",
        client_id="rampart-service",
        client_secret="secret123",
    )


@pytest.mark.asyncio
async def test_keycloak_lookup_groups(keycloak_provider):
    token_response = _make_response(200, {"access_token": "tok123"})
    user_response = _make_response(200, [{"id": "user-uuid-1"}])
    groups_response = _make_response(200, [
        {"id": "g1", "name": "DHA-Clinical", "path": "/DHA-Clinical"},
        {"id": "g2", "name": "DHA-Admin", "path": "/DHA-Admin"},
    ])

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=token_response):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=[user_response, groups_response]):
            groups = await keycloak_provider.lookup_groups("jsmith@dha.mil")

    assert sorted(groups) == ["DHA-Admin", "DHA-Clinical"]


@pytest.mark.asyncio
async def test_keycloak_user_not_found(keycloak_provider):
    token_response = _make_response(200, {"access_token": "tok123"})
    user_response = _make_response(200, [])

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=token_response):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=user_response):
            groups = await keycloak_provider.lookup_groups("nobody@dha.mil")

    assert groups == []


@pytest.mark.asyncio
async def test_keycloak_unreachable(keycloak_provider):
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.ConnectError("refused")):
        with pytest.raises(httpx.ConnectError):
            await keycloak_provider.lookup_groups("jsmith@dha.mil")
