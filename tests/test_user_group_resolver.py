import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest

from rampart.app.config import UserGroupResolverConfig, KeycloakConfig
from rampart.app.group_providers import GroupProvider
from rampart.app.user_group_resolver import UserGroupResolver


def test_resolver_config_defaults():
    cfg = UserGroupResolverConfig()
    assert cfg.enabled is False
    assert cfg.provider == "keycloak"
    assert cfg.cache_ttl_seconds == 900
    assert cfg.cache_max_size == 20000
    assert cfg.cache_persist_interval_seconds == 60
    assert cfg.cache_path == "data/user_group_cache.json"
    assert cfg.mappings_path == "data/group_mappings.json"


def test_keycloak_config_defaults():
    cfg = KeycloakConfig()
    assert cfg.base_url == ""
    assert cfg.realm == ""
    assert cfg.client_id == ""
    assert cfg.client_secret == ""


class FakeProvider(GroupProvider):
    def __init__(self, groups_by_user: dict[str, list[str]]):
        self.groups_by_user = groups_by_user
        self.call_count = 0

    async def lookup_groups(self, user_id: str) -> list[str]:
        self.call_count += 1
        return self.groups_by_user.get(user_id, [])


@pytest.fixture
def cache_path(tmp_path):
    return str(tmp_path / "user_group_cache.json")


def _make_resolver(provider, cache_path, ttl=900, max_size=100):
    return UserGroupResolver(provider=provider, cache_path=cache_path, cache_ttl_seconds=ttl, cache_max_size=max_size)


@pytest.mark.asyncio
async def test_cache_miss_calls_provider(cache_path):
    provider = FakeProvider({"alice@test.com": ["group-a", "group-b"]})
    resolver = _make_resolver(provider, cache_path)
    groups = await resolver.resolve("alice@test.com")
    assert sorted(groups) == ["group-a", "group-b"]
    assert provider.call_count == 1


@pytest.mark.asyncio
async def test_cache_hit_skips_provider(cache_path):
    provider = FakeProvider({"alice@test.com": ["group-a"]})
    resolver = _make_resolver(provider, cache_path)
    await resolver.resolve("alice@test.com")
    await resolver.resolve("alice@test.com")
    assert provider.call_count == 1


@pytest.mark.asyncio
async def test_cache_expired_calls_provider_again(cache_path):
    provider = FakeProvider({"alice@test.com": ["group-a"]})
    resolver = _make_resolver(provider, cache_path, ttl=0)
    await resolver.resolve("alice@test.com")
    await resolver.resolve("alice@test.com")
    assert provider.call_count == 2


@pytest.mark.asyncio
async def test_user_not_found_returns_empty(cache_path):
    provider = FakeProvider({})
    resolver = _make_resolver(provider, cache_path)
    groups = await resolver.resolve("nobody@test.com")
    assert groups == []


@pytest.mark.asyncio
async def test_lru_eviction(cache_path):
    users = {f"user{i}@test.com": [f"group-{i}"] for i in range(5)}
    provider = FakeProvider(users)
    resolver = _make_resolver(provider, cache_path, max_size=3)
    for email in users:
        await resolver.resolve(email)
    assert len(resolver._cache) == 3


@pytest.mark.asyncio
async def test_persist_and_load(cache_path):
    provider = FakeProvider({"alice@test.com": ["group-a"]})
    resolver = _make_resolver(provider, cache_path)
    await resolver.resolve("alice@test.com")
    resolver.persist()

    resolver2 = _make_resolver(provider, cache_path)
    resolver2.load()
    groups = await resolver2.resolve("alice@test.com")
    assert groups == ["group-a"]
    assert provider.call_count == 1  # loaded from file, not re-fetched
