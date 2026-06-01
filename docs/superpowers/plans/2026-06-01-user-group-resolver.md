# User Group Resolver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the OpenAI `user` field (email) to external identity provider group memberships, map those to RAMPART groups, and use the union of their policies for evaluation.

**Architecture:** A pluggable `GroupProvider` interface (Keycloak first) feeds a TTL-cached `UserGroupResolver`. External groups map to RAMPART groups via an admin-managed mapping table stored in JSON. Policy resolution in `main.py` checks the resolver before falling back to the API key's assigned policies.

**Tech Stack:** Python 3.10+, FastAPI, httpx (Keycloak API calls), Pydantic models, JSON file storage, existing RAMPART UI/MCP patterns.

---

## File Structure

**New files:**
| File | Responsibility |
|------|---------------|
| `rampart/app/group_providers/__init__.py` | `GroupProvider` abstract base class |
| `rampart/app/group_providers/keycloak.py` | Keycloak Admin REST API implementation |
| `rampart/app/user_group_resolver.py` | In-memory cache, TTL logic, JSON persistence, mapping resolution, orchestration |
| `rampart/app/group_mapping_store.py` | CRUD for `data/group_mappings.json` (follows `group_store.py` pattern) |
| `tests/test_group_provider.py` | Tests for provider interface and Keycloak provider |
| `tests/test_user_group_resolver.py` | Tests for cache, TTL, persistence, mapping resolution |
| `tests/test_group_mapping_store.py` | Tests for mapping CRUD |
| `tests/test_resolver_integration.py` | End-to-end: user field -> resolver -> policy selection -> fallback |

**Modified files:**
| File | Change |
|------|--------|
| `rampart/app/config.py` | Add `KeycloakConfig`, `UserGroupResolverConfig`, add to `AppConfig` |
| `rampart/app/settings_store.py` | Add resolver fields to `RuntimeSettings` |
| `rampart/app/main.py` | Pass `user` to `_resolve_policies()`, call resolver |
| `rampart/app/ui.py` | Add resolver section to settings form, add `/ui/group-mappings` page |
| `rampart/app/mcp_server.py` | Add 4 mapping CRUD tools |

---

### Task 1: GroupProvider Interface

**Files:**
- Create: `rampart/app/group_providers/__init__.py`
- Test: `tests/test_group_provider.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_group_provider.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_group_provider.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# rampart/app/group_providers/__init__.py
from __future__ import annotations

from abc import ABC, abstractmethod


class GroupProvider(ABC):
    @abstractmethod
    async def lookup_groups(self, user_id: str) -> list[str]:
        """Return external group names for a user identifier (e.g. email)."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_group_provider.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add rampart/app/group_providers/__init__.py tests/test_group_provider.py
git commit -m "feat: add GroupProvider abstract interface"
```

---

### Task 2: KeycloakGroupProvider

**Files:**
- Create: `rampart/app/group_providers/keycloak.py`
- Test: `tests/test_group_provider.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_group_provider.py`:

```python
import httpx
from unittest.mock import AsyncMock, patch
from rampart.app.group_providers.keycloak import KeycloakGroupProvider


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
    token_response = httpx.Response(200, json={"access_token": "tok123"})
    user_response = httpx.Response(200, json=[{"id": "user-uuid-1"}])
    groups_response = httpx.Response(200, json=[
        {"id": "g1", "name": "DHA-Clinical", "path": "/DHA-Clinical"},
        {"id": "g2", "name": "DHA-Admin", "path": "/DHA-Admin"},
    ])

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=token_response):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=[user_response, groups_response]):
            groups = await keycloak_provider.lookup_groups("jsmith@dha.mil")

    assert sorted(groups) == ["DHA-Admin", "DHA-Clinical"]


@pytest.mark.asyncio
async def test_keycloak_user_not_found(keycloak_provider):
    token_response = httpx.Response(200, json={"access_token": "tok123"})
    user_response = httpx.Response(200, json=[])

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=token_response):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=user_response):
            groups = await keycloak_provider.lookup_groups("nobody@dha.mil")

    assert groups == []


@pytest.mark.asyncio
async def test_keycloak_unreachable(keycloak_provider):
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.ConnectError("refused")):
        with pytest.raises(httpx.ConnectError):
            await keycloak_provider.lookup_groups("jsmith@dha.mil")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_group_provider.py -v`
Expected: FAIL — keycloak module not found

- [ ] **Step 3: Write implementation**

```python
# rampart/app/group_providers/keycloak.py
from __future__ import annotations

import httpx

from rampart.app.group_providers import GroupProvider
from rampart.app.tls import tls_verify


class KeycloakGroupProvider(GroupProvider):
    def __init__(self, base_url: str, realm: str, client_id: str, client_secret: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout

    async def lookup_groups(self, user_id: str) -> list[str]:
        token = await self._get_service_token()
        admin_base = f"{self.base_url}/admin/realms/{self.realm}"
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=self.timeout, verify=tls_verify()) as client:
            resp = await client.get(f"{admin_base}/users", params={"email": user_id, "exact": "true"}, headers=headers)
            resp.raise_for_status()
            users = resp.json()
            if not users:
                return []
            kc_user_id = users[0]["id"]
            resp = await client.get(f"{admin_base}/users/{kc_user_id}/groups", headers=headers)
            resp.raise_for_status()
            return [g["name"] for g in resp.json() if isinstance(g, dict) and "name" in g]

    async def _get_service_token(self) -> str:
        token_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        async with httpx.AsyncClient(timeout=self.timeout, verify=tls_verify()) as client:
            resp = await client.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            })
            resp.raise_for_status()
            return resp.json()["access_token"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_group_provider.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add rampart/app/group_providers/keycloak.py tests/test_group_provider.py
git commit -m "feat: add KeycloakGroupProvider implementation"
```

---

### Task 3: Group Mapping Store

**Files:**
- Create: `rampart/app/group_mapping_store.py`
- Test: `tests/test_group_mapping_store.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_group_mapping_store.py
import pytest
from rampart.app.group_mapping_store import (
    GroupMapping,
    list_mappings,
    get_mapping,
    create_mapping,
    update_mapping,
    delete_mapping,
)


@pytest.fixture
def store_path(tmp_path):
    return str(tmp_path / "group_mappings.json")


def test_list_mappings_empty(store_path):
    assert list_mappings(store_path) == []


def test_create_and_list(store_path):
    m = create_mapping("DHA-Clinical", "clinical-staff", path=store_path)
    assert m.external_group == "DHA-Clinical"
    assert m.rampart_group_id == "clinical-staff"
    assert m.enabled is True
    assert m.id  # auto-generated
    mappings = list_mappings(store_path)
    assert len(mappings) == 1
    assert mappings[0].id == m.id


def test_get_mapping(store_path):
    m = create_mapping("DHA-Admin", "admin-group", path=store_path)
    found = get_mapping(m.id, store_path)
    assert found is not None
    assert found.external_group == "DHA-Admin"


def test_get_mapping_not_found(store_path):
    assert get_mapping("nonexistent", store_path) is None


def test_update_mapping(store_path):
    m = create_mapping("DHA-Clinical", "clinical-staff", path=store_path)
    m.rampart_group_id = "new-group"
    m.enabled = False
    update_mapping(m, store_path)
    found = get_mapping(m.id, store_path)
    assert found.rampart_group_id == "new-group"
    assert found.enabled is False


def test_update_not_found(store_path):
    m = GroupMapping(id="bad-id", external_group="X", rampart_group_id="Y")
    with pytest.raises(ValueError, match="not found"):
        update_mapping(m, store_path)


def test_delete_mapping(store_path):
    m = create_mapping("DHA-Clinical", "clinical-staff", path=store_path)
    delete_mapping(m.id, store_path)
    assert list_mappings(store_path) == []


def test_delete_not_found(store_path):
    with pytest.raises(ValueError, match="not found"):
        delete_mapping("bad-id", store_path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_group_mapping_store.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write implementation**

```python
# rampart/app/group_mapping_store.py
from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


MAPPING_STORE_PATH = "data/group_mappings.json"


class GroupMapping(BaseModel):
    id: str = ""
    external_group: str = ""
    rampart_group_id: str = ""
    enabled: bool = True


class MappingStore(BaseModel):
    mappings: list[GroupMapping] = Field(default_factory=list)


def _generate_id() -> str:
    return "map-" + secrets.token_hex(6)


def _load(path: Optional[str] = None) -> MappingStore:
    store_path = Path(path or MAPPING_STORE_PATH)
    if not store_path.exists():
        return MappingStore()
    with store_path.open("r", encoding="utf-8") as f:
        return MappingStore.model_validate(json.load(f))


def _save(store: MappingStore, path: Optional[str] = None) -> None:
    store_path = Path(path or MAPPING_STORE_PATH)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("w", encoding="utf-8") as f:
        json.dump(store.model_dump(), f, indent=2, sort_keys=True)
        f.write("\n")


def list_mappings(path: Optional[str] = None) -> list[GroupMapping]:
    return _load(path).mappings


def get_mapping(mapping_id: str, path: Optional[str] = None) -> Optional[GroupMapping]:
    for m in list_mappings(path):
        if m.id == mapping_id:
            return m
    return None


def create_mapping(external_group: str, rampart_group_id: str, enabled: bool = True, path: Optional[str] = None) -> GroupMapping:
    mapping = GroupMapping(id=_generate_id(), external_group=external_group, rampart_group_id=rampart_group_id, enabled=enabled)
    store = _load(path)
    store.mappings.append(mapping)
    _save(store, path)
    return mapping


def update_mapping(mapping: GroupMapping, path: Optional[str] = None) -> None:
    store = _load(path)
    found = False
    updated = []
    for existing in store.mappings:
        if existing.id == mapping.id:
            updated.append(mapping)
            found = True
        else:
            updated.append(existing)
    if not found:
        raise ValueError(f"Mapping '{mapping.id}' not found.")
    store.mappings = updated
    _save(store, path)


def delete_mapping(mapping_id: str, path: Optional[str] = None) -> None:
    store = _load(path)
    original = len(store.mappings)
    store.mappings = [m for m in store.mappings if m.id != mapping_id]
    if len(store.mappings) == original:
        raise ValueError(f"Mapping '{mapping_id}' not found.")
    _save(store, path)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_group_mapping_store.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add rampart/app/group_mapping_store.py tests/test_group_mapping_store.py
git commit -m "feat: add group mapping store (external group -> RAMPART group)"
```

---

### Task 4: Config Models

**Files:**
- Modify: `rampart/app/config.py`
- Test: `tests/test_user_group_resolver.py` (start file)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_user_group_resolver.py
from rampart.app.config import UserGroupResolverConfig, KeycloakConfig


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_user_group_resolver.py::test_resolver_config_defaults -v`
Expected: FAIL — cannot import

- [ ] **Step 3: Add config models to `rampart/app/config.py`**

Add before the `AppConfig` class:

```python
class KeycloakConfig(BaseModel):
    base_url: str = ""
    realm: str = ""
    client_id: str = ""
    client_secret: str = ""


class UserGroupResolverConfig(BaseModel):
    enabled: bool = False
    provider: str = "keycloak"
    cache_ttl_seconds: int = 900
    cache_max_size: int = 20000
    cache_persist_interval_seconds: int = 60
    cache_path: str = "data/user_group_cache.json"
    mappings_path: str = "data/group_mappings.json"
    keycloak: KeycloakConfig = Field(default_factory=KeycloakConfig)
```

Add to `AppConfig`:

```python
    user_group_resolver: UserGroupResolverConfig = Field(default_factory=UserGroupResolverConfig)
```

Add to `_apply_env_overrides`:

```python
    resolver = config.user_group_resolver
    resolver.keycloak.base_url = os.getenv("RAMPART_KEYCLOAK_BASE_URL", resolver.keycloak.base_url)
    resolver.keycloak.realm = os.getenv("RAMPART_KEYCLOAK_REALM", resolver.keycloak.realm)
    resolver.keycloak.client_id = os.getenv("RAMPART_KEYCLOAK_CLIENT_ID", resolver.keycloak.client_id)
    resolver.keycloak.client_secret = os.getenv("RAMPART_KEYCLOAK_CLIENT_SECRET", resolver.keycloak.client_secret)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_user_group_resolver.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run all existing tests to check nothing broke**

Run: `python -m pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add rampart/app/config.py tests/test_user_group_resolver.py
git commit -m "feat: add UserGroupResolverConfig and KeycloakConfig models"
```

---

### Task 5: UserGroupResolver (Cache + Orchestration)

**Files:**
- Create: `rampart/app/user_group_resolver.py`
- Test: `tests/test_user_group_resolver.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_user_group_resolver.py`:

```python
import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest

from rampart.app.config import AppConfig, UserGroupResolverConfig, KeycloakConfig
from rampart.app.group_providers import GroupProvider
from rampart.app.user_group_resolver import UserGroupResolver


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_user_group_resolver.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write implementation**

```python
# rampart/app/user_group_resolver.py
from __future__ import annotations

import json
from pathlib import Path
from time import time
from typing import Any, Optional

from rampart.app.group_providers import GroupProvider


class UserGroupResolver:
    def __init__(self, provider: GroupProvider, cache_path: str, cache_ttl_seconds: int = 900, cache_max_size: int = 20000):
        self.provider = provider
        self.cache_path = cache_path
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_max_size = cache_max_size
        self._cache: dict[str, dict[str, Any]] = {}
        self._dirty = False

    async def resolve(self, user_id: str) -> list[str]:
        entry = self._cache.get(user_id)
        if entry is not None and (time() - entry["fetched_at"]) < self.cache_ttl_seconds:
            return entry["groups"]
        groups = await self.provider.lookup_groups(user_id)
        self._cache[user_id] = {"groups": groups, "fetched_at": time()}
        self._dirty = True
        self._evict_if_needed()
        return groups

    def persist(self) -> None:
        if not self._dirty:
            return
        path = Path(self.cache_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self._cache, f, sort_keys=True)
            f.write("\n")
        self._dirty = False

    def load(self) -> None:
        path = Path(self.cache_path)
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8") as f:
                self._cache = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._cache = {}

    def _evict_if_needed(self) -> None:
        while len(self._cache) > self.cache_max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k]["fetched_at"])
            del self._cache[oldest_key]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_user_group_resolver.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add rampart/app/user_group_resolver.py tests/test_user_group_resolver.py
git commit -m "feat: add UserGroupResolver with TTL cache and JSON persistence"
```

---

### Task 6: Settings Store + Config Wiring

**Files:**
- Modify: `rampart/app/settings_store.py`
- Modify: `rampart/app/config.py` (add `_apply_local_settings` entries)

- [ ] **Step 1: Add resolver fields to `RuntimeSettings` in `settings_store.py`**

Add these fields to the `RuntimeSettings` class after the existing fields:

```python
    # User Group Resolver
    user_group_resolver_enabled: Optional[bool] = None
    user_group_resolver_provider: str = ""
    user_group_resolver_cache_ttl_seconds: Optional[int] = None
    user_group_resolver_keycloak_base_url: str = ""
    user_group_resolver_keycloak_realm: str = ""
    user_group_resolver_keycloak_client_id: str = ""
    user_group_resolver_keycloak_client_secret: str = ""
```

- [ ] **Step 2: Add `_apply_local_settings` entries in `config.py`**

Append to the end of `_apply_local_settings`:

```python
    if settings.user_group_resolver_enabled is not None:
        config.user_group_resolver.enabled = settings.user_group_resolver_enabled
    if settings.user_group_resolver_provider:
        config.user_group_resolver.provider = settings.user_group_resolver_provider
    if settings.user_group_resolver_cache_ttl_seconds is not None:
        config.user_group_resolver.cache_ttl_seconds = settings.user_group_resolver_cache_ttl_seconds
    if settings.user_group_resolver_keycloak_base_url:
        config.user_group_resolver.keycloak.base_url = settings.user_group_resolver_keycloak_base_url
    if settings.user_group_resolver_keycloak_realm:
        config.user_group_resolver.keycloak.realm = settings.user_group_resolver_keycloak_realm
    if settings.user_group_resolver_keycloak_client_id:
        config.user_group_resolver.keycloak.client_id = settings.user_group_resolver_keycloak_client_id
    if settings.user_group_resolver_keycloak_client_secret:
        config.user_group_resolver.keycloak.client_secret = settings.user_group_resolver_keycloak_client_secret
```

- [ ] **Step 3: Run all tests**

Run: `python -m pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add rampart/app/settings_store.py rampart/app/config.py
git commit -m "feat: wire resolver settings into RuntimeSettings and config"
```

---

### Task 7: Policy Resolution Integration

**Files:**
- Modify: `rampart/app/main.py`
- Test: `tests/test_resolver_integration.py`

- [ ] **Step 1: Write the failing integration test**

```python
# tests/test_resolver_integration.py
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from fastapi.testclient import TestClient
from rampart.app.main import app
from rampart.app.config import (
    AppConfig, PolicyConfig, CheckConfig, UserGroupResolverConfig, KeycloakConfig,
)
from rampart.app.group_store import GroupRecord


def _config_with_resolver(policies, groups, mappings):
    """Build an AppConfig with resolver enabled and given policies/groups/mappings."""
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
    """When user field is present and resolver succeeds, use resolved policies."""
    policies = [
        PolicyConfig(id="baseline-policy", enabled=True, severity="high", action="block",
                     checks=[CheckConfig(type="regex", pattern="BLOCKED")]),
        PolicyConfig(id="clinical-policy", enabled=True, severity="high", action="block",
                     checks=[CheckConfig(type="regex", pattern="SECRET_CLINICAL")]),
    ]
    group = GroupRecord(id="clinical-staff", name="Clinical Staff", enrollment_key="k", policy_ids=["clinical-policy"])
    mappings_data = [{"id": "m1", "external_group": "DHA-Clinical", "rampart_group_id": "clinical-staff", "enabled": True}]

    config = _config_with_resolver(policies, [group], mappings_data)

    with patch("rampart.app.main.get_config", return_value=config), \
         patch("rampart.app.main._resolve_client_record", return_value=None), \
         patch("rampart.app.main.resolve_policies_for_user", return_value=[policies[1]]) as mock_resolve, \
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_resolver_integration.py -v`
Expected: FAIL — `resolve_policies_for_user` not importable from `main`

- [ ] **Step 3: Modify `main.py`**

Add import at top:

```python
from rampart.app.openai.compat import extract_user
```

(Already present from prior commit — verify.)

Add new function `resolve_policies_for_user`:

```python
def resolve_policies_for_user(config: AppConfig, user: str) -> list[PolicyConfig]:
    """Resolve external groups for a user and map to RAMPART policies."""
    from rampart.app.user_group_resolver import UserGroupResolver
    from rampart.app.group_providers.keycloak import KeycloakGroupProvider
    from rampart.app.group_mapping_store import list_mappings
    from rampart.app.group_store import get_group
    import asyncio

    resolver_cfg = config.user_group_resolver
    if resolver_cfg.provider == "keycloak":
        kc = resolver_cfg.keycloak
        provider = KeycloakGroupProvider(
            base_url=kc.base_url, realm=kc.realm,
            client_id=kc.client_id, client_secret=kc.client_secret,
        )
    else:
        return []

    resolver = _get_or_create_resolver(provider, resolver_cfg)
    external_groups = asyncio.get_event_loop().run_until_complete(resolver.resolve(user))
    if not external_groups:
        return []

    mappings = list_mappings(resolver_cfg.mappings_path)
    group_map = {m.external_group: m.rampart_group_id for m in mappings if m.enabled}

    rampart_group_ids: set[str] = set()
    for ext_group in external_groups:
        if ext_group in group_map:
            rampart_group_ids.add(group_map[ext_group])

    if not rampart_group_ids:
        return []

    enabled_policies = [p for p in config.policies if p.enabled]
    policy_ids: set[str] = set()
    for gid in rampart_group_ids:
        group = get_group(gid)
        if group and group.policy_ids:
            policy_ids.update(group.policy_ids)

    return [p for p in enabled_policies if p.id in policy_ids]


# Module-level resolver instance (per-process singleton)
_resolver_instance: Optional[Any] = None
_resolver_config_hash: Optional[str] = None


def _get_or_create_resolver(provider, resolver_cfg) -> Any:
    global _resolver_instance, _resolver_config_hash
    from rampart.app.user_group_resolver import UserGroupResolver
    cfg_hash = f"{resolver_cfg.provider}:{resolver_cfg.cache_ttl_seconds}:{resolver_cfg.cache_max_size}"
    if _resolver_instance is None or _resolver_config_hash != cfg_hash:
        _resolver_instance = UserGroupResolver(
            provider=provider,
            cache_path=resolver_cfg.cache_path,
            cache_ttl_seconds=resolver_cfg.cache_ttl_seconds,
            cache_max_size=resolver_cfg.cache_max_size,
        )
        _resolver_instance.load()
        _resolver_config_hash = cfg_hash
    return _resolver_instance
```

Modify `_resolve_policies` to accept and use `user`:

```python
def _resolve_policies(config: AppConfig, client: Optional[ClientRecord], user: Optional[str] = None) -> list[PolicyConfig]:
    if user and config.user_group_resolver.enabled:
        try:
            policies = resolve_policies_for_user(config, user)
            if policies:
                return policies
        except Exception:
            pass  # fall through to existing logic
    enabled_policies = [policy for policy in config.policies if policy.enabled]
    # ... rest of existing logic unchanged
```

Modify the `/v1/rampart/evaluate` endpoint to pass `user`:

```python
    user = extract_user(payload.request)
    policies = _resolve_policies(config, client_record, user=user)
```

Modify the `/v1/chat/completions` endpoint to pass `user`:

```python
    user = extract_user(payload)
    policies = _resolve_policies(config, client_record, user=user)
```

**Important:** Since `resolve_policies_for_user` is called inside an async endpoint, use `await resolver.resolve(user)` directly instead of `run_until_complete`. The function should be async:

```python
async def resolve_policies_for_user(config: AppConfig, user: str) -> list[PolicyConfig]:
```

And call it with `await` in `_resolve_policies` (which must also become async):

```python
async def _resolve_policies(config: AppConfig, client: Optional[ClientRecord], user: Optional[str] = None) -> list[PolicyConfig]:
    if user and config.user_group_resolver.enabled:
        try:
            policies = await resolve_policies_for_user(config, user)
            if policies:
                return policies
        except Exception:
            pass
    # ... existing sync logic unchanged
```

Update callers in both endpoints: `policies = await _resolve_policies(config, client_record, user=user)`

- [ ] **Step 4: Run integration tests**

Run: `python -m pytest tests/test_resolver_integration.py -v`
Expected: PASS

- [ ] **Step 5: Run all tests**

Run: `python -m pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add rampart/app/main.py tests/test_resolver_integration.py
git commit -m "feat: integrate UserGroupResolver into policy resolution pipeline"
```

---

### Task 8: Admin UI — Settings Section

**Files:**
- Modify: `rampart/app/ui.py`
- Modify: `rampart/app/settings_store.py` (already done in Task 6)

- [ ] **Step 1: Add User Group Resolver fieldset to `_settings_form` in `ui.py`**

Insert before the closing `</form>` tag (before the MCP fieldset's closing and the `<div class="actions">` button), add a new fieldset:

```python
        <fieldset class="fieldset">
          <legend>User Group Resolver</legend>
          <div class="hint">Resolve end-user identity to external group memberships for per-user policy assignment.</div>
          <div>
            <label style="display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px;color:var(--text-secondary)">Enabled <input type="checkbox" name="user_group_resolver_enabled" {"checked" if config.user_group_resolver.enabled else ""} style="width:auto"></label>
            <div class="hint" style="margin-top:4px">When enabled, the OpenAI 'user' field (email) is resolved to external group memberships for policy selection.</div>
          </div>
          <label>Provider
            <select name="user_group_resolver_provider">
              <option value="keycloak" {"selected" if config.user_group_resolver.provider == "keycloak" else ""}>Keycloak</option>
            </select>
          </label>
          <label>Cache TTL (seconds)<input name="user_group_resolver_cache_ttl_seconds" value="{get_value("user_group_resolver_cache_ttl_seconds", config.user_group_resolver.cache_ttl_seconds)}" inputmode="numeric"></label>
          <label>Keycloak Base URL<input name="user_group_resolver_keycloak_base_url" value="{get_value("user_group_resolver_keycloak_base_url", config.user_group_resolver.keycloak.base_url)}" placeholder="https://keycloak.example.com"></label>
          <label>Keycloak Realm<input name="user_group_resolver_keycloak_realm" value="{get_value("user_group_resolver_keycloak_realm", config.user_group_resolver.keycloak.realm)}" placeholder="dha"></label>
          <label>Keycloak Client ID<input name="user_group_resolver_keycloak_client_id" value="{get_value("user_group_resolver_keycloak_client_id", config.user_group_resolver.keycloak.client_id)}" placeholder="rampart-service"></label>
          <label>Keycloak Client Secret<input name="user_group_resolver_keycloak_client_secret" value="{get_value("user_group_resolver_keycloak_client_secret", config.user_group_resolver.keycloak.client_secret)}" type="password" autocomplete="off"></label>
        </fieldset>
```

- [ ] **Step 2: Update `update_settings` POST handler to read new fields**

Add to the `RuntimeSettings(...)` constructor in the `update_settings` function:

```python
            user_group_resolver_enabled=form.get("user_group_resolver_enabled") == "on",
            user_group_resolver_provider=form.get("user_group_resolver_provider", "").strip(),
            user_group_resolver_cache_ttl_seconds=_optional_int(form.get("user_group_resolver_cache_ttl_seconds", "")),
            user_group_resolver_keycloak_base_url=form.get("user_group_resolver_keycloak_base_url", "").strip(),
            user_group_resolver_keycloak_realm=form.get("user_group_resolver_keycloak_realm", "").strip(),
            user_group_resolver_keycloak_client_id=form.get("user_group_resolver_keycloak_client_id", "").strip(),
            user_group_resolver_keycloak_client_secret=form.get("user_group_resolver_keycloak_client_secret", "").strip(),
```

Add `_optional_int` helper near `_optional_float` if not already present:

```python
def _optional_int(value: str) -> Optional[int]:
    value = value.strip()
    return int(value) if value else None
```

- [ ] **Step 3: Run all tests**

Run: `python -m pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat: add User Group Resolver section to /ui/settings"
```

---

### Task 9: Admin UI — Group Mappings Page

**Files:**
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Add imports at top of `ui.py`**

```python
from rampart.app.group_mapping_store import (
    GroupMapping, list_mappings as store_list_mappings, get_mapping,
    create_mapping as store_create_mapping, update_mapping as store_update_mapping,
    delete_mapping as store_delete_mapping,
)
```

- [ ] **Step 2: Add routes for `/ui/group-mappings`**

Add after the existing group routes (around line 605), following the same pattern as `/ui/groups`:

```python
# --- Group Mappings UI ---

@router.get("/ui/group-mappings", response_class=HTMLResponse)
async def group_mappings_index(request: Request, message: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    config = get_config()
    mappings = store_list_mappings(config.user_group_resolver.mappings_path)
    groups = store_list_groups()
    group_names = {g.id: g.name for g in groups}
    rows = "\n".join(
        f'<tr><td>{escape(m.external_group)}</td>'
        f'<td>{escape(group_names.get(m.rampart_group_id, m.rampart_group_id))}</td>'
        f'<td>{"Enabled" if m.enabled else "Disabled"}</td>'
        f'<td><a href="/ui/group-mappings/{m.id}">Edit</a></td></tr>'
        for m in mappings
    )
    body = f"""
      <section class="toolbar">
        <div><h1>Group Mappings</h1><p>Map external identity provider groups to RAMPART groups.</p></div>
        <a class="button primary" href="/ui/group-mappings/new">New Mapping</a>
      </section>
      {_notice(message, None)}
      <section class="panel">
        <table>
          <thead><tr><th>External Group</th><th>RAMPART Group</th><th>Status</th><th></th></tr></thead>
          <tbody>{rows or _empty_row(4, "No group mappings configured.")}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART Group Mappings", body, read_session_user(request)))


@router.get("/ui/group-mappings/new", response_class=HTMLResponse)
async def new_group_mapping(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    return HTMLResponse(_group_mapping_form(None, "Create Mapping", "/ui/group-mappings/new", actor=read_session_user(request)))


@router.post("/ui/group-mappings/new", response_class=HTMLResponse)
async def create_group_mapping_route(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    config = get_config()
    form = await _form_data(request)
    external_group = form.get("external_group", "").strip()
    rampart_group_id = form.get("rampart_group_id", "").strip()
    if not external_group or not rampart_group_id:
        return HTMLResponse(_group_mapping_form(None, "Create Mapping", "/ui/group-mappings/new", "External group and RAMPART group are required.", read_session_user(request)), status_code=400)
    store_create_mapping(external_group, rampart_group_id, path=config.user_group_resolver.mappings_path)
    return RedirectResponse("/ui/group-mappings?message=Mapping+created", status_code=303)


@router.get("/ui/group-mappings/{mapping_id}", response_class=HTMLResponse)
async def edit_group_mapping(mapping_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    config = get_config()
    mapping = get_mapping(mapping_id, config.user_group_resolver.mappings_path)
    if not mapping:
        return HTMLResponse(_page("Mapping Not Found", "<p>Mapping not found.</p>", read_session_user(request)), status_code=404)
    return HTMLResponse(_group_mapping_form(mapping, "Edit Mapping", f"/ui/group-mappings/{mapping.id}", actor=read_session_user(request)))


@router.post("/ui/group-mappings/{mapping_id}", response_class=HTMLResponse)
async def update_group_mapping_route(mapping_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    config = get_config()
    mapping = get_mapping(mapping_id, config.user_group_resolver.mappings_path)
    if not mapping:
        return RedirectResponse("/ui/group-mappings?message=Mapping+not+found", status_code=303)
    form = await _form_data(request)
    mapping.external_group = form.get("external_group", mapping.external_group).strip()
    mapping.rampart_group_id = form.get("rampart_group_id", mapping.rampart_group_id).strip()
    mapping.enabled = form.get("enabled") == "on"
    store_update_mapping(mapping, config.user_group_resolver.mappings_path)
    return RedirectResponse("/ui/group-mappings?message=Mapping+saved", status_code=303)


@router.post("/ui/group-mappings/{mapping_id}/delete", response_class=HTMLResponse)
async def delete_group_mapping_route(mapping_id: str, request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    config = get_config()
    try:
        store_delete_mapping(mapping_id, config.user_group_resolver.mappings_path)
    except ValueError:
        pass
    return RedirectResponse("/ui/group-mappings?message=Mapping+deleted", status_code=303)


def _group_mapping_form(mapping: Optional[GroupMapping], title: str, action: str, error: Optional[str] = None, actor: Optional[str] = None) -> str:
    groups = store_list_groups()
    options = "\n".join(
        f'<option value="{escape(g.id)}" {"selected" if mapping and mapping.rampart_group_id == g.id else ""}>{escape(g.name)} ({escape(g.id)})</option>'
        for g in groups
    )
    body = f"""
      <section class="toolbar"><div><h1>{escape(title)}</h1></div></section>
      {_notice(None, error)}
      <form class="panel form" method="post" action="{escape(action)}">
        <label>External Group Name<input name="external_group" value="{escape(mapping.external_group if mapping else "")}" placeholder="e.g. DHA-Clinical" required></label>
        <label>RAMPART Group<select name="rampart_group_id" required><option value="">Select...</option>{options}</select></label>
        <div>
          <label style="display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px;color:var(--text-secondary)">Enabled <input type="checkbox" name="enabled" {"checked" if (mapping is None or mapping.enabled) else ""} style="width:auto"></label>
        </div>
        <div class="actions">
          <button class="button primary" type="submit">Save</button>
          <a href="/ui/group-mappings" class="button">Cancel</a>
          {"" if mapping is None else f'<form method="post" action="/ui/group-mappings/{mapping.id}/delete" style="margin-left:auto"><button class="button danger" type="submit" onclick="return confirm(\\\'Delete this mapping?\\\')">Delete</button></form>'}
        </div>
      </form>
    """
    return _page(f"RAMPART {title}", body, actor)
```

- [ ] **Step 3: Add nav link to Group Mappings**

Find the nav section in `_page` helper or sidebar that links to `/ui/groups` and add a link for `/ui/group-mappings` next to it. Search for the nav items in `_page` and add:

```python
<a href="/ui/group-mappings" ...>Group Mappings</a>
```

- [ ] **Step 4: Run all tests**

Run: `python -m pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat: add /ui/group-mappings admin page for external group mapping"
```

---

### Task 10: MCP Tools for Group Mappings

**Files:**
- Modify: `rampart/app/mcp_server.py`

- [ ] **Step 1: Add imports at top of `mcp_server.py`**

```python
from rampart.app.group_mapping_store import (
    list_mappings as store_list_mappings, get_mapping as store_get_mapping,
    create_mapping as store_create_mapping, update_mapping as store_update_mapping_record,
    delete_mapping as store_delete_mapping, GroupMapping,
)
```

- [ ] **Step 2: Add mapping tool names to `WRITE_TOOLS` set**

```python
WRITE_TOOLS = {
    ...,
    "create_group_mapping", "update_group_mapping", "delete_group_mapping",
}
```

- [ ] **Step 3: Add 4 MCP tool handlers**

```python
@_handler(
    "list_group_mappings",
    "List all external group to RAMPART group mappings.",
    {"type": "object", "properties": {}, "required": []},
)
def handle_list_group_mappings() -> str:
    config = get_config()
    mappings = store_list_mappings(config.user_group_resolver.mappings_path)
    return json.dumps([
        {"id": m.id, "external_group": m.external_group, "rampart_group_id": m.rampart_group_id, "enabled": m.enabled}
        for m in mappings
    ])


@_handler(
    "create_group_mapping",
    "Create a mapping from an external identity provider group to a RAMPART group.",
    {
        "type": "object",
        "properties": {
            "external_group": {"type": "string", "description": "External group name (e.g. from Keycloak)"},
            "rampart_group_id": {"type": "string", "description": "RAMPART group ID to map to"},
            "enabled": {"type": "boolean", "description": "Whether the mapping is active", "default": True},
        },
        "required": ["external_group", "rampart_group_id"],
    },
)
def handle_create_group_mapping(external_group: str, rampart_group_id: str, enabled: bool = True) -> str:
    config = get_config()
    mapping = store_create_mapping(external_group, rampart_group_id, enabled=enabled, path=config.user_group_resolver.mappings_path)
    return json.dumps({"created": mapping.id, "external_group": mapping.external_group, "rampart_group_id": mapping.rampart_group_id})


@_handler(
    "update_group_mapping",
    "Update an existing group mapping. Only provided fields are changed.",
    {
        "type": "object",
        "properties": {
            "mapping_id": {"type": "string", "description": "The mapping ID to update"},
            "external_group": {"type": "string", "description": "New external group name"},
            "rampart_group_id": {"type": "string", "description": "New RAMPART group ID"},
            "enabled": {"type": "boolean", "description": "Whether the mapping is active"},
        },
        "required": ["mapping_id"],
    },
)
def handle_update_group_mapping(mapping_id: str, external_group: str = None, rampart_group_id: str = None, enabled: bool = None) -> str:
    config = get_config()
    mapping = store_get_mapping(mapping_id, config.user_group_resolver.mappings_path)
    if not mapping:
        return json.dumps({"error": f"Mapping '{mapping_id}' not found."})
    if external_group is not None:
        mapping.external_group = external_group
    if rampart_group_id is not None:
        mapping.rampart_group_id = rampart_group_id
    if enabled is not None:
        mapping.enabled = enabled
    store_update_mapping_record(mapping, config.user_group_resolver.mappings_path)
    return json.dumps({"updated": mapping_id})


@_handler(
    "delete_group_mapping",
    "Delete a group mapping.",
    {
        "type": "object",
        "properties": {
            "mapping_id": {"type": "string", "description": "The mapping ID to delete"},
        },
        "required": ["mapping_id"],
    },
)
def handle_delete_group_mapping(mapping_id: str) -> str:
    config = get_config()
    try:
        store_delete_mapping(mapping_id, config.user_group_resolver.mappings_path)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"deleted": mapping_id})
```

- [ ] **Step 4: Run all tests**

Run: `python -m pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add rampart/app/mcp_server.py
git commit -m "feat: add MCP tools for group mapping CRUD"
```

---

### Task 11: Cache Persistence Background Task

**Files:**
- Modify: `rampart/app/main.py`

- [ ] **Step 1: Add periodic cache persistence on startup**

In `main.py`, add a background task that persists the resolver cache periodically:

```python
import asyncio as _asyncio

@app.on_event("startup")
async def _start_cache_persistence():
    config = get_config()
    if not config.user_group_resolver.enabled:
        return
    interval = config.user_group_resolver.cache_persist_interval_seconds

    async def _persist_loop():
        while True:
            await _asyncio.sleep(interval)
            if _resolver_instance is not None:
                _resolver_instance.persist()

    _asyncio.create_task(_persist_loop())
```

- [ ] **Step 2: Run all tests**

Run: `python -m pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add rampart/app/main.py
git commit -m "feat: add background cache persistence for user group resolver"
```

---

### Task 12: Final Integration Test & Cleanup

**Files:**
- Test: `tests/test_resolver_integration.py` (extend)

- [ ] **Step 1: Add fallback test**

Append to `tests/test_resolver_integration.py`:

```python
def test_resolver_failure_falls_back(client):
    """When resolver raises, fall back to API key policies."""
    policies = [
        PolicyConfig(id="baseline-policy", enabled=True, severity="high", action="block",
                     checks=[CheckConfig(type="regex", pattern="BLOCKED")]),
    ]
    config = _config_with_resolver(policies, [], [])

    with patch("rampart.app.main.get_config", return_value=config), \
         patch("rampart.app.main._resolve_client_record", return_value=None), \
         patch("rampart.app.main.resolve_policies_for_user", side_effect=Exception("Keycloak down")), \
         patch("rampart.app.main.write_evaluation_event"):
        resp = client.post("/v1/rampart/evaluate", json={
            "request": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello BLOCKED"}], "user": "jsmith@dha.mil"}
        })
    assert resp.status_code == 200
    assert resp.json()["decision"] == "fail"
```

- [ ] **Step 2: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add tests/test_resolver_integration.py
git commit -m "test: add resolver fallback integration test"
```

- [ ] **Step 4: Push all commits**

```bash
git push origin master
```
