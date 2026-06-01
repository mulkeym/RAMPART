# User Group Resolver — Design Spec

**Date:** 2026-06-01
**Status:** Draft
**Scope:** Pluggable user-to-group resolution with external identity provider integration

---

## Problem

RAMPART currently assigns policies based on API key identity (client record → group enrollment or direct assignment). For the Ask Sage integration, different users sharing the same API key need different policy sets based on their role/group membership in an external identity provider (initially Keycloak, with future support for PingFederate, AD/LDAP, etc.).

## Overview

A new `UserGroupResolver` module resolves the OpenAI `user` field (email address provided by Ask Sage) to external group memberships via a pluggable provider interface. External groups are mapped to RAMPART groups through an admin-managed mapping table. The union of all matched RAMPART groups' policies is used for evaluation.

The resolver includes an in-memory cache (up to 20,000 users) with TTL-based expiry and JSON file persistence for warm restarts.

## Policy Resolution Precedence

1. **User field present + provider resolves + mappings match** — union of all mapped RAMPART group policies (replaces API key baseline)
2. **User field present but lookup fails / no mappings match** — fall back to the API key's assigned policies (existing behavior)
3. **No user field** — API key's assigned policies (existing behavior, unchanged)

When Keycloak-resolved policies are available, they **replace** (not merge with) the API key's baseline policies. The API key's policies serve purely as a safety net fallback. Admins are responsible for ensuring Keycloak group mappings are complete.

## Architecture

```
Request (user: "jsmith@dha.mil")
    |
    v
UserGroupResolver (in-memory cache + TTL)
    | cache miss
    v
GroupProvider interface
    |
    +-- KeycloakGroupProvider  (first implementation)
    +-- LDAPGroupProvider      (future)
    +-- PingFederateProvider    (future)
    |
    v
External groups: ["DHA-Clinical", "PII-Authorized"]
    |
    v
Mapping table: external group name --> RAMPART group
    |
    v
Union of RAMPART policies from all matched groups
```

## Components

### 1. GroupProvider Interface

Abstract base class with a single method:

```python
class GroupProvider:
    async def lookup_groups(self, user_id: str) -> list[str]:
        """Return external group names for a user identifier (email)."""
```

- Input: user identifier (email address)
- Output: list of external group name strings
- Raises on provider unreachable/error (resolver handles fallback)
- User not found: returns empty list (not an error)

### 2. KeycloakGroupProvider

First implementation of GroupProvider.

- Authenticates via **client credentials** grant (service account) — RAMPART is a backend service
- Lookup flow:
  1. `GET /admin/realms/{realm}/users?email={email}` — find user by email
  2. `GET /admin/realms/{realm}/users/{user_id}/groups` — get user's group memberships
- Returns list of group `name` fields
- User not found: returns empty list
- Keycloak unreachable: raises exception

### 3. UserGroupResolver

Orchestrates cache, provider, and mapping resolution.

**In-memory cache** — dict keyed by email:

```python
{
  "jsmith@dha.mil": {
    "groups": ["DHA-Clinical", "PII-Authorized"],
    "fetched_at": 1748793600.0
  }
}
```

**Cache behavior:**
- Cache hit + fresh (within TTL): return groups immediately
- Cache miss or stale: synchronous provider lookup, cache result, return groups
- Max 20,000 entries. LRU eviction when exceeded (least recently fetched entry dropped)
- Per-process dict. No locking needed (uvicorn async workers in single process per container)

**JSON persistence** (`data/user_group_cache.json`):
- Written periodically (default every 60 seconds) only if dirty — avoids file thrashing
- Loaded on startup to warm the cache
- All loaded entries still subject to TTL — stale entries from a long shutdown refresh on first request
- Missing or corrupt file: start with empty cache (cold start)

**Cache flow on request:**
1. Email not in cache → provider lookup → cache → return groups
2. Email in cache + fresh → return groups
3. Email in cache + stale → provider lookup → update cache → return groups

### 4. Mapping Table

Stored in `data/group_mappings.json`:

```json
[
  {
    "id": "map-001",
    "external_group": "DHA-Clinical",
    "rampart_group_id": "clinical-staff",
    "enabled": true
  },
  {
    "id": "map-002",
    "external_group": "DHA-Admin",
    "rampart_group_id": "admin-unrestricted",
    "enabled": true
  }
]
```

**Fields:**
- `id` — unique identifier for the mapping entry
- `external_group` — exact group name as returned by the provider
- `rampart_group_id` — references an existing RAMPART group (which has policies assigned)
- `enabled` — allows disabling a mapping without deleting it

**Rules:**
- Multiple external groups can map to the same RAMPART group
- One external group maps to exactly one RAMPART group per mapping entry
- A user in multiple external groups gets the union of all their mapped RAMPART groups' policies
- Unmapped external groups are silently ignored

**Resolution example:**
- User `jsmith@dha.mil` → provider returns `["DHA-Clinical", "DHA-Admin"]`
- Mapping resolves to RAMPART groups `["clinical-staff", "admin-unrestricted"]`
- `clinical-staff` has policies `[no-pii, hipaa-compliance]`
- `admin-unrestricted` has policies `[prompt-injection-defense]`
- Union: `[no-pii, hipaa-compliance, prompt-injection-defense]`

### 5. Integration Point

**Modified function: `_resolve_policies()` in `main.py`**

New optional `user` parameter:

```python
def _resolve_policies(config, client, user=None):
    if user and config.user_group_resolver.enabled:
        try:
            policies = resolve_policies_for_user(config, user)
            if policies:  # mappings matched
                return policies
        except Exception:
            pass  # fall through to existing logic
    # Existing logic unchanged:
    # group enrollment -> direct assignment -> all enabled
```

No changes to PolicyEngine, LLM evaluator, or tracking. They already receive the resolved policy list. This is purely a change in how that list is determined.

The `user` field also still flows into tracking/logs and LLM evaluator prompts (wired up in prior commit).

## New Files

| File | Purpose |
|------|---------|
| `rampart/app/user_group_resolver.py` | Cache logic, TTL, JSON persistence, orchestrates provider + mapping |
| `rampart/app/group_providers/__init__.py` | GroupProvider base class |
| `rampart/app/group_providers/keycloak.py` | Keycloak Admin API implementation |
| `data/group_mappings.json` | Admin-managed external-to-RAMPART group mappings |
| `data/user_group_cache.json` | Cache persistence (auto-created at runtime) |

## Modified Files

| File | Change |
|------|--------|
| `rampart/app/config.py` | Add `UserGroupResolverConfig` with provider-specific sub-configs |
| `rampart/app/main.py` | Pass `user` to `_resolve_policies()`, add resolver fallback logic |
| `rampart/app/ui.py` | Add User Group Resolver section to `/ui/settings`, add `/ui/group-mappings` page |
| `rampart/app/mcp_server.py` | Add 4 mapping CRUD tools |
| `rampart/app/settings_store.py` | Persist resolver config alongside existing settings |

## Configuration

Added to `config.yaml` (or overridable via environment variables):

```yaml
user_group_resolver:
  enabled: false  # opt-in, disabled by default
  provider: "keycloak"
  cache_ttl_seconds: 900
  cache_max_size: 20000
  cache_persist_interval_seconds: 60
  cache_path: "data/user_group_cache.json"
  mappings_path: "data/group_mappings.json"
  keycloak:
    base_url: ""       # or RAMPART_KEYCLOAK_BASE_URL
    realm: ""          # or RAMPART_KEYCLOAK_REALM
    client_id: ""      # or RAMPART_KEYCLOAK_CLIENT_ID
    client_secret: ""  # or RAMPART_KEYCLOAK_CLIENT_SECRET
```

**Docker environment variables** for secrets:
- `RAMPART_KEYCLOAK_BASE_URL`
- `RAMPART_KEYCLOAK_REALM`
- `RAMPART_KEYCLOAK_CLIENT_ID`
- `RAMPART_KEYCLOAK_CLIENT_SECRET`

## Admin UI

### `/ui/settings` — User Group Resolver section

Added alongside existing LLM evaluator, vision, and upstream settings:
- Enable/disable toggle
- Provider dropdown (keycloak initially, extensible)
- Cache TTL (seconds)
- Cache max size
- Provider-specific fields (base URL, realm, client ID, client secret with masked input)
- "Test Connection" button — verifies RAMPART can authenticate with the provider

### `/ui/group-mappings` — Mapping table management

Dedicated page (like `/ui/groups` and `/ui/policies`):
- List all mappings with external group name, RAMPART group, enabled status
- Add new mapping (select external group name, select RAMPART group)
- Edit existing mapping
- Enable/disable toggle per mapping
- Delete mapping

### MCP Tools

4 new tools following existing patterns:
- `list_group_mappings` — list all mapping entries
- `create_group_mapping` — create a new mapping
- `update_group_mapping` — update an existing mapping
- `delete_group_mapping` — delete a mapping

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Provider unreachable on cache miss | Fall back to API key's assigned policies |
| Provider returns empty groups | Fall back to API key's assigned policies |
| No enabled mappings match the returned groups | Fall back to API key's assigned policies |
| User field not present in request | Existing policy resolution (unchanged) |
| Resolver disabled in config | Existing policy resolution (unchanged) |
| Cache persistence file corrupt/missing | Start with empty cache, build from live lookups |
| Cache full (20,000 entries) | LRU eviction of least recently fetched entry |

## Horizontal Scaling

Each container maintains its own in-memory cache and JSON persistence file. With TTL-based expiry, each container independently calls the provider on cache misses. At 20,000 users this is manageable. If duplicated provider calls become a problem at higher scale, a shared cache (Redis) is a clean upgrade path requiring changes only to the cache layer in `UserGroupResolver` — no changes to the provider interface, mapping logic, or policy resolution.

## Testing

- Unit tests for `UserGroupResolver` cache logic (hit, miss, stale, eviction, persistence)
- Unit tests for `KeycloakGroupProvider` with mocked HTTP responses
- Unit tests for mapping resolution (single group, multiple groups, no match, disabled mapping)
- Integration test for the full flow: user field → resolver → mapping → policy selection → fallback
- Test for precedence: resolver result replaces client policies; fallback uses client policies
