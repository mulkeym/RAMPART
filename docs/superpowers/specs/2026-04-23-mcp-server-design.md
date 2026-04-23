# RAMPART MCP Server

## Overview

An MCP (Model Context Protocol) server interface for RAMPART, mounted as an SSE endpoint on the existing FastAPI app. Enables LLMs to manage policies, create and configure API key clients, assign policies to clients, evaluate prompts against the policy engine, and monitor violations — all through standard MCP tool calls.

## Goals

1. **LLM-driven administration** — An LLM can fully manage RAMPART: create policies, create clients, assign policies to clients
2. **Policy testing** — Evaluate prompts against policies without logging or sending to upstream
3. **Violation monitoring** — Query violation history for observability
4. **Secure access** — Dedicated admin API key separates management access from regular client access

## Constraints

- Uses the `mcp` Python library (FastMCP) for protocol compliance
- SSE transport mounted on the existing FastAPI app at `/mcp`
- Auth via dedicated admin API key (`RAMPART_MCP_ADMIN_KEY` env var)
- All tools call existing store functions — no new business logic
- Does not replace the REST API or UI — complements them

## Architecture

### Transport

SSE endpoint mounted on FastAPI at `/mcp`. The `mcp` library's `sse_app()` provides a Starlette-compatible ASGI app that handles the MCP protocol (JSON-RPC over SSE). This app is wrapped with auth middleware and mounted on the main FastAPI app.

### Auth

- Admin API key set via `RAMPART_MCP_ADMIN_KEY` environment variable
- If not set, the MCP endpoint returns 403 ("MCP is disabled — set RAMPART_MCP_ADMIN_KEY to enable")
- Clients pass the key as a query parameter: `/mcp/sse?admin_key=<key>`
- Key validated once at SSE connection establishment
- All tool calls on an authenticated connection are authorized (no per-tool permissions)

### Client Configuration

LLM clients (e.g., Claude Code) configure the MCP server as:
```json
{
  "mcpServers": {
    "rampart": {
      "url": "http://localhost:8080/mcp/sse?admin_key=your_key_here"
    }
  }
}
```

### File Structure

- `rampart/app/mcp_server.py` — MCP server with all 15 tools (new file)
- `rampart/app/main.py` — Mount MCP SSE app (modify)
- `rampart/app/config.py` — Add `mcp_admin_key` to AuthConfig with env var (modify)
- `pyproject.toml` — Add `mcp` dependency (modify)

### No Changes To

- Policy engine, LLM evaluator, proxy, sanitizer
- Client store, policy store, tracking
- UI, playground, settings

## Tools

### Policy Management

#### `list_policies`

**Parameters:** None

**Returns:** JSON array of policy summaries.

```json
[
  {
    "id": "no-credential-disclosure",
    "enabled": true,
    "severity": "high",
    "category": "credential_disclosure",
    "description": "Block requests asking for passwords, API keys, tokens, or secrets.",
    "action": "block",
    "check_count": 1
  }
]
```

#### `get_policy`

**Parameters:**
- `policy_id` (str, required)

**Returns:** Full policy including checks as YAML string.

```json
{
  "id": "no-credential-disclosure",
  "enabled": true,
  "severity": "high",
  "category": "credential_disclosure",
  "description": "Block requests asking for passwords, API keys, tokens, or secrets.",
  "action": "block",
  "checks_yaml": "- type: regex\n  pattern: '(?i)(api[_ -]?key|password|secret|token)...'"
}
```

Returns error text if policy not found.

#### `create_policy`

**Parameters:**
- `id` (str, required)
- `severity` (str, default "medium") — low/medium/high/critical
- `category` (str, default "policy")
- `description` (str, default "")
- `action` (str, default "block") — block/warn
- `checks_yaml` (str, required) — YAML list of check configs

**Returns:** The created policy summary. Error if ID already exists or checks_yaml is invalid.

Example `checks_yaml`:
```yaml
- type: regex
  pattern: "(?i)social.security"
- type: llm
  instruction: "Block requests that ask for personal health information"
```

#### `update_policy`

**Parameters:**
- `policy_id` (str, required)
- `severity` (str, optional)
- `category` (str, optional)
- `description` (str, optional)
- `action` (str, optional)
- `enabled` (bool, optional)
- `checks_yaml` (str, optional)

**Returns:** Updated policy summary. Only provided fields are changed. Error if not found.

#### `delete_policy`

**Parameters:**
- `policy_id` (str, required)

**Returns:** Confirmation message. Error if not found.

### Client Management

#### `list_clients`

**Parameters:** None

**Returns:** JSON array of client summaries (key_hash omitted).

```json
[
  {
    "id": "acme-prod",
    "customer": "acme",
    "app_name": "chatbot",
    "team": "platform",
    "environment": "production",
    "enabled": true,
    "policy_ids": ["no-credential-disclosure", "no-pii-data"],
    "last_used_at": "2026-04-23T..."
  }
]
```

#### `create_client`

**Parameters:**
- `client_id` (str, required)
- `customer` (str, required)
- `app_name` (str, required)
- `owner_name` (str, optional)
- `owner_email` (str, optional)
- `team` (str, optional)
- `environment` (str, default "production")
- `policy_ids` (list[str], optional) — policies to assign, empty means all enabled

**Returns:** Client summary + the raw API key (shown only this once). Error if ID already exists.

```json
{
  "client": { "id": "acme-prod", "customer": "acme", ... },
  "api_key": "rmp_live_abc123..."
}
```

#### `update_client`

**Parameters:**
- `client_id` (str, required)
- `customer` (str, optional)
- `app_name` (str, optional)
- `owner_name` (str, optional)
- `owner_email` (str, optional)
- `team` (str, optional)
- `environment` (str, optional)
- `notes` (str, optional)

**Returns:** Updated client summary. Only provided fields are changed. Error if not found.

#### `toggle_client`

**Parameters:**
- `client_id` (str, required)
- `enabled` (bool, required)

**Returns:** Confirmation with new status. Error if not found.

#### `rotate_client_key`

**Parameters:**
- `client_id` (str, required)

**Returns:** The new API key (shown only this once). Error if not found.

### Policy Assignment

#### `assign_policies`

**Parameters:**
- `client_id` (str, required)
- `policy_ids` (list[str], required) — empty list means "all enabled policies apply"

**Returns:** Updated client with new policy_ids. Error if client not found.

### Evaluation

#### `evaluate_prompt`

**Parameters:**
- `messages` (list[dict], required) — OpenAI-format messages array
- `policy_ids` (list[str], optional) — specific policies to evaluate against. If omitted, uses all enabled policies.

**Returns:** Evaluation results.

```json
{
  "decision": "fail",
  "violations": [
    {
      "policy_id": "no-credential-disclosure",
      "severity": "high",
      "category": "credential_disclosure",
      "message": "Request matched a blocked pattern.",
      "source": "deterministic",
      "path": "messages[1].content"
    }
  ],
  "sanitized_request": { "messages": [...] },
  "policies_evaluated": ["no-credential-disclosure", "no-pii-data"]
}
```

Does NOT log to evaluation events. Does NOT send to upstream LLM.

### Monitoring

#### `get_violations`

**Parameters:**
- `customer` (str, optional) — filter by customer
- `client_id` (str, optional) — filter by client
- `limit` (int, default 50) — max events to return

**Returns:** Recent violation events, most recent first.

```json
{
  "total_events": 142,
  "returned": 50,
  "events": [
    {
      "timestamp": "2026-04-23T...",
      "customer": "acme",
      "client_id": "acme-prod",
      "decision": "fail",
      "violation_count": 2,
      "violations": [
        {
          "policy_id": "no-credential-disclosure",
          "severity": "high",
          "category": "credential_disclosure",
          "source": "deterministic"
        }
      ]
    }
  ]
}
```

## Config Changes

Add to `AuthConfig` in `config.py`:

```python
mcp_admin_key: str = ""
```

Add env var override in `_apply_env_overrides`:

```python
auth.mcp_admin_key = os.getenv("RAMPART_MCP_ADMIN_KEY", auth.mcp_admin_key)
```

## Dependencies

Add to `pyproject.toml`:

```toml
mcp>=1.0
```

## Implementation Scope

### New Files
1. `rampart/app/mcp_server.py` — FastMCP server instance, 15 tool functions, auth middleware, SSE app factory

### Modified Files
2. `rampart/app/main.py` — Import and mount MCP SSE app
3. `rampart/app/config.py` — Add `mcp_admin_key` field and env var override
4. `pyproject.toml` — Add `mcp` dependency
