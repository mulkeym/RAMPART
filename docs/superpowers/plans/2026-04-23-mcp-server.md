# RAMPART MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an MCP (Model Context Protocol) server to RAMPART that exposes 15 tools for policy management, client management, policy assignment, evaluation, and violation monitoring via Streamable HTTP transport.

**Architecture:** Hand-rolled MCP protocol implementation (no `mcp` library — requires Python 3.10+, project uses 3.9). A new `rampart/app/mcp_server.py` implements JSON-RPC over HTTP POST at `/mcp`. Auth via `RAMPART_MCP_ADMIN_KEY` env var. All tools are thin wrappers around existing store functions.

**Tech Stack:** Python 3.9 / FastAPI, JSON-RPC 2.0, Streamable HTTP MCP transport (POST endpoint), existing RAMPART stores and policy engine.

**Spec:** `docs/superpowers/specs/2026-04-23-mcp-server-design.md`

---

### Task 1: Add mcp_admin_key to config

**Files:**
- Modify: `rampart/app/config.py:23-31` (AuthConfig)
- Modify: `rampart/app/config.py:119-133` (_apply_env_overrides)

- [ ] **Step 1: Add `mcp_admin_key` field to AuthConfig**

In `rampart/app/config.py`, add the field to the `AuthConfig` class:

```python
class AuthConfig(BaseModel):
    admin_username: str = "admin"
    admin_password_hash: str = ""
    auth_state_path: str = "data/auth.json"
    session_secret: str = "change-me"
    session_cookie_name: str = "rampart_session"
    session_max_age_seconds: int = 28800
    secure_cookies: bool = False
    audit_log_path: str = "logs/audit.jsonl"
    mcp_admin_key: str = ""
```

- [ ] **Step 2: Add env var override in `_apply_env_overrides`**

Add this line after the `auth.secure_cookies` line (after line 126):

```python
    auth.mcp_admin_key = os.getenv("RAMPART_MCP_ADMIN_KEY", auth.mcp_admin_key)
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from rampart.app.config import get_config; c = get_config(); print('mcp_admin_key:', repr(c.auth.mcp_admin_key))"`
Expected: `mcp_admin_key: ''`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/config.py
git commit -m "feat(mcp): add mcp_admin_key to AuthConfig with env var override"
```

---

### Task 2: Create mcp_server.py with protocol handler and policy tools

**Files:**
- Create: `rampart/app/mcp_server.py`

This task creates the MCP server module with the JSON-RPC protocol handler, auth validation, and the 5 policy management tools. Client tools, evaluation, and monitoring are added in subsequent tasks.

- [ ] **Step 1: Create `rampart/app/mcp_server.py`**

```python
from __future__ import annotations

import json
from typing import Any, Optional

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from rampart.app.config import CheckConfig, PolicyConfig, get_config
from rampart.app.policy_store import delete_policy as store_delete_policy, get_policy, list_policies, upsert_policy

router = APIRouter()

# --- MCP Tool Registry ---

TOOLS: list[dict[str, Any]] = []


def _register_tool(name: str, description: str, input_schema: dict[str, Any]):
    """Decorator factory to register MCP tools."""
    def decorator(func):
        TOOLS.append({
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        })
        func._mcp_tool_name = name
        return func
    return decorator


TOOL_HANDLERS: dict[str, Any] = {}


def _handler(name: str, description: str, input_schema: dict[str, Any]):
    """Register a tool and its handler."""
    def decorator(func):
        TOOLS.append({
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        })
        TOOL_HANDLERS[name] = func
        return func
    return decorator


# --- JSON-RPC Protocol ---

def _jsonrpc_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _jsonrpc_error(id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def _validate_admin_key(request: Request) -> Optional[JSONResponse]:
    config = get_config()
    admin_key = config.auth.mcp_admin_key
    if not admin_key:
        return JSONResponse(
            _jsonrpc_error(None, -32000, "MCP is disabled — set RAMPART_MCP_ADMIN_KEY to enable"),
            status_code=403,
        )
    provided = request.headers.get("authorization", "")
    if provided.lower().startswith("bearer "):
        provided = provided[7:].strip()
    if not provided:
        provided = request.query_params.get("admin_key", "")
    if provided != admin_key:
        return JSONResponse(
            _jsonrpc_error(None, -32000, "Invalid MCP admin key"),
            status_code=401,
        )
    return None


@router.post("/mcp")
async def mcp_endpoint(request: Request) -> JSONResponse:
    auth_error = _validate_admin_key(request)
    if auth_error:
        return auth_error

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_jsonrpc_error(None, -32700, "Parse error"))

    method = body.get("method", "")
    msg_id = body.get("id")
    params = body.get("params", {})

    if method == "initialize":
        return JSONResponse(_jsonrpc_response(msg_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "rampart", "version": "0.1.0"},
        }))

    if method == "notifications/initialized":
        return JSONResponse(_jsonrpc_response(msg_id, None))

    if method == "tools/list":
        return JSONResponse(_jsonrpc_response(msg_id, {"tools": TOOLS}))

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return JSONResponse(_jsonrpc_error(msg_id, -32601, f"Unknown tool: {tool_name}"))
        try:
            import asyncio
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**arguments)
            else:
                result = handler(**arguments)
            return JSONResponse(_jsonrpc_response(msg_id, {
                "content": [{"type": "text", "text": result if isinstance(result, str) else json.dumps(result, indent=2)}],
            }))
        except Exception as e:
            return JSONResponse(_jsonrpc_response(msg_id, {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True,
            }))

    return JSONResponse(_jsonrpc_error(msg_id, -32601, f"Method not found: {method}"))


# --- Policy Management Tools ---

@_handler(
    "list_policies",
    "List all configured policies with their ID, status, severity, category, description, action, and check count.",
    {"type": "object", "properties": {}, "required": []},
)
def handle_list_policies() -> str:
    policies = list_policies()
    result = [
        {
            "id": p.id,
            "enabled": p.enabled,
            "severity": p.severity,
            "category": p.category,
            "description": p.description,
            "action": p.action,
            "check_count": len(p.checks),
        }
        for p in policies
    ]
    return json.dumps(result, indent=2)


@_handler(
    "get_policy",
    "Get a single policy by ID, including its full checks configuration as YAML.",
    {
        "type": "object",
        "properties": {
            "policy_id": {"type": "string", "description": "The policy ID to retrieve"},
        },
        "required": ["policy_id"],
    },
)
def handle_get_policy(policy_id: str) -> str:
    policy = get_policy(policy_id)
    if policy is None:
        return json.dumps({"error": f"Policy '{policy_id}' not found."})
    checks_yaml = yaml.safe_dump(
        [check.model_dump(exclude_none=True) for check in policy.checks],
        sort_keys=False,
    ).strip()
    return json.dumps({
        "id": policy.id,
        "enabled": policy.enabled,
        "severity": policy.severity,
        "category": policy.category,
        "description": policy.description,
        "action": policy.action,
        "checks_yaml": checks_yaml,
    }, indent=2)


@_handler(
    "create_policy",
    "Create a new policy. Checks are provided as a YAML string. Example checks_yaml: '- type: regex\\n  pattern: \"(?i)password\"'",
    {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique policy identifier"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "default": "medium"},
            "category": {"type": "string", "default": "policy"},
            "description": {"type": "string", "default": ""},
            "action": {"type": "string", "enum": ["block", "warn"], "default": "block"},
            "checks_yaml": {"type": "string", "description": "YAML list of check configs"},
        },
        "required": ["id", "checks_yaml"],
    },
)
def handle_create_policy(
    id: str,
    checks_yaml: str,
    severity: str = "medium",
    category: str = "policy",
    description: str = "",
    action: str = "block",
) -> str:
    if get_policy(id) is not None:
        return json.dumps({"error": f"Policy '{id}' already exists."})
    try:
        checks_data = yaml.safe_load(checks_yaml) or []
        if not isinstance(checks_data, list):
            return json.dumps({"error": "checks_yaml must be a YAML list."})
        checks = [CheckConfig.model_validate(c) for c in checks_data]
    except Exception as e:
        return json.dumps({"error": f"Invalid checks_yaml: {e}"})
    policy = PolicyConfig(
        id=id, enabled=True, severity=severity, category=category,
        description=description, action=action, checks=checks,
    )
    upsert_policy(policy)
    return json.dumps({"created": id, "severity": severity, "action": action, "check_count": len(checks)})


@_handler(
    "update_policy",
    "Update an existing policy. Only provided fields are changed. Omit fields to keep their current values.",
    {
        "type": "object",
        "properties": {
            "policy_id": {"type": "string", "description": "The policy ID to update"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "category": {"type": "string"},
            "description": {"type": "string"},
            "action": {"type": "string", "enum": ["block", "warn"]},
            "enabled": {"type": "boolean"},
            "checks_yaml": {"type": "string", "description": "YAML list of check configs"},
        },
        "required": ["policy_id"],
    },
)
def handle_update_policy(
    policy_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    description: Optional[str] = None,
    action: Optional[str] = None,
    enabled: Optional[bool] = None,
    checks_yaml: Optional[str] = None,
) -> str:
    policy = get_policy(policy_id)
    if policy is None:
        return json.dumps({"error": f"Policy '{policy_id}' not found."})
    if severity is not None:
        policy.severity = severity
    if category is not None:
        policy.category = category
    if description is not None:
        policy.description = description
    if action is not None:
        policy.action = action
    if enabled is not None:
        policy.enabled = enabled
    if checks_yaml is not None:
        try:
            checks_data = yaml.safe_load(checks_yaml) or []
            if not isinstance(checks_data, list):
                return json.dumps({"error": "checks_yaml must be a YAML list."})
            policy.checks = [CheckConfig.model_validate(c) for c in checks_data]
        except Exception as e:
            return json.dumps({"error": f"Invalid checks_yaml: {e}"})
    upsert_policy(policy)
    return json.dumps({"updated": policy_id})


@_handler(
    "delete_policy",
    "Delete a policy by ID.",
    {
        "type": "object",
        "properties": {
            "policy_id": {"type": "string", "description": "The policy ID to delete"},
        },
        "required": ["policy_id"],
    },
)
def handle_delete_policy(policy_id: str) -> str:
    if get_policy(policy_id) is None:
        return json.dumps({"error": f"Policy '{policy_id}' not found."})
    store_delete_policy(policy_id)
    return json.dumps({"deleted": policy_id})
```

- [ ] **Step 2: Verify imports**

Run: `python3 -c "from rampart.app.mcp_server import router, TOOLS; print(f'{len(TOOLS)} tools registered')"`
Expected: `5 tools registered`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/mcp_server.py
git commit -m "feat(mcp): create mcp_server.py with protocol handler and policy tools"
```

---

### Task 3: Add client management and policy assignment tools

**Files:**
- Modify: `rampart/app/mcp_server.py`

- [ ] **Step 1: Add client imports at the top of mcp_server.py**

Add to the imports section:

```python
from rampart.app.client_store import (
    ClientRecord, create_client as store_create_client, get_client, list_clients,
    rotate_client_key as store_rotate_key, set_client_enabled, update_client as store_update_client,
)
```

- [ ] **Step 2: Add client management tools**

Append these tool handlers after the policy tools:

```python
# --- Client Management Tools ---

@_handler(
    "list_clients",
    "List all API key clients with their ID, customer, app, team, status, assigned policies, and last used timestamp.",
    {"type": "object", "properties": {}, "required": []},
)
def handle_list_clients() -> str:
    config = get_config()
    clients = list_clients(config.clients.path)
    result = [
        {
            "id": c.id,
            "customer": c.customer,
            "app_name": c.app_name,
            "team": c.team,
            "environment": c.environment,
            "enabled": c.enabled,
            "policy_ids": c.policy_ids,
            "last_used_at": c.last_used_at,
        }
        for c in clients
    ]
    return json.dumps(result, indent=2)


@_handler(
    "create_client",
    "Create a new API key client. Returns the client info and the raw API key (shown only once).",
    {
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "Unique client identifier"},
            "customer": {"type": "string", "description": "Customer name"},
            "app_name": {"type": "string", "description": "Application name"},
            "owner_name": {"type": "string", "default": ""},
            "owner_email": {"type": "string", "default": ""},
            "team": {"type": "string", "default": ""},
            "environment": {"type": "string", "default": "production"},
            "policy_ids": {"type": "array", "items": {"type": "string"}, "default": [], "description": "Policies to assign. Empty means all enabled policies apply."},
        },
        "required": ["client_id", "customer", "app_name"],
    },
)
def handle_create_client(
    client_id: str,
    customer: str,
    app_name: str,
    owner_name: str = "",
    owner_email: str = "",
    team: str = "",
    environment: str = "production",
    policy_ids: Optional[list] = None,
) -> str:
    config = get_config()
    try:
        created = store_create_client(
            client_id=client_id, customer=customer, app_name=app_name,
            owner_name=owner_name, owner_email=owner_email, team=team,
            environment=environment, policy_ids=policy_ids,
            path=config.clients.path,
        )
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({
        "client": {
            "id": created.client.id, "customer": created.client.customer,
            "app_name": created.client.app_name, "team": created.client.team,
            "environment": created.client.environment, "enabled": created.client.enabled,
            "policy_ids": created.client.policy_ids,
        },
        "api_key": created.api_key,
    }, indent=2)


@_handler(
    "update_client",
    "Update an existing client. Only provided fields are changed.",
    {
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "The client ID to update"},
            "customer": {"type": "string"},
            "app_name": {"type": "string"},
            "owner_name": {"type": "string"},
            "owner_email": {"type": "string"},
            "team": {"type": "string"},
            "environment": {"type": "string"},
            "notes": {"type": "string"},
        },
        "required": ["client_id"],
    },
)
def handle_update_client(
    client_id: str,
    customer: Optional[str] = None,
    app_name: Optional[str] = None,
    owner_name: Optional[str] = None,
    owner_email: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    notes: Optional[str] = None,
) -> str:
    config = get_config()
    client = get_client(client_id, config.clients.path)
    if client is None:
        return json.dumps({"error": f"Client '{client_id}' not found."})
    if customer is not None:
        client.customer = customer
    if app_name is not None:
        client.app_name = app_name
    if owner_name is not None:
        client.owner_name = owner_name
    if owner_email is not None:
        client.owner_email = owner_email
    if team is not None:
        client.team = team
    if environment is not None:
        client.environment = environment
    if notes is not None:
        client.notes = notes
    store_update_client(client, config.clients.path)
    return json.dumps({"updated": client_id})


@_handler(
    "toggle_client",
    "Enable or disable an API key client.",
    {
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "The client ID to toggle"},
            "enabled": {"type": "boolean", "description": "True to enable, false to disable"},
        },
        "required": ["client_id", "enabled"],
    },
)
def handle_toggle_client(client_id: str, enabled: bool) -> str:
    config = get_config()
    try:
        set_client_enabled(client_id, enabled, config.clients.path)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"client_id": client_id, "enabled": enabled})


@_handler(
    "rotate_client_key",
    "Rotate the API key for a client. Returns the new key (shown only once). The old key is invalidated.",
    {
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "The client ID whose key to rotate"},
        },
        "required": ["client_id"],
    },
)
def handle_rotate_client_key(client_id: str) -> str:
    config = get_config()
    try:
        created = store_rotate_key(client_id, config.clients.path)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"client_id": client_id, "api_key": created.api_key})


# --- Policy Assignment ---

@_handler(
    "assign_policies",
    "Set which policies apply to a client. Pass an empty list to use all enabled policies.",
    {
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "The client ID to assign policies to"},
            "policy_ids": {"type": "array", "items": {"type": "string"}, "description": "List of policy IDs. Empty means all enabled policies apply."},
        },
        "required": ["client_id", "policy_ids"],
    },
)
def handle_assign_policies(client_id: str, policy_ids: list) -> str:
    config = get_config()
    client = get_client(client_id, config.clients.path)
    if client is None:
        return json.dumps({"error": f"Client '{client_id}' not found."})
    client.policy_ids = [str(pid) for pid in policy_ids]
    store_update_client(client, config.clients.path)
    return json.dumps({"client_id": client_id, "policy_ids": client.policy_ids})
```

- [ ] **Step 3: Verify tool count**

Run: `python3 -c "from rampart.app.mcp_server import TOOLS; print(f'{len(TOOLS)} tools registered')"`
Expected: `12 tools registered`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/mcp_server.py
git commit -m "feat(mcp): add client management and policy assignment tools"
```

---

### Task 4: Add evaluation and monitoring tools

**Files:**
- Modify: `rampart/app/mcp_server.py`

- [ ] **Step 1: Add evaluation and tracking imports**

Add to the imports section of `mcp_server.py`:

```python
from rampart.app.tracking import load_evaluation_events
```

- [ ] **Step 2: Add evaluate_prompt tool**

Append after the policy assignment tools:

```python
# --- Evaluation ---

@_handler(
    "evaluate_prompt",
    "Evaluate a prompt against policies without logging or sending to upstream. Returns decision, violations, and sanitized request.",
    {
        "type": "object",
        "properties": {
            "messages": {
                "type": "array",
                "items": {"type": "object"},
                "description": "OpenAI-format messages array, e.g. [{\"role\": \"user\", \"content\": \"hello\"}]",
            },
            "policy_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific policy IDs to evaluate. Omit to use all enabled policies.",
            },
        },
        "required": ["messages"],
    },
)
async def handle_evaluate_prompt(messages: list, policy_ids: Optional[list] = None) -> str:
    from rampart.app.policy.engine import PolicyEngine

    config = get_config()
    if policy_ids:
        policies = [p for p in config.policies if p.id in set(policy_ids)]
    else:
        policies = [p for p in config.policies if p.enabled]
    # Force all selected policies to enabled for evaluation
    for p in policies:
        p.enabled = True

    engine = PolicyEngine(config, policies)
    openai_request = {"messages": messages}
    response = await engine.evaluate(openai_request)

    result = {
        "decision": response.decision,
        "violations": [
            {
                "policy_id": v.policy_id,
                "severity": v.severity,
                "category": v.category,
                "message": v.message,
                "source": v.source,
                "path": v.path,
            }
            for v in response.violations
        ],
        "policies_evaluated": [p.id for p in policies],
    }
    if response.sanitized_request:
        result["sanitized_request"] = response.sanitized_request
    return json.dumps(result, indent=2)
```

- [ ] **Step 3: Add get_violations tool**

```python
# --- Monitoring ---

@_handler(
    "get_violations",
    "Query recent violation events. Optionally filter by customer or client ID.",
    {
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Filter by customer name"},
            "client_id": {"type": "string", "description": "Filter by client ID"},
            "limit": {"type": "integer", "default": 50, "description": "Max events to return (default 50)"},
        },
        "required": [],
    },
)
def handle_get_violations(
    customer: Optional[str] = None,
    client_id: Optional[str] = None,
    limit: int = 50,
) -> str:
    config = get_config()
    events = load_evaluation_events(config.tracking.log_path)
    # Filter to failed events only
    failed = [e for e in events if e.get("decision") == "fail"]
    if customer:
        failed = [e for e in failed if e.get("customer") == customer]
    if client_id:
        failed = [e for e in failed if e.get("client_id") == client_id]
    # Most recent first
    failed.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    limited = failed[:limit]
    result = {
        "total_events": len(failed),
        "returned": len(limited),
        "events": [
            {
                "timestamp": e.get("timestamp"),
                "customer": e.get("customer"),
                "client_id": e.get("client_id"),
                "decision": e.get("decision"),
                "violation_count": len(e.get("violations", [])),
                "violations": e.get("violations", []),
            }
            for e in limited
        ],
    }
    return json.dumps(result, indent=2)
```

- [ ] **Step 4: Verify tool count**

Run: `python3 -c "from rampart.app.mcp_server import TOOLS; print(f'{len(TOOLS)} tools registered'); print([t['name'] for t in TOOLS])"`
Expected: `14 tools registered` with all tool names listed.

Note: The spec lists 15 tools but `enable_policy`/`disable_policy` are merged into `update_policy` (with `enabled` param), and `enable_client`/`disable_client` are merged into `toggle_client`. This gives us 13 distinct tools. Let me count: list_policies, get_policy, create_policy, update_policy, delete_policy (5) + list_clients, create_client, update_client, toggle_client, rotate_client_key (5) + assign_policies (1) + evaluate_prompt (1) + get_violations (1) = 13 tools.

- [ ] **Step 5: Commit**

```bash
git add rampart/app/mcp_server.py
git commit -m "feat(mcp): add evaluate_prompt and get_violations tools"
```

---

### Task 5: Register MCP router in main.py

**Files:**
- Modify: `rampart/app/main.py:13-22`

- [ ] **Step 1: Add MCP router import and registration**

In `rampart/app/main.py`, add the import after the playground router import:

```python
from rampart.app.mcp_server import router as mcp_router
```

Add the router registration after the playground router:

```python
app.include_router(mcp_router)
```

- [ ] **Step 2: Verify the route is registered**

Run: `python3 -c "from rampart.app.main import app; print([r.path for r in app.routes if hasattr(r, 'path') and 'mcp' in r.path])"`
Expected: `['/mcp']`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/main.py
git commit -m "feat(mcp): register MCP router in main app"
```

---

### Task 6: Run tests and verify no regressions

**Files:**
- Read: `tests/`

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All previously-passing tests still pass (35 pass, 2 pre-existing failures in test_gateway.py).

- [ ] **Step 2: Test MCP endpoint manually**

Run the app and test with curl:

```bash
# Test without admin key (should get 403)
curl -s -X POST http://localhost:8080/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | python3 -m json.tool

# Set admin key and test
export RAMPART_MCP_ADMIN_KEY=test-key-123

# Restart app, then test initialize
curl -s -X POST http://localhost:8080/mcp -H "Content-Type: application/json" -H "Authorization: Bearer test-key-123" -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | python3 -m json.tool

# Test tools/list
curl -s -X POST http://localhost:8080/mcp -H "Content-Type: application/json" -H "Authorization: Bearer test-key-123" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | python3 -m json.tool

# Test list_policies
curl -s -X POST http://localhost:8080/mcp -H "Content-Type: application/json" -H "Authorization: Bearer test-key-123" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_policies","arguments":{}}}' | python3 -m json.tool
```

- [ ] **Step 3: Commit (if fixes needed)**

```bash
git add -A
git commit -m "fix: resolve MCP integration issues"
```
