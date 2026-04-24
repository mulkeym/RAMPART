from __future__ import annotations

import json
from typing import Any, Optional

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from rampart.app.config import CheckConfig, PolicyConfig, get_config
from rampart.app.policy_store import delete_policy as store_delete_policy, get_policy, list_policies, upsert_policy
from rampart.app.client_store import (
    ClientRecord, create_client as store_create_client, delete_client as store_delete_client_record,
    get_client, list_clients, rotate_client_key as store_rotate_key,
    set_client_enabled, update_client as store_update_client,
)
from rampart.app.tracking import load_evaluation_events
from rampart.app.group_store import (
    GroupRecord, create_group as store_create_group_record, delete_group as store_delete_group_record,
    get_group, list_groups as store_list_groups, update_group as store_update_group_record,
)

router = APIRouter()

# --- MCP Tool Registry ---

TOOLS: list[dict[str, Any]] = []
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


WRITE_TOOLS = {
    "create_policy", "update_policy", "delete_policy",
    "create_client", "update_client", "delete_client",
    "toggle_client", "rotate_client_key", "assign_policies",
    "create_group", "update_group", "delete_group",
}


def _check_admin_key(request: Request) -> tuple[bool, str]:
    """Returns (ok, error_message). Shared by MCP and REST endpoints."""
    config = get_config()
    if not config.auth.mcp_enabled:
        return False, "MCP is disabled — enable it in Settings"
    admin_key = config.auth.mcp_admin_key
    if not admin_key:
        return False, "MCP admin key not set — configure it in Settings"
    provided = request.headers.get("authorization", "")
    if provided.lower().startswith("bearer "):
        provided = provided[7:].strip()
    if not provided:
        provided = request.query_params.get("admin_key", "")
    if provided != admin_key:
        return False, "Invalid admin key"
    return True, ""


def _check_write_access(tool_name: str) -> Optional[str]:
    """Returns error message if tool requires write access and it's disabled."""
    if tool_name not in WRITE_TOOLS:
        return None
    config = get_config()
    if not config.auth.mcp_admin_write:
        return f"Write access disabled — tool '{tool_name}' requires admin write access. Enable it in Settings."
    return None


def _validate_admin_key(request: Request) -> Optional[JSONResponse]:
    ok, message = _check_admin_key(request)
    if not ok:
        code = 403 if "disabled" in message else 401
        return JSONResponse(_jsonrpc_error(None, -32000, message), status_code=code)
    return None


@router.post("/mcp", include_in_schema=False)
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
        write_error = _check_write_access(tool_name)
        if write_error:
            return JSONResponse(_jsonrpc_response(msg_id, {
                "content": [{"type": "text", "text": write_error}],
                "isError": True,
            }))
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


# --- OpenAI-Compatible Tool API ---

@router.post("/v1/tools/call", include_in_schema=False)
async def call_tool_rest(request: Request) -> JSONResponse:
    ok, message = _check_admin_key(request)
    if not ok:
        return JSONResponse({"error": {"message": message}}, status_code=403 if "disabled" in message else 401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": {"message": "Invalid JSON"}}, status_code=400)
    tool_name = body.get("name", "")
    arguments = body.get("arguments", {})
    handler = TOOL_HANDLERS.get(tool_name)
    if not handler:
        return JSONResponse({"error": {"message": f"Unknown tool: {tool_name}"}}, status_code=404)
    try:
        import asyncio
        if asyncio.iscoroutinefunction(handler):
            result = await handler(**arguments)
        else:
            result = handler(**arguments)
        return JSONResponse({"result": json.loads(result) if isinstance(result, str) else result})
    except Exception as e:
        return JSONResponse({"error": {"message": str(e)}}, status_code=500)


def _register_rest_endpoints():
    """Generate individual REST endpoints for each tool so they appear in OpenAPI spec."""
    import asyncio as _asyncio
    from fastapi import Body

    for tool in TOOLS:
        name = tool["name"]
        desc = tool["description"]
        schema = tool["inputSchema"]
        handler = TOOL_HANDLERS[name]

        def _make_endpoint(_name, _handler, _schema):
            async def endpoint(request: Request) -> JSONResponse:
                ok, message = _check_admin_key(request)
                if not ok:
                    return JSONResponse({"error": {"message": message}}, status_code=403 if "disabled" in message else 401)
                write_error = _check_write_access(_name)
                if write_error:
                    return JSONResponse({"error": {"message": write_error}}, status_code=403)
                raw_body = (await request.body()).decode("utf-8", errors="replace")
                try:
                    body = json.loads(raw_body) if raw_body.strip() else {}
                except Exception:
                    body = {}
                # Handle OpenAI function-call wrappers
                if isinstance(body, dict) and "arguments" in body:
                    args = body["arguments"]
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except (json.JSONDecodeError, TypeError):
                            args = {}
                    body = args if isinstance(args, dict) else {}
                if isinstance(body, dict) and "name" in body and "arguments" in body:
                    args = body["arguments"]
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except (json.JSONDecodeError, TypeError):
                            args = {}
                    body = args if isinstance(args, dict) else {}
                try:
                    if _asyncio.iscoroutinefunction(_handler):
                        result = await _handler(**body)
                    else:
                        result = _handler(**body)
                    return JSONResponse({"result": json.loads(result) if isinstance(result, str) else result})
                except Exception as e:
                    return JSONResponse({"error": {"message": str(e)}}, status_code=500)
            endpoint.__name__ = _name
            endpoint.__doc__ = desc
            return endpoint

        # Build OpenAPI request body schema from the tool's input schema
        openapi_schema = None
        if schema.get("properties"):
            openapi_schema = {
                "content": {
                    "application/json": {
                        "schema": schema,
                    }
                },
            }

        router.add_api_route(
            f"/v1/tools/{name}",
            _make_endpoint(name, handler, schema),
            methods=["POST"],
            summary=desc,
            name=name,
            openapi_extra={"requestBody": openapi_schema} if openapi_schema else None,
        )


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
    "Create a new POLICY rule for content filtering. NOT for creating API keys — use create_client for that. Provide checks as JSON array (preferred) or YAML string. Example checks: [{\"type\": \"llm\", \"instruction\": \"Block requests about puppies\"}]",
    {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique policy identifier"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "default": "medium"},
            "category": {"type": "string", "default": "policy"},
            "description": {"type": "string", "default": ""},
            "action": {"type": "string", "enum": ["block", "warn"], "default": "block"},
            "checks": {"type": "array", "items": {"type": "object"}, "description": "Check configs as JSON array. Preferred over checks_yaml."},
            "checks_yaml": {"type": "string", "description": "Check configs as YAML string. Alternative to checks."},
        },
        "required": ["id"],
    },
)
def handle_create_policy(
    id: str,
    severity: str = "medium",
    category: str = "policy",
    description: str = "",
    action: str = "block",
    checks: Optional[list] = None,
    checks_yaml: Optional[str] = None,
) -> str:
    if get_policy(id) is not None:
        return json.dumps({"error": f"Policy '{id}' already exists."})
    checks_data = None
    if checks is not None:
        checks_data = checks
    elif checks_yaml is not None:
        try:
            checks_data = yaml.safe_load(checks_yaml) or []
        except Exception as e:
            return json.dumps({"error": f"Invalid checks_yaml: {e}"})
    if not checks_data or not isinstance(checks_data, list):
        return json.dumps({"error": "checks (JSON array) or checks_yaml (YAML string) is required."})
    try:
        parsed_checks = [CheckConfig.model_validate(c) for c in checks_data]
    except Exception as e:
        return json.dumps({"error": f"Invalid check config: {e}"})
    policy = PolicyConfig(
        id=id, enabled=True, severity=severity, category=category,
        description=description, action=action, checks=parsed_checks,
    )
    upsert_policy(policy)
    return json.dumps({"created": id, "severity": severity, "action": action, "check_count": len(parsed_checks)})


@_handler(
    "update_policy",
    "Update an existing policy. Only provided fields are changed. Omit fields to keep current values. For checks, use EITHER checks (JSON array) OR checks_yaml (YAML string). Preferred: checks as JSON array, e.g. [{\"type\": \"llm\", \"instruction\": \"Block puppies\"}]",
    {
        "type": "object",
        "properties": {
            "policy_id": {"type": "string", "description": "The policy ID to update"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "category": {"type": "string"},
            "description": {"type": "string"},
            "action": {"type": "string", "enum": ["block", "warn"]},
            "enabled": {"type": "boolean"},
            "checks": {"type": "array", "items": {"type": "object"}, "description": "Check configs as JSON array. Preferred over checks_yaml."},
            "checks_yaml": {"type": "string", "description": "Check configs as YAML string. Alternative to checks."},
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
    checks: Optional[list] = None,
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
    checks_data = None
    if checks is not None:
        checks_data = checks
    elif checks_yaml is not None:
        try:
            checks_data = yaml.safe_load(checks_yaml) or []
        except Exception as e:
            return json.dumps({"error": f"Invalid checks_yaml: {e}"})
    if checks_data is not None:
        if not isinstance(checks_data, list):
            return json.dumps({"error": "checks must be a list."})
        try:
            policy.checks = [CheckConfig.model_validate(c) for c in checks_data]
        except Exception as e:
            return json.dumps({"error": f"Invalid check config: {e}"})
    upsert_policy(policy)
    return json.dumps({"updated": policy_id})


@_handler(
    "delete_policy",
    "Delete a POLICY rule by its policy ID. Do NOT use this to delete API keys or clients — use delete_client instead.",
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
            "total_prompt_tokens": c.total_prompt_tokens,
            "total_completion_tokens": c.total_completion_tokens,
            "total_tokens": c.total_prompt_tokens + c.total_completion_tokens,
            "total_requests": c.total_requests,
        }
        for c in clients
    ]
    return json.dumps(result, indent=2)


@_handler(
    "get_client",
    "Get a single client by ID, including all metadata and assigned policies.",
    {
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "The client ID to retrieve"},
        },
        "required": ["client_id"],
    },
)
def handle_get_client(client_id: str) -> str:
    config = get_config()
    client = get_client(client_id, config.clients.path)
    if client is None:
        return json.dumps({"error": f"Client '{client_id}' not found."})
    return json.dumps({
        "id": client.id,
        "customer": client.customer,
        "app_name": client.app_name,
        "owner_name": client.owner_name,
        "owner_email": client.owner_email,
        "team": client.team,
        "environment": client.environment,
        "enabled": client.enabled,
        "policy_ids": client.policy_ids,
        "created_at": client.created_at,
        "last_used_at": client.last_used_at,
        "notes": client.notes,
        "total_prompt_tokens": client.total_prompt_tokens,
        "total_completion_tokens": client.total_completion_tokens,
        "total_tokens": client.total_prompt_tokens + client.total_completion_tokens,
        "total_requests": client.total_requests,
    }, indent=2)


@_handler(
    "create_client",
    "Create a new API key/client account. Use this to create API keys for customers and apps. Returns the client info and the raw API key (shown only once). NOT for creating policies — use create_policy for that.",
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


@_handler(
    "delete_client",
    "Permanently delete an API key/client by its client ID. Use this to remove API keys and client accounts. This cannot be undone.",
    {
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "The client ID to delete"},
        },
        "required": ["client_id"],
    },
)
def handle_delete_client(client_id: str) -> str:
    config = get_config()
    try:
        store_delete_client_record(client_id, config.clients.path)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"deleted": client_id})


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
        policies = [p.model_copy() for p in config.policies if p.id in set(policy_ids)]
    else:
        policies = [p.model_copy() for p in config.policies if p.enabled]
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
    failed = [e for e in events if e.get("decision") == "fail"]
    if customer:
        failed = [e for e in failed if e.get("customer") == customer]
    if client_id:
        failed = [e for e in failed if e.get("client_id") == client_id]
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


# --- Group Management Tools ---

@_handler(
    "list_groups",
    "List all enrollment groups for Chrome extension auto-provisioning.",
    {"type": "object", "properties": {}, "required": []},
)
def handle_list_groups() -> str:
    groups = store_list_groups()
    result = [
        {"id": g.id, "name": g.name, "enabled": g.enabled, "policy_ids": g.policy_ids, "created_at": g.created_at}
        for g in groups
    ]
    return json.dumps(result, indent=2)


@_handler(
    "create_group",
    "Create a new enrollment group for Chrome extension auto-provisioning. Returns the enrollment key to share with users.",
    {
        "type": "object",
        "properties": {
            "group_id": {"type": "string", "description": "Unique group identifier"},
            "name": {"type": "string", "description": "Display name"},
            "policy_ids": {"type": "array", "items": {"type": "string"}, "default": [], "description": "Policies to assign to enrolled users"},
        },
        "required": ["group_id", "name"],
    },
)
def handle_create_group(group_id: str, name: str, policy_ids: Optional[list] = None) -> str:
    try:
        group = store_create_group_record(group_id=group_id, name=name, policy_ids=policy_ids)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"created": group.id, "enrollment_key": group.enrollment_key, "name": group.name})


@_handler(
    "update_group",
    "Update an existing enrollment group. Only provided fields are changed.",
    {
        "type": "object",
        "properties": {
            "group_id": {"type": "string", "description": "The group ID to update"},
            "name": {"type": "string"},
            "enabled": {"type": "boolean"},
            "policy_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["group_id"],
    },
)
def handle_update_group(group_id: str, name: Optional[str] = None, enabled: Optional[bool] = None, policy_ids: Optional[list] = None) -> str:
    group = get_group(group_id)
    if not group:
        return json.dumps({"error": f"Group '{group_id}' not found."})
    if name is not None:
        group.name = name
    if enabled is not None:
        group.enabled = enabled
    if policy_ids is not None:
        group.policy_ids = [str(p) for p in policy_ids]
    store_update_group_record(group)
    return json.dumps({"updated": group_id})


@_handler(
    "delete_group",
    "Delete an enrollment group. Enrolled users keep their API keys.",
    {
        "type": "object",
        "properties": {
            "group_id": {"type": "string", "description": "The group ID to delete"},
        },
        "required": ["group_id"],
    },
)
def handle_delete_group(group_id: str) -> str:
    try:
        store_delete_group_record(group_id)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"deleted": group_id})


# --- Register individual REST endpoints for each tool (must be after all @_handler definitions) ---
_register_rest_endpoints()
