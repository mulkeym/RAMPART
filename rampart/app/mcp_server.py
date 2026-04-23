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
