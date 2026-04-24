from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from rampart.app.client_store import create_client, get_client, rotate_client_key
from rampart.app.config import get_config
from rampart.app.group_store import get_group_by_enrollment_key

router = APIRouter()


def _generate_client_id(email: str, device_id: str) -> str:
    name = email.split("@")[0] if email else "unknown"
    name = re.sub(r"[^a-zA-Z0-9]", "-", name)[:20]
    short_device = device_id[-8:] if device_id else "00000000"
    return f"ext-{name}-{short_device}"


@router.post("/v1/enroll")
async def enroll(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON"}, status_code=400)

    enrollment_key = body.get("enrollment_key", "").strip()
    user_name = body.get("user_name", "").strip()
    user_email = body.get("user_email", "").strip()
    device_id = body.get("device_id", "").strip()

    if not enrollment_key:
        return JSONResponse({"status": "error", "message": "Enrollment key is required"}, status_code=400)

    group = get_group_by_enrollment_key(enrollment_key)
    if not group:
        return JSONResponse({"status": "error", "message": "Invalid enrollment key"}, status_code=403)

    config = get_config()
    client_id = _generate_client_id(user_email, device_id)
    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"

    existing = get_client(client_id, config.clients.path)
    if existing:
        # Re-enrollment: rotate the key
        created = rotate_client_key(client_id, config.clients.path)
        # Update policies to match current group
        existing = get_client(client_id, config.clients.path)
        if existing:
            existing.policy_ids = group.policy_ids
            existing.notes = f"Group: {group.id}"
            from rampart.app.client_store import update_client
            update_client(existing, config.clients.path)
        return JSONResponse({
            "status": "re-enrolled",
            "client_id": client_id,
            "api_key": created.api_key,
            "group_id": group.id,
            "group_name": group.name,
            "policies": group.policy_ids,
            "rampart_url": server_url,
        })

    # New enrollment
    created = create_client(
        client_id=client_id,
        customer=group.name,
        app_name="Chrome Extension",
        owner_name=user_name,
        owner_email=user_email,
        team=group.id,
        environment="extension",
        notes=f"Group: {group.id}",
        policy_ids=group.policy_ids,
        path=config.clients.path,
    )
    return JSONResponse({
        "status": "enrolled",
        "client_id": created.client.id,
        "api_key": created.api_key,
        "group_id": group.id,
        "group_name": group.name,
        "policies": group.policy_ids,
        "rampart_url": server_url,
    })
