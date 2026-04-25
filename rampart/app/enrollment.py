from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from rampart.app.client_store import create_client, get_client, rotate_client_key
from rampart.app.config import get_config
from rampart.app.group_store import get_group_by_enrollment_key
from rampart.app.identity import consume_nonce
from rampart.app.ratelimit import check_rate_limit, rate_limit_response_json

router = APIRouter()


def _generate_client_id(email: str, device_id: str) -> str:
    name = email.split("@")[0] if email else "unknown"
    name = re.sub(r"[^a-zA-Z0-9]", "-", name)[:20]
    short_device = device_id[-8:] if device_id else "00000000"
    return f"ext-{name}-{short_device}"


@router.post("/v1/enroll")
async def enroll(request: Request) -> JSONResponse:
    if not check_rate_limit(request):
        return rate_limit_response_json()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON"}, status_code=400)

    enrollment_key = body.get("enrollment_key", "").strip()
    user_name = body.get("user_name", "").strip()
    user_email = body.get("user_email", "").strip()
    device_id = body.get("device_id", "").strip()
    identity_nonce = body.get("identity_nonce", "").strip()

    if not enrollment_key:
        return JSONResponse({"status": "error", "message": "Enrollment key is required"}, status_code=400)

    group = get_group_by_enrollment_key(enrollment_key)
    if not group:
        return JSONResponse({"status": "error", "message": "Invalid enrollment key"}, status_code=403)

    # If identity nonce provided, use verified CAC identity as client ID
    verified_identity = None
    if identity_nonce:
        result = consume_nonce(identity_nonce)
        if result:
            san, cn = result
            verified_identity = san or cn
            user_email = user_email or san
            user_name = user_name or cn

    config = get_config()
    # Use verified SAN as client ID if available, otherwise generate from email
    if verified_identity:
        client_id = re.sub(r"[^a-zA-Z0-9@._-]", "-", verified_identity)[:60]
    else:
        client_id = _generate_client_id(user_email, device_id)
    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"

    existing = get_client(client_id, config.clients.path)
    if existing:
        # Re-enrollment: rotate the key and update group
        created = rotate_client_key(client_id, config.clients.path)
        existing = get_client(client_id, config.clients.path)
        if existing:
            existing.group_id = group.id
            existing.policy_ids = []  # Policies come from group, not client
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

    # New enrollment — group_id set, no policy_ids copied
    created = create_client(
        client_id=client_id,
        customer=group.name,
        app_name="Chrome Extension",
        owner_name=user_name,
        owner_email=user_email,
        team=group.id,
        environment="extension",
        notes=f"Group: {group.id}",
        policy_ids=[],  # Policies resolved dynamically from group
        path=config.clients.path,
    )
    # Set group_id on the new client
    new_client = get_client(created.client.id, config.clients.path)
    if new_client:
        new_client.group_id = group.id
        from rampart.app.client_store import update_client
        update_client(new_client, config.clients.path)
    return JSONResponse({
        "status": "enrolled",
        "client_id": created.client.id,
        "api_key": created.api_key,
        "group_id": group.id,
        "group_name": group.name,
        "policies": group.policy_ids,
        "rampart_url": server_url,
    })
