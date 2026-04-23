from __future__ import annotations

from typing import Any

import httpx

from rampart.app.config import UpstreamConfig


async def proxy_chat_completion(config: UpstreamConfig, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    headers = {"content-type": "application/json"}
    if config.api_key:
        headers["authorization"] = f"Bearer {config.api_key}"
    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        response = await client.post(
            f"{config.base_url.rstrip('/')}/chat/completions",
            json=payload,
            headers=headers,
        )
    try:
        body = response.json()
    except ValueError:
        body = {
            "error": {
                "message": response.text,
                "type": "upstream_error",
                "code": response.status_code,
            }
        }
    return body, response.status_code


def openai_policy_error(message: str, violations: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "error": {
            "message": message,
            "type": "policy_violation",
            "code": "rampart_policy_violation",
            "violations": violations,
        }
    }
