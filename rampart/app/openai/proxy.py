from __future__ import annotations

from typing import Any, AsyncIterator, Optional

import httpx

from rampart.app.config import UpstreamConfig
from rampart.app.tls import tls_verify

# Shared connection pool — reused across requests
_client: Optional[httpx.AsyncClient] = None


def _get_client(timeout: float = 120.0) -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            verify=tls_verify(),
            timeout=timeout,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
    return _client


async def proxy_chat_completion(config: UpstreamConfig, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    headers = {"content-type": "application/json"}
    if config.api_key:
        headers["authorization"] = f"Bearer {config.api_key}"
    client = _get_client(config.timeout_seconds)
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


async def proxy_chat_completion_stream(config: UpstreamConfig, payload: dict[str, Any]) -> AsyncIterator[bytes]:
    """Stream SSE response from upstream LLM."""
    headers = {"content-type": "application/json"}
    if config.api_key:
        headers["authorization"] = f"Bearer {config.api_key}"
    client = _get_client(config.timeout_seconds)
    async with client.stream(
        "POST",
        f"{config.base_url.rstrip('/')}/chat/completions",
        json=payload,
        headers=headers,
    ) as response:
        async for chunk in response.aiter_bytes():
            yield chunk


def openai_policy_error(message: str, violations: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "error": {
            "message": message,
            "type": "policy_violation",
            "code": "rampart_policy_violation",
            "violations": violations,
        }
    }
