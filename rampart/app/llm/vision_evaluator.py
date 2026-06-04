from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from rampart.app.config import AppConfig, CheckConfig, PolicyConfig
from rampart.app.llm.prompts import build_vision_check_prompt
from rampart.app.models import Violation
from rampart.app.tls import tls_verify


# Shared connection pool — reuses TCP/TLS connections across requests
_http_pool: Optional[httpx.AsyncClient] = None
_http_pool_base_url: str = ""


def _get_http_pool(base_url: str, timeout: float, verify_ssl) -> httpx.AsyncClient:
    global _http_pool, _http_pool_base_url
    if _http_pool is None or _http_pool_base_url != base_url:
        if _http_pool is not None:
            _http_pool = None
        _http_pool = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_ssl,
            limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
        )
        _http_pool_base_url = base_url
    return _http_pool


class VisionEvaluator:
    def __init__(self, config: AppConfig, policies: Optional[list[PolicyConfig]] = None):
        self.config = config
        self.policies = policies if policies is not None else config.policies

    async def evaluate(self, request: dict[str, Any]) -> tuple[list[Violation], list[str]]:
        images = _extract_images(request)
        if not images:
            return [], []

        vision_config = self.config.vision_evaluator
        if not vision_config.enabled:
            return [], ["Vision evaluator not configured — images were not evaluated against policies."]

        checks = [
            (policy, check)
            for policy in self.policies
            if policy.enabled
            for check in policy.checks
            if check.type == "llm" and not check.skip_vision
        ]
        if not checks:
            return [], []

        violations: list[Violation] = []
        for policy, check in checks:
            for msg_idx, part_idx, image_url in images:
                result = await self._evaluate_image(image_url, msg_idx, part_idx, policy, check)
                violations.extend(result)
        return violations, []

    async def _evaluate_image(
        self,
        image_url: str,
        msg_idx: int,
        part_idx: int,
        policy: PolicyConfig,
        check: CheckConfig,
    ) -> list[Violation]:
        vision_config = self.config.vision_evaluator
        prompt = build_vision_check_prompt(policy, check)
        payload = {
            "model": vision_config.model,
            "messages": [
                {"role": "system", "content": "Return only valid JSON."},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": image_url}},
                    ],
                },
            ],
            "temperature": 0,
        }

        try:
            client = _get_http_pool(vision_config.base_url, vision_config.timeout_seconds, tls_verify())
            response = await client.post(
                f"{vision_config.base_url.rstrip('/')}/chat/completions",
                json=payload,
            )
            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]
            data = json.loads(_strip_json_fence(content))
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            if not vision_config.fail_closed_on_error:
                return []
            return [
                Violation(
                    policy_id="vision-evaluator-unavailable",
                    severity="critical",
                    category="evaluator_error",
                    message=f"Vision evaluator failed: {error.__class__.__name__}",
                    source="vision",
                )
            ]

        if not data.get("violates"):
            return []
        return [
            Violation(
                policy_id=policy.id,
                severity=policy.severity,
                category=policy.category,
                message=data.get("message") or "Vision evaluator reported a policy violation.",
                source="vision",
                path=f"messages[{msg_idx}].content[{part_idx}]",
            )
        ]


def _extract_images(request: dict[str, Any]) -> list[tuple[int, int, str]]:
    """Extract all image URLs from the request. Returns (msg_idx, part_idx, url) tuples."""
    images = []
    for msg_idx, message in enumerate(request.get("messages") or []):
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for part_idx, part in enumerate(content):
            if not isinstance(part, dict):
                continue
            if part.get("type") == "image_url":
                image_url = part.get("image_url")
                if isinstance(image_url, dict) and isinstance(image_url.get("url"), str):
                    images.append((msg_idx, part_idx, image_url["url"]))
    return images


def _strip_json_fence(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```json"):
        stripped = stripped.removeprefix("```json").strip()
    if stripped.startswith("```"):
        stripped = stripped.removeprefix("```").strip()
    if stripped.endswith("```"):
        stripped = stripped.removesuffix("```").strip()
    return stripped
