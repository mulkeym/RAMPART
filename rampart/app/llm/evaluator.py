from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from rampart.app.config import AppConfig, CheckConfig, PolicyConfig
from rampart.app.llm.prompts import build_policy_check_prompt
from rampart.app.models import Violation


class LlmEvaluator:
    def __init__(self, config: AppConfig, policies: Optional[list[PolicyConfig]] = None):
        self.config = config
        self.policies = policies if policies is not None else config.policies

    async def evaluate(self, request: dict[str, Any]) -> list[Violation]:
        llm_config = self.config.llm_evaluator
        if not llm_config.enabled:
            return []

        policies_with_llm_checks = [
            (policy, check)
            for policy in self.policies
            if policy.enabled
            for check in policy.checks
            if check.type == "llm"
        ]
        if not policies_with_llm_checks:
            return []

        request_json = json.dumps(_strip_image_data(request), sort_keys=True, ensure_ascii=True)
        violations: list[Violation] = []
        for policy, check in policies_with_llm_checks:
            result = await self._evaluate_policy_check(request_json, policy, check)
            violations.extend(result)
        return violations

    async def _evaluate_policy_check(self, request_json: str, policy: PolicyConfig, check: CheckConfig) -> list[Violation]:
        llm_config = self.config.llm_evaluator
        prompt = build_policy_check_prompt(request_json, policy, check)
        payload = {
            "model": llm_config.model,
            "messages": [
                {"role": "system", "content": "Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }

        try:
            async with httpx.AsyncClient(timeout=llm_config.timeout_seconds) as client:
                response = await client.post(
                    f"{llm_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]
            data = json.loads(_strip_json_fence(content))
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            if not llm_config.fail_closed_on_error:
                return []
            return [
                Violation(
                    policy_id="llm-evaluator-unavailable",
                    severity="critical",
                    category="evaluator_error",
                    message=f"LLM evaluator failed: {error.__class__.__name__}",
                    source="llm",
                )
            ]

        if not data.get("violates"):
            return []
        return [
            Violation(
                policy_id=policy.id,
                severity=policy.severity,
                category=policy.category,
                message=data.get("message") or "LLM evaluator reported a policy violation.",
                source="llm",
            )
        ]


def _strip_image_data(request: dict[str, Any]) -> dict[str, Any]:
    """Remove base64 image data from the request before sending to the evaluator LLM.

    The evaluator checks text-based policies and does not need raw image bytes.
    Replacing them with a placeholder avoids exceeding token limits.
    """
    from copy import deepcopy

    stripped = deepcopy(request)
    for message in stripped.get("messages") or []:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict):
                continue
            image_url = part.get("image_url")
            if isinstance(image_url, dict) and isinstance(image_url.get("url"), str):
                url = image_url["url"]
                if url.startswith("data:"):
                    image_url["url"] = "[base64 image omitted]"
    return stripped


def _strip_json_fence(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```json"):
        stripped = stripped.removeprefix("```json").strip()
    if stripped.startswith("```"):
        stripped = stripped.removeprefix("```").strip()
    if stripped.endswith("```"):
        stripped = stripped.removesuffix("```").strip()
    return stripped
