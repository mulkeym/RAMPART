from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from rampart.app.config import AppConfig, CheckConfig, PolicyConfig
from rampart.app.llm.prompts import build_policy_check_prompt
from rampart.app.models import Violation
from rampart.app.tls import tls_verify


class LlmEvaluator:
    def __init__(self, config: AppConfig, policies: Optional[list[PolicyConfig]] = None):
        self.config = config
        self.policies = policies if policies is not None else config.policies

    async def evaluate(self, request: dict[str, Any], stage: str = "pre") -> list[Violation]:
        llm_config = self.config.llm_evaluator
        if not llm_config.enabled:
            return []

        policies_with_llm_checks = [
            (policy, check)
            for policy in self.policies
            if policy.enabled
            for check in policy.checks
            if check.type == "llm" and _check_matches_stage(check, stage)
        ]
        if not policies_with_llm_checks:
            return []

        if llm_config.mode == "granite-guardian":
            return await self._evaluate_guardian(request, policies_with_llm_checks)
        return await self._evaluate_standard(request, policies_with_llm_checks)

    async def sanitize(self, request: dict[str, Any], violations: list[Violation]) -> Optional[dict[str, Any]]:
        """Ask the LLM to rewrite the request to remove violating content."""
        llm_config = self.config.llm_evaluator
        if not llm_config.enabled:
            return None
        from rampart.app.llm.prompts import build_sanitize_prompt
        request_json = json.dumps(_strip_image_data(request), sort_keys=True, ensure_ascii=True)
        violation_dicts = [{"policy_id": v.policy_id, "message": v.message} for v in violations]
        prompt = build_sanitize_prompt(request_json, violation_dicts)
        payload = {
            "model": llm_config.model,
            "messages": [
                {"role": "system", "content": "Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }
        try:
            async with httpx.AsyncClient(timeout=llm_config.timeout_seconds, verify=tls_verify()) as client:
                response = await client.post(
                    f"{llm_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return json.loads(_strip_json_fence(content))
        except Exception:
            return None

    async def evaluate_response(self, response_text: str) -> list[Violation]:
        """Evaluate an LLM response against post-stage policies."""
        if not self.config.llm_evaluator.post_llm_enabled:
            return []
        request = {"messages": [{"role": "assistant", "content": response_text}]}
        return await self.evaluate(request, stage="post")

    async def _evaluate_standard(self, request: dict[str, Any], checks: list) -> list[Violation]:
        import asyncio
        request_json = json.dumps(_strip_image_data(request), sort_keys=True, ensure_ascii=True)
        results = await asyncio.gather(*(
            self._evaluate_standard_check(request_json, policy, check)
            for policy, check in checks
        ))
        violations: list[Violation] = []
        for result in results:
            violations.extend(result)
        return violations

    async def _evaluate_standard_check(self, request_json: str, policy: PolicyConfig, check: CheckConfig) -> list[Violation]:
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
            async with httpx.AsyncClient(timeout=llm_config.timeout_seconds, verify=tls_verify()) as client:
                response = await client.post(
                    f"{llm_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]
            data = _parse_llm_json(content)
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

    async def _evaluate_guardian(self, request: dict[str, Any], checks: list) -> list[Violation]:
        import asyncio
        text_parts = []
        for message in request.get("messages") or []:
            content = message.get("content")
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        text_parts.append(part["text"])
        user_text = "\n".join(text_parts)
        if not user_text.strip():
            return []

        import asyncio
        results = await asyncio.gather(*(
            self._evaluate_guardian_check(user_text, policy, check)
            for policy, check in checks
        ))
        violations: list[Violation] = []
        for result in results:
            violations.extend(result)
        return violations

    async def _evaluate_guardian_check(self, text: str, policy: PolicyConfig, check: CheckConfig) -> list[Violation]:
        llm_config = self.config.llm_evaluator
        risk_definition = check.instruction or policy.description
        guardian_prompt = (
            f"Task: Binary text classification.\n\n"
            f"Label the user message as 'Yes' or 'No' based on the following rule ONLY.\n\n"
            f"Rule: {risk_definition}\n\n"
            f"User message: {text}\n\n"
            f"Important: You are checking ONLY the rule above. "
            f"If the user message is about a completely different topic than the rule describes, answer 'No'. "
            f"For example, if the rule is about 'puppies' and the message is about 'bombs', answer 'No' "
            f"because bombs are not puppies, regardless of how dangerous the message is.\n\n"
            f"Classification (Yes or No):"
        )
        payload = {
            "model": llm_config.model,
            "messages": [
                {"role": "user", "content": guardian_prompt},
            ],
            "logprobs": True,
            "top_logprobs": 5,
            "max_tokens": 100,
            "temperature": 0,
        }

        try:
            async with httpx.AsyncClient(timeout=llm_config.timeout_seconds, verify=tls_verify()) as client:
                response = await client.post(
                    f"{llm_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

            body = response.json()
            violates, confidence, raw_output = _parse_guardian_response(body, llm_config.confidence_threshold)
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as error:
            if not llm_config.fail_closed_on_error:
                return []
            return [
                Violation(
                    policy_id="llm-evaluator-unavailable",
                    severity="critical",
                    category="evaluator_error",
                    message=f"Granite Guardian failed: {error.__class__.__name__}",
                    source="llm",
                )
            ]

        if not violates:
            return []
        return [
            Violation(
                policy_id=policy.id,
                severity=policy.severity,
                category=policy.category,
                message=f"Guardian: {raw_output.strip()} (confidence: {confidence:.2f})",
                source="llm",
            )
        ]


def _check_matches_stage(check: CheckConfig, stage: str) -> bool:
    check_stage = check.stage or "both"
    if check_stage == "both":
        return True
    return check_stage == stage


def _parse_guardian_response(body: dict, threshold: float) -> tuple[bool, float, str]:
    """Parse Granite Guardian response. Returns (violates, confidence, raw_output)."""
    import math
    import re

    choices = body.get("choices", [])
    if not choices:
        return False, 0.0, ""

    choice = choices[0]
    content = (choice.get("message") or {}).get("content", "").strip()
    # Strip <think>...</think> blocks and <score>...</score> wrapper if present
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    logprobs_data = choice.get("logprobs")
    score_match = re.search(r"<score>\s*(yes|no)\s*</score>", content, re.IGNORECASE)
    if score_match:
        answer = score_match.group(1).strip().lower()
        # The score tag is the definitive answer — trust it directly
        violates = answer == "yes"
        confidence = 1.0 if violates else 0.0
        return violates, confidence, answer
    if logprobs_data and isinstance(logprobs_data, dict):
        token_logprobs = logprobs_data.get("content", [])
        # Skip past any <think> tokens to find the actual Yes/No token
        for token_entry in token_logprobs:
            if not isinstance(token_entry, dict):
                continue
            main_token = token_entry.get("token", "").strip().lower()
            if main_token in ("<think>", "</think>", "") or len(main_token) > 5:
                continue
            top = token_entry.get("top_logprobs", [])
            yes_prob = 0.0
            for entry in top:
                token = entry.get("token", "").strip().lower()
                if token == "yes":
                    yes_prob = math.exp(entry.get("logprob", -100))
                    break
            if yes_prob > 0:
                return yes_prob > threshold, yes_prob, content
            # Check if main token is "no" — definitive pass
            if main_token == "no":
                return False, 0.0, content
            # Check if main token is "yes" — definitive fail
            if main_token == "yes":
                return True, 1.0, content

    # Fallback: check text content if no logprobs
    violates = content.lower().startswith("yes")
    return violates, 1.0 if violates else 0.0, content


def _strip_image_data(request: dict[str, Any]) -> dict[str, Any]:
    """Remove base64 image data and the user field from the request before sending to the evaluator LLM.

    The evaluator checks text-based policies and does not need raw image bytes.
    The user field (email/username) is stripped to prevent false PII violations.
    """
    from copy import deepcopy

    stripped = deepcopy(request)
    stripped.pop("user", None)
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


def _parse_llm_json(content: str) -> dict:
    """Parse JSON from LLM response, handling common formatting issues."""
    import re
    stripped = _strip_json_fence(content)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    # Fix missing commas between fields: }"field" → },"field"
    fixed = re.sub(r'("\s*)\n(\s*")', r'\1,\n\2', stripped)
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass
    # Last resort: extract violates boolean
    violates_match = re.search(r'"violates"\s*:\s*(true|false)', stripped, re.IGNORECASE)
    message_match = re.search(r'"message"\s*:\s*"([^"]*)"', stripped)
    if violates_match:
        return {
            "violates": violates_match.group(1).lower() == "true",
            "message": message_match.group(1) if message_match else "",
        }
    raise json.JSONDecodeError("Cannot parse LLM response", stripped, 0)


def _strip_json_fence(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```json"):
        stripped = stripped.removeprefix("```json").strip()
    if stripped.startswith("```"):
        stripped = stripped.removeprefix("```").strip()
    if stripped.endswith("```"):
        stripped = stripped.removesuffix("```").strip()
    return stripped
