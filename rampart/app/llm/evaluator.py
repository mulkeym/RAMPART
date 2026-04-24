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
            f"You are a safety agent. Your task is to determine whether the user message "
            f"violates the following safety risk definition.\n\n"
            f"<risk_name>\n{policy.id}\n</risk_name>\n\n"
            f"<risk_definition>\n{risk_definition}\n</risk_definition>\n\n"
            f"<user_message>\n{text}\n</user_message>\n\n"
            f"Analyze the user message for the specified risk. "
            f"Answer with only 'Yes' if the message violates the risk definition, "
            f"or 'No' if it does not. Do not explain."
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
            async with httpx.AsyncClient(timeout=llm_config.timeout_seconds) as client:
                response = await client.post(
                    f"{llm_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

            body = response.json()
            import sys
            raw_content = (body.get("choices", [{}])[0].get("message") or {}).get("content", "")
            print(f"[GUARDIAN RAW] policy={policy.id} | content={repr(raw_content[:300])}", file=sys.stderr, flush=True)
            violates, confidence, raw_output = _parse_guardian_response(body, llm_config.confidence_threshold)
            print(f"[GUARDIAN] policy={policy.id} | violates={violates} | confidence={confidence:.3f} | parsed={raw_output[:100]}", file=sys.stderr, flush=True)
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
        # Still try logprobs for confidence, but we have the answer from the tag
        yes_prob = 1.0 if answer == "yes" else 0.0
        if logprobs_data and isinstance(logprobs_data, dict):
            for token_entry in (logprobs_data.get("content") or []):
                if not isinstance(token_entry, dict):
                    continue
                for entry in token_entry.get("top_logprobs", []):
                    t = entry.get("token", "").strip().lower()
                    if t == "yes":
                        yes_prob = math.exp(entry.get("logprob", -100))
                        break
                if yes_prob not in (0.0, 1.0):
                    break
        violates = answer == "yes" and yes_prob > threshold
        return violates, yes_prob, answer
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
