from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

from rampart.app.config import AppConfig, PolicyConfig
from rampart.app.llm.evaluator import LlmEvaluator
from rampart.app.llm.vision_evaluator import VisionEvaluator
from rampart.app.models import EvaluationResponse, Violation
from rampart.app.openai.compat import extract_model, extract_tool_names, iter_message_text
from rampart.app.policy.sanitizer import sanitize_request


class PolicyEngine:
    def __init__(self, config: AppConfig, policies: Optional[list[PolicyConfig]] = None):
        self.config = config
        self.policies = policies if policies is not None else config.policies
        self.llm_evaluator = LlmEvaluator(config, self.policies)
        self.vision_evaluator = VisionEvaluator(config, self.policies)

    async def evaluate(self, request: dict[str, Any]) -> EvaluationResponse:
        deterministic_violations, denied_tools = self._evaluate_deterministic(request)
        llm_violations, (vision_violations, vision_warnings) = await asyncio.gather(
            self.llm_evaluator.evaluate(request),
            self.vision_evaluator.evaluate(request),
        )
        violations = _dedupe_violations(deterministic_violations + llm_violations + vision_violations)
        decision = "fail" if any(_is_blocking(v, self.policies) for v in violations) else "accept"
        sanitized = None
        if violations and self.config.failure_response.include_sanitized_request:
            sanitized = sanitize_request(request, denied_tools=denied_tools)
        return EvaluationResponse(
            decision=decision,
            violations=violations,
            sanitized_request=sanitized,
            warnings=vision_warnings,
        )

    async def post_evaluate(self, response_text: str) -> list[Violation]:
        """Evaluate an upstream LLM response against post-stage policies."""
        return await self.llm_evaluator.evaluate_response(response_text)

    def _evaluate_deterministic(self, request: dict[str, Any]) -> tuple[list[Violation], set[str]]:
        violations: list[Violation] = []
        denied_tools: set[str] = set()
        for policy in self.policies:
            if not policy.enabled:
                continue
            for check in policy.checks:
                if check.type == "regex" and check.pattern:
                    violations.extend(_regex_violations(request, policy, check.pattern))
                elif check.type == "tool_allowlist" and check.allowed_tools is not None:
                    found = set(extract_tool_names(request))
                    disallowed = found - set(check.allowed_tools)
                    denied_tools.update(disallowed)
                    for tool_name in sorted(disallowed):
                        violations.append(_violation(policy, f"Tool '{tool_name}' is not allowed.", "tools"))
                elif check.type == "tool_denylist" and check.denied_tools is not None:
                    found = set(extract_tool_names(request))
                    denied = found & set(check.denied_tools)
                    denied_tools.update(denied)
                    for tool_name in sorted(denied):
                        violations.append(_violation(policy, f"Tool '{tool_name}' is denied.", "tools"))
                elif check.type == "model_allowlist" and check.allowed_models is not None:
                    model = extract_model(request)
                    if model and model not in set(check.allowed_models):
                        violations.append(_violation(policy, f"Model '{model}' is not allowed.", "model"))
                elif check.type == "max_chars" and check.max_chars is not None:
                    for path, text in iter_message_text(request):
                        if len(text) > check.max_chars:
                            violations.append(_violation(policy, f"Message exceeds {check.max_chars} characters.", path))
        return violations, denied_tools


def _regex_violations(request: dict[str, Any], policy: PolicyConfig, pattern: str) -> list[Violation]:
    compiled = re.compile(pattern, re.IGNORECASE)
    violations: list[Violation] = []
    for path, text in iter_message_text(request):
        if compiled.search(text):
            violations.append(_violation(policy, policy.description or "Request matched a blocked pattern.", path))
    return violations


def _violation(policy: PolicyConfig, message: str, path: Optional[str] = None) -> Violation:
    return Violation(
        policy_id=policy.id,
        severity=policy.severity,
        category=policy.category,
        message=message,
        path=path,
    )


def _is_blocking(violation: Violation, policies: list[PolicyConfig]) -> bool:
    for policy in policies:
        if policy.id == violation.policy_id:
            return policy.action == "block"
    return True


def _dedupe_violations(violations: list[Violation]) -> list[Violation]:
    seen: set[tuple[str, Optional[str], str]] = set()
    deduped: list[Violation] = []
    for violation in violations:
        key = (violation.policy_id, violation.path, violation.message)
        if key not in seen:
            deduped.append(violation)
            seen.add(key)
    return deduped
