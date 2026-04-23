from __future__ import annotations

from rampart.app.config import CheckConfig, PolicyConfig


def build_policy_check_prompt(request_json: str, policy: PolicyConfig, check: CheckConfig) -> str:
    plain_text_rule = check.instruction or policy.description
    return f"""You are RAMPART, a strict API request firewall evaluator.

Evaluate the OpenAI-compatible API request against exactly one policy.

Policy ID: {policy.id}
Severity: {policy.severity}
Category: {policy.category}
Action: {policy.action}
Description: {policy.description}

Plain-text policy rule:
{plain_text_rule}

Apply the plain-text policy rule to the request context. Consider user messages,
system messages, tool definitions, requested tool calls, and the apparent intent
of the request. Do not require exact keyword matches. If the request violates
the rule by meaning or context, mark it as a violation.

Return only valid JSON matching this shape:
{{
  "violates": true,
  "message": "short reason"
}}

If there is no violation, return {{"violates": false, "message": ""}}.

Request:
{request_json}
"""


def build_vision_check_prompt(policy: PolicyConfig, check: CheckConfig) -> str:
    instruction = check.instruction or policy.description
    return f"""You are RAMPART, a strict API request firewall evaluator.

Evaluate the attached image against exactly one policy.

Policy ID: {policy.id}
Severity: {policy.severity}
Category: {policy.category}
Description: {policy.description}

Plain-text policy rule:
{instruction}

Examine the image for any content that violates the rule.
Consider text visible in the image, objects, scenes, and context.

Return only valid JSON matching this shape:
{{"violates": true, "message": "short reason"}}

If there is no violation, return {{"violates": false, "message": ""}}.
"""
