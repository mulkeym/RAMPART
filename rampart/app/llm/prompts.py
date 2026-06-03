from __future__ import annotations

from rampart.app.config import CheckConfig, PolicyConfig


def build_policy_check_prompt(request_json: str, policy: PolicyConfig, check: CheckConfig, user: str | None = None) -> str:
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
system messages, tool definitions, requested tool calls, the end-user identity
(if provided), and the apparent intent of the request.
Do not require exact keyword matches. If the request violates
the rule by meaning or context, mark it as a violation.

Note: Requests may contain "[base64 image omitted]" placeholders where images were
attached. This is normal multimodal content and should NOT be treated as suspicious
encoding, injection, or obfuscation.

Return only valid JSON matching this shape:
{{
  "violates": true,
  "message": "short reason"
}}

If there is no violation, return {{"violates": false, "message": ""}}.

Request:
{request_json}
"""


def build_batch_policy_check_prompt(request_json: str, policies: list[tuple]) -> str:
    """Build a single prompt that checks multiple policies at once. Returns only IDs of violating policies."""
    policy_list = "\n".join(
        f"- {policy.id}: {check.instruction or policy.description}"
        for policy, check in policies
    )
    return f"""You are RAMPART, a strict API request firewall evaluator.

You MUST check the request against EVERY policy below independently.
A request can violate multiple policies at the same time.
Do not stop after finding the first violation — check ALL policies.

Policies:
{policy_list}

Request:
{request_json}

For EACH policy above, decide independently if the request violates it.
A single request can match zero, one, or many policies simultaneously.

Return only valid JSON — an array of ALL violated policy IDs.
If no policies are violated, return an empty array.

Example with multiple violations: ["no-pii", "harmful-content", "no-puppies"]
Example with one violation: ["no-pii"]
Example with no violations: []
"""


def build_sanitize_prompt(request_json: str, violations: list[dict]) -> str:
    violation_list = "\n".join(
        f"- [{v.get('policy_id', 'unknown')}] {v.get('message', 'Policy violation')}"
        for v in violations
    )
    return f"""You are RAMPART, a prompt sanitization engine.

The following OpenAI-compatible API request was blocked because it violates one or more policies.
Your job is to rewrite ONLY the user message content to remove the violating material while
preserving the original intent as much as possible. Do not change system messages, roles, model,
or any other fields.

Policy violations found:
{violation_list}

Original request:
{request_json}

Return ONLY the complete rewritten JSON request (valid JSON, same structure). Replace or remove
the content that caused each violation. Keep everything else unchanged. If the entire user message
is a violation, replace it with "[Content removed by RAMPART policy]".

Return only the JSON — no explanation, no markdown fences.
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
