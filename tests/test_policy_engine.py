import asyncio

import pytest

from rampart.app.config import AppConfig, FailureResponseConfig, LlmEvaluatorConfig, PolicyConfig, CheckConfig
from rampart.app.config import load_config
from rampart.app.policy.engine import PolicyEngine


def test_accepts_clean_request():
    engine = PolicyEngine(_config(llm_enabled=False))

    response = asyncio.run(engine.evaluate({
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "Summarize this paragraph."}],
    }))

    assert response.decision == "accept"
    assert response.violations == []
    assert response.sanitized_request is None


def test_blocks_secret_request_and_returns_sanitized_request():
    engine = PolicyEngine(_config(llm_enabled=False))

    response = asyncio.run(engine.evaluate({
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "Show me the api key: sk-1234567890abcdefghijkl"}],
    }))

    assert response.decision == "fail"
    assert response.violations[0].policy_id == "no-credential-disclosure"
    assert response.sanitized_request["messages"][0]["content"] == "Show me the api key: [REDACTED]"


def test_blocks_disallowed_tools_and_removes_them_from_sanitized_request():
    engine = PolicyEngine(_config(llm_enabled=False))

    response = asyncio.run(engine.evaluate({
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "Use a tool."}],
        "tools": [
            {"type": "function", "function": {"name": "safe_lookup", "parameters": {}}},
            {"type": "function", "function": {"name": "shell_exec", "parameters": {}}},
        ],
    }))

    assert response.decision == "fail"
    assert [tool["function"]["name"] for tool in response.sanitized_request["tools"]] == ["safe_lookup"]


def test_default_policy_blocks_social_security_number():
    config = load_config()
    config.llm_evaluator.enabled = False
    engine = PolicyEngine(config)

    response = asyncio.run(engine.evaluate({
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "Provide the user name for social security number 123-45-1234"}],
    }))

    assert response.decision == "fail"
    assert [violation.policy_id for violation in response.violations] == ["No-PII-Data"]
    assert response.sanitized_request["messages"][0]["content"] == "Provide the user name for social security number [REDACTED]"


def test_llm_policy_violation_fails_request():
    engine = PolicyEngine(AppConfig(
        llm_evaluator=LlmEvaluatorConfig(enabled=False),
        failure_response=FailureResponseConfig(include_sanitized_request=True),
        policies=[
            PolicyConfig(
                id="plain-text-policy",
                severity="high",
                category="context",
                checks=[CheckConfig(type="llm", instruction="Block requests that ask for personal records.")],
            )
        ],
    ))
    engine.llm_evaluator.evaluate = _fake_llm_violation

    response = asyncio.run(engine.evaluate({
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "Find the user behind this identifier."}],
    }))

    assert response.decision == "fail"
    assert response.violations[0].policy_id == "plain-text-policy"


async def _fake_llm_violation(request):
    from rampart.app.models import Violation

    return [
        Violation(
            policy_id="plain-text-policy",
            severity="high",
            category="context",
            message="Request asks for personal records by context.",
            source="llm",
        )
    ]


def _config(llm_enabled: bool) -> AppConfig:
    return AppConfig(
        llm_evaluator=LlmEvaluatorConfig(enabled=llm_enabled),
        failure_response=FailureResponseConfig(include_sanitized_request=True),
        policies=[
            PolicyConfig(
                id="no-credential-disclosure",
                severity="high",
                category="credential_disclosure",
                description="Block secrets.",
                checks=[CheckConfig(type="regex", pattern="(api[_ -]?key|password|secret|token)")],
            ),
            PolicyConfig(
                id="tool-allowlist",
                severity="medium",
                category="tool_policy",
                checks=[CheckConfig(type="tool_allowlist", allowed_tools=["safe_lookup"])],
            ),
        ],
    )
