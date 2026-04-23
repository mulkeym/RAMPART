import asyncio

import httpx

from rampart.app.config import AppConfig, CheckConfig, LlmEvaluatorConfig, PolicyConfig
from rampart.app.llm.evaluator import LlmEvaluator
from rampart.app.llm.prompts import build_policy_check_prompt


def test_policy_check_prompt_includes_plain_text_rule():
    policy = PolicyConfig(
        id="no-pii",
        severity="high",
        category="pii",
        checks=[CheckConfig(type="llm", instruction="Block requests that contain or ask for PII or PHI.")],
    )

    prompt = build_policy_check_prompt("{}", policy, policy.checks[0])

    assert "exactly one policy" in prompt
    assert "Policy ID: no-pii" in prompt
    assert "Block requests that contain or ask for PII or PHI." in prompt
    assert "Do not require exact keyword matches." in prompt


def test_llm_evaluator_applies_each_llm_check(monkeypatch):
    captured_payloads = []

    async def fake_post(self, url, json):
        captured_payloads.append(json)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"violates": true, "message": "Request asks for PII by context."}'
                        }
                    }
                ]
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    config = AppConfig(
        llm_evaluator=LlmEvaluatorConfig(enabled=True),
        policies=[
            PolicyConfig(
                id="context-pii",
                severity="high",
                category="pii_phi",
                checks=[CheckConfig(type="llm", instruction="Block requests that ask for PII or PHI.")],
            ),
            PolicyConfig(
                id="regex-only",
                checks=[CheckConfig(type="regex", pattern="secret")],
            ),
        ],
    )

    violations = asyncio.run(LlmEvaluator(config).evaluate({
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "Who owns SSN 123-45-1234?"}],
    }))

    assert len(captured_payloads) == 1
    assert violations[0].policy_id == "context-pii"
    assert violations[0].message == "Request asks for PII by context."
