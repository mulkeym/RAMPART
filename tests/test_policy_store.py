from rampart.app.config import AppConfig, CheckConfig, FailureResponseConfig, LlmEvaluatorConfig, PolicyConfig, load_config, save_config
from rampart.app.policy_store import delete_policy, get_policy, list_policies, upsert_policy


def test_save_and_load_config_roundtrip(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    config = AppConfig(
        llm_evaluator=LlmEvaluatorConfig(enabled=False),
        failure_response=FailureResponseConfig(include_sanitized_request=True),
        policies=[
            PolicyConfig(
                id="test-policy",
                severity="high",
                category="test",
                description="A test policy.",
                checks=[CheckConfig(type="regex", pattern="secret")],
            )
        ],
    )

    save_config(config, policy_path)
    loaded = load_config(policy_path)

    assert loaded.policies[0].id == "test-policy"
    assert loaded.policies[0].checks[0].pattern == "secret"


def test_upsert_and_delete_policy(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    save_config(AppConfig(llm_evaluator=LlmEvaluatorConfig(enabled=False)), policy_path)

    upsert_policy(
        PolicyConfig(
            id="tool-policy",
            category="tool_policy",
            checks=[CheckConfig(type="tool_allowlist", allowed_tools=["lookup"])],
        ),
        policy_path,
    )

    assert [policy.id for policy in list_policies(policy_path)] == ["tool-policy"]
    assert get_policy("tool-policy", policy_path).checks[0].allowed_tools == ["lookup"]

    upsert_policy(
        PolicyConfig(
            id="tool-policy",
            category="tool_policy",
            checks=[CheckConfig(type="tool_allowlist", allowed_tools=["lookup", "search"])],
        ),
        policy_path,
    )

    assert len(list_policies(policy_path)) == 1
    assert get_policy("tool-policy", policy_path).checks[0].allowed_tools == ["lookup", "search"]

    delete_policy("tool-policy", policy_path)

    assert list_policies(policy_path) == []
