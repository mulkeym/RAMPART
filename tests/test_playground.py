import json
import pytest
from rampart.app.playground import _build_openai_request


def test_prompt_scenario_builds_messages():
    form = {
        "scenario_type": "prompt",
        "msg_count": "1",
        "msg_role_0": "user",
        "msg_text_0": "Hello world",
        "model_override": "gpt-4",
        "user_field": "alice@test.com",
    }
    req = _build_openai_request(form)
    assert req["messages"] == [{"role": "user", "content": "Hello world"}]
    assert req["model"] == "gpt-4"
    assert req["user"] == "alice@test.com"


def test_prompt_scenario_no_user():
    form = {
        "scenario_type": "prompt",
        "msg_count": "1",
        "msg_role_0": "user",
        "msg_text_0": "Hello",
        "user_field": "",
    }
    req = _build_openai_request(form)
    assert "user" not in req


def test_tools_scenario_builds_tools():
    form = {
        "scenario_type": "tools",
        "tool_names": "get_weather, execute_code, send_email",
        "msg_count": "1",
        "msg_role_0": "user",
        "msg_text_0": "What is the weather?",
        "model_override": "",
        "user_field": "",
    }
    req = _build_openai_request(form)
    assert len(req["tools"]) == 3
    assert req["tools"][0]["type"] == "function"
    assert req["tools"][0]["function"]["name"] == "get_weather"
    assert req["tools"][1]["function"]["name"] == "execute_code"
    assert req["tools"][2]["function"]["name"] == "send_email"
    assert req["messages"] == [{"role": "user", "content": "What is the weather?"}]


def test_tools_scenario_empty_names():
    form = {
        "scenario_type": "tools",
        "tool_names": "",
        "msg_count": "1",
        "msg_role_0": "user",
        "msg_text_0": "Hello",
        "model_override": "",
        "user_field": "",
    }
    req = _build_openai_request(form)
    assert "tools" not in req
    assert req["messages"] == [{"role": "user", "content": "Hello"}]


def test_raw_json_scenario():
    raw = json.dumps({
        "model": "gpt-4",
        "user": "bob@test.com",
        "messages": [{"role": "user", "content": "test"}],
        "tools": [{"type": "function", "function": {"name": "my_tool"}}],
    })
    form = {"scenario_type": "raw_json", "raw_json": raw}
    req = _build_openai_request(form)
    assert req["model"] == "gpt-4"
    assert req["user"] == "bob@test.com"
    assert req["messages"] == [{"role": "user", "content": "test"}]
    assert req["tools"][0]["function"]["name"] == "my_tool"


def test_raw_json_invalid():
    form = {"scenario_type": "raw_json", "raw_json": "not valid json{"}
    with pytest.raises(ValueError, match="Invalid JSON"):
        _build_openai_request(form)


def test_raw_json_no_messages():
    form = {"scenario_type": "raw_json", "raw_json": json.dumps({"model": "gpt-4"})}
    with pytest.raises(ValueError, match="messages"):
        _build_openai_request(form)
