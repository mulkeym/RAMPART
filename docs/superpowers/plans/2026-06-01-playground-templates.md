# Playground Scenario Templates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a scenario template selector to the playground for testing tool calls, raw JSON requests, and user identity alongside existing prompt evaluation.

**Architecture:** A dropdown at the top of the playground selects one of three templates (Prompt, Tool Calls, Raw JSON). JavaScript shows/hides form sections. The POST handler reads `scenario_type` to build the OpenAI request differently per template. All changes are in `rampart/app/playground.py`.

**Tech Stack:** Python, FastAPI, HTML/CSS/JS (inline in playground.py), existing PolicyEngine.

---

## File Structure

**Modified files:**
| File | Change |
|------|--------|
| `rampart/app/playground.py` | Add scenario dropdown, tool call form, raw JSON form, user field, request building logic |

**Test files:**
| File | Change |
|------|--------|
| `tests/test_playground.py` | Tests for tool call and raw JSON request building |

---

### Task 1: Request Building Logic (Tool Calls + Raw JSON + User Field)

**Files:**
- Modify: `rampart/app/playground.py`
- Create: `tests/test_playground.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_playground.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_playground.py -v`
Expected: FAIL — `_build_openai_request` not found

- [ ] **Step 3: Add `_build_openai_request` to `playground.py`**

Add after the existing `_build_messages` function:

```python
def _build_openai_request(form: dict[str, str]) -> dict[str, Any]:
    """Build an OpenAI-compatible request dict based on the selected scenario template."""
    scenario = form.get("scenario_type", "prompt")

    if scenario == "raw_json":
        raw = form.get("raw_json", "").strip()
        try:
            request = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        if not isinstance(request, dict) or "messages" not in request:
            raise ValueError("Request must include a messages array")
        return request

    messages = _build_messages(form)
    request: dict[str, Any] = {"messages": messages}

    model_override = form.get("model_override", "").strip()
    if model_override:
        request["model"] = model_override

    user_field = form.get("user_field", "").strip()
    if user_field:
        request["user"] = user_field

    if scenario == "tools":
        tool_names_raw = form.get("tool_names", "").strip()
        if tool_names_raw:
            names = [n.strip() for n in tool_names_raw.split(",") if n.strip()]
            if names:
                request["tools"] = [
                    {
                        "type": "function",
                        "function": {
                            "name": name,
                            "description": "",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    }
                    for name in names
                ]

    return request
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_playground.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add rampart/app/playground.py tests/test_playground.py
git commit -m "feat: add _build_openai_request for playground scenario templates"
```

---

### Task 2: Wire Request Builder into Evaluate Handlers

**Files:**
- Modify: `rampart/app/playground.py`

- [ ] **Step 1: Update `playground_evaluate` POST handler**

Replace the request-building section in `playground_evaluate` (the lines from `messages = _build_messages(form)` through `openai_request["model"] = model_override`) with a call to `_build_openai_request`. Also handle ValueError for raw JSON errors.

Find this block (around line 267-271):
```python
    messages = _build_messages(form)
    openai_request: dict[str, Any] = {"messages": messages}
    model_override = form.get("model_override", "").strip()
    if model_override:
        openai_request["model"] = model_override
```

Replace with:
```python
    try:
        openai_request = _build_openai_request(form)
    except ValueError as e:
        return HTMLResponse(f'<div class="notice error">{escape(str(e))}</div>')
```

- [ ] **Step 2: Update `playground_llm` POST handler**

Find the same pattern in `playground_llm` (around line 322-326):
```python
    messages = _build_messages(form)
    openai_request: dict[str, Any] = {"messages": messages}
    model_override = form.get("model_override", "").strip()
    if model_override:
        openai_request["model"] = model_override
```

Replace with:
```python
    try:
        openai_request = _build_openai_request(form)
    except ValueError as e:
        return HTMLResponse(f'<div class="notice error">{escape(str(e))}</div>')
```

- [ ] **Step 3: Update the prompt log entry in `playground_evaluate`**

The `user` field in the log entry should use the request's user field (not just `actor`). Find:
```python
        user=actor,
```

Replace with:
```python
        user=openai_request.get("user") or actor,
```

- [ ] **Step 4: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add rampart/app/playground.py
git commit -m "feat: wire _build_openai_request into playground evaluate handlers"
```

---

### Task 3: UI — Scenario Dropdown + Template Forms

**Files:**
- Modify: `rampart/app/playground.py`

- [ ] **Step 1: Add scenario dropdown to `_playground_page`**

In the `_playground_page` function, find the `<form id="pg-form"` opening. Add a scenario dropdown and hidden field right after the form opens, before the `<div class="pg-input">`:

```python
        <div style="padding:12px 16px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;margin-bottom:12px;display:flex;align-items:center;gap:12px">
          <label style="font-size:13px;color:var(--muted);white-space:nowrap;margin:0">Test Scenario:</label>
          <select id="pg-scenario" name="scenario_type" onchange="pgScenarioChange(this.value)" style="flex:1;max-width:300px">
            <option value="prompt" selected>Prompt Evaluation</option>
            <option value="tools">Tool Call Test</option>
            <option value="raw_json">Raw JSON</option>
          </select>
        </div>
```

- [ ] **Step 2: Add user field to the prompt template section**

Find the messages section div (`<div class="pg-messages panel"`). Add a user email field after the messages `</div>` closing and before the policies section:

```python
          <div class="pg-user-field panel" style="padding:12px 16px;margin-top:8px" id="pg-user-section">
            <label style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:6px;display:block">User Identity (optional)</label>
            <input name="user_field" placeholder="email@example.com — for testing group-based policy resolution" style="width:100%">
          </div>
```

- [ ] **Step 3: Add tool call form section (hidden by default)**

Add after the user field section, before the policies section:

```python
          <div id="pg-tools-section" style="display:none">
            <div class="panel" style="padding:16px;margin-bottom:8px">
              <label style="font-size:14px;font-weight:700;color:var(--text);display:block;margin-bottom:8px">Tool Names</label>
              <input name="tool_names" placeholder="get_weather, execute_code, send_email (comma-separated)" style="width:100%">
              <div class="hint" style="margin-top:6px">Enter tool names to test against tool_allowlist and tool_denylist policies. Names are wrapped in OpenAI function tool format automatically.</div>
            </div>
          </div>
```

- [ ] **Step 4: Add raw JSON form section (hidden by default)**

Add after the tools section:

```python
          <div id="pg-raw-section" style="display:none">
            <div class="panel" style="padding:16px">
              <label style="font-size:14px;font-weight:700;color:var(--text);display:block;margin-bottom:8px">OpenAI Request JSON</label>
              <textarea name="raw_json" rows="18" style="width:100%;font-family:monospace;font-size:12px;line-height:1.5;background:var(--bg-primary);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:12px;resize:vertical">{_raw_json_template()}</textarea>
              <div class="hint" style="margin-top:6px">Edit the full OpenAI-compatible request. Includes model, user, messages, and tools. RAMPART evaluates everything.</div>
            </div>
          </div>
```

- [ ] **Step 5: Add `_raw_json_template` helper**

Add near the other helper functions:

```python
def _raw_json_template() -> str:
    return escape(json.dumps({
        "model": "gpt-4",
        "user": "testuser@example.com",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Enter your prompt here"},
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "example_tool",
                    "description": "An example tool definition",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                        },
                    },
                },
            },
        ],
    }, indent=2))
```

- [ ] **Step 6: Add `pgScenarioChange` JavaScript**

Add to the `_playground_script` function, inside the `<script>` tag:

```javascript
function pgScenarioChange(scenario) {
  var msgSection = document.querySelector('.pg-messages');
  var userSection = document.getElementById('pg-user-section');
  var toolsSection = document.getElementById('pg-tools-section');
  var rawSection = document.getElementById('pg-raw-section');

  // Hide all optional sections
  if (msgSection) msgSection.style.display = 'none';
  if (userSection) userSection.style.display = 'none';
  if (toolsSection) toolsSection.style.display = 'none';
  if (rawSection) rawSection.style.display = 'none';

  if (scenario === 'prompt') {
    if (msgSection) msgSection.style.display = '';
    if (userSection) userSection.style.display = '';
  } else if (scenario === 'tools') {
    if (msgSection) msgSection.style.display = '';
    if (userSection) userSection.style.display = '';
    if (toolsSection) toolsSection.style.display = '';
  } else if (scenario === 'raw_json') {
    if (rawSection) rawSection.style.display = '';
  }
}
```

- [ ] **Step 7: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 8: Manually test in browser**

Restart: `pkill -f uvicorn; python -m uvicorn rampart.app.main:app --host 0.0.0.0 --port 8080`

Open `http://localhost:8080/ui/playground` and verify:
- Dropdown shows 3 options
- Switching to "Tool Call Test" shows tool names input + messages + user field
- Switching to "Raw JSON" shows only the JSON textarea with template
- Switching back to "Prompt Evaluation" shows messages + user field
- Evaluate works for all 3 templates

- [ ] **Step 9: Commit and push**

```bash
git add rampart/app/playground.py
git commit -m "feat: add scenario template UI to playground (prompt, tools, raw JSON)"
git push origin master
```
