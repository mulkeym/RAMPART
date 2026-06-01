# Playground Scenario Templates — Design Spec

**Date:** 2026-06-01
**Status:** Draft
**Scope:** Add scenario template selector to the playground for testing all RAMPART evaluation capabilities

---

## Problem

The playground only tests text prompts and images against policies. RAMPART also evaluates tool calls (tool_allowlist/tool_denylist), model restrictions (model_allowlist), user identity (group-based policy resolution), and arbitrary OpenAI request shapes. Users have no way to test these capabilities without making raw API calls.

## Overview

A dropdown at the top of the playground selects one of three test scenario templates. Switching templates swaps the input form below. Policy selection, evaluation buttons (Evaluate Only / Evaluate & Send), upstream override, and results stay shared across all templates.

## Templates

### 1. Prompt Evaluation (default)

The current playground behavior — no changes needed. Adds a `user` email input field for testing group-based policy resolution.

**Fields:**
- Messages builder (system/user/assistant with image support) — existing
- User email (new text input, optional)
- Model override — existing
- Upstream override — existing

### 2. Tool Call Test

Tests tool_allowlist and tool_denylist policies.

**Fields:**
- Tool names (comma-separated text input, e.g. `get_weather, execute_code, send_email`)
- Messages builder (same as Prompt Evaluation, for context)
- User email (optional)
- Model override

The form builds an OpenAI request with a `tools` array containing function definitions (name-only, with stub description and empty parameters) plus the messages.

### 3. Raw JSON

Full control — a large textarea pre-populated with a complete OpenAI request template.

**Template content:**
```json
{
  "model": "gpt-4",
  "user": "testuser@example.com",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Enter your prompt here"}
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
            "query": {"type": "string"}
          }
        }
      }
    }
  ]
}
```

Users edit the JSON directly. The textarea content is parsed and passed directly to the policy engine, bypassing form-based request building. Self-documenting through descriptive placeholder values.

## UI Layout

```
+--------------------------------------------------+
| Playground                                        |
+--------------------------------------------------+
| Test Scenario: [Prompt Evaluation ▼]              |
+--------------------------------------------------+
|                                                    |
|  (template-specific form area swaps here)          |
|                                                    |
+--------------------------------------------------+
| Policies: [✓] no-pii  [✓] prompt-injection  ...   |
| + Ad-hoc Rule                                      |
+--------------------------------------------------+
| [Model override]  [Evaluate Only] [Evaluate & Send]|
+--------------------------------------------------+
| Results (shared across all templates)              |
+--------------------------------------------------+
```

The dropdown is a `<select>` with values: `prompt` (default), `tools`, `raw_json`. JavaScript shows/hides the appropriate form section. No page reload.

## Implementation Approach

### Form handling

- The dropdown value is submitted as a hidden field `scenario_type`
- `playground_evaluate` reads `scenario_type` to determine how to build the OpenAI request:
  - `prompt` — existing `_build_messages()` logic, adds `user` field if provided
  - `tools` — calls `_build_messages()` plus builds `tools` array from comma-separated names
  - `raw_json` — parses the textarea content as JSON directly, no form building

### Tool name to OpenAI tool format

For the Tool Call template, each comma-separated tool name becomes:
```python
{"type": "function", "function": {"name": "<tool_name>", "description": "", "parameters": {"type": "object", "properties": {}}}}
```

This is sufficient for tool_allowlist/tool_denylist evaluation since policies check tool names only.

### JavaScript

- `pgScenarioChange(select)` — shows/hides form sections based on selected value
- Existing message builder JS works unchanged for prompt and tools templates
- Raw JSON template just needs the textarea — no additional JS

## Modified Files

| File | Change |
|------|--------|
| `rampart/app/playground.py` | Add scenario_type handling, tool name parsing, raw JSON parsing, user field support |

No new files. The playground is self-contained in `playground.py` (routes + form HTML + JavaScript).

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Raw JSON is invalid | Show error: "Invalid JSON: {parse error}" |
| Raw JSON has no messages | Show error: "Request must include a messages array" |
| Tool names field is empty | Evaluate with messages only (no tools in request) |
| User field is empty | Omit user from request (existing behavior) |
