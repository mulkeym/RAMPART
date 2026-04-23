# RAMPART Vision Evaluator

## Overview

A separate multimodal/vision LLM evaluator for RAMPART that evaluates image content in requests against policies. Runs alongside the existing text-based LLM evaluator — each has its own config (model, endpoint, timeout) since they may use different LLMs. Existing `type: llm` policy checks automatically apply to images unless explicitly opted out with `skip_vision: true`.

## Goals

1. **Image policy enforcement** — Evaluate images attached to requests against the same policies that check text content (PII in screenshots, inappropriate content, etc.)
2. **Separate LLM config** — Vision-capable models are often different from text models; separate endpoint/model/timeout config
3. **Transparent coverage gaps** — When vision evaluator is not configured, warn that images were not evaluated
4. **Per-image granularity** — Each image evaluated individually with clear violation paths

## Constraints

- New file `rampart/app/llm/vision_evaluator.py` — separate from text evaluator
- Same OpenAI-compatible API format for the vision LLM endpoint
- `type: llm` checks apply to both text and images by default; opt out per check with `skip_vision: true`
- One API call per image per policy check (not batched)
- Runs concurrently with text LLM evaluator via `asyncio.gather`

## Config

### VisionEvaluatorConfig

New config block in `config.py`, same pattern as `LlmEvaluatorConfig`:

```python
class VisionEvaluatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://192.168.1.181:8082"
    model: str = ""
    timeout_seconds: float = 30.0
    fail_closed_on_error: bool = True
```

Added to `AppConfig`:

```python
vision_evaluator: VisionEvaluatorConfig = Field(default_factory=VisionEvaluatorConfig)
```

### Policy YAML

```yaml
vision_evaluator:
  enabled: false
  base_url: "http://192.168.1.181:8082"
  model: "llava-v1.6"
  timeout_seconds: 30.0
  fail_closed_on_error: true
```

### Environment Variable Overrides

| Variable | Purpose |
|----------|---------|
| `RAMPART_VISION_EVALUATOR_BASE_URL` | Vision LLM endpoint |
| `RAMPART_VISION_EVALUATOR_MODEL` | Vision model name |

### Runtime Settings

`RuntimeSettings` gains three new fields:

```python
vision_evaluator_base_url: str = ""
vision_evaluator_model: str = ""
vision_evaluator_timeout_seconds: Optional[float] = None
```

Applied in `_apply_local_settings` the same way as the text evaluator fields.

### Settings UI

New "Vision Evaluator LLM" fieldset on the Settings page (`/ui/settings`) between "Context Analysis LLM" and "Default Pass-Through LLM". Contains Base URL, Model, and Timeout Seconds fields. Same pattern as the existing fieldsets.

### CheckConfig Extension

New optional field:

```python
class CheckConfig(BaseModel):
    ...existing fields...
    skip_vision: Optional[bool] = None
```

When `skip_vision` is `True`, this `type: llm` check is not evaluated against images. Default is `None` (meaning vision evaluation applies).

## Violation Model

Extend `Violation.source` from `Literal["deterministic", "llm"]` to `Literal["deterministic", "llm", "vision"]`.

Vision violations use:
- `source="vision"`
- `path` pointing to the exact image location: e.g., `messages[1].content[2]` (message index, content part index)

## VisionEvaluator Class

**File:** `rampart/app/llm/vision_evaluator.py`

### Constructor

```python
class VisionEvaluator:
    def __init__(self, config: AppConfig, policies: list[PolicyConfig] = None):
        self.config = config
        self.policies = policies if policies is not None else config.policies
```

### evaluate(request) -> tuple[list[Violation], list[str]]

Returns a tuple of (violations, warnings).

1. Extract all images from the request:
   - Iterate `request["messages"]`, for each message with `content` as a list, find parts where `part["type"] == "image_url"`
   - Collect `(message_index, part_index, image_url)` tuples
2. If no images found, return `([], [])`
3. If vision evaluator is not enabled:
   - Return `([], ["Vision evaluator not configured — images were not evaluated against policies."])`
4. Find applicable checks: all policies with `type: llm` checks where `check.skip_vision` is not `True`
5. For each `(policy, check)` x each `(msg_idx, part_idx, image_url)`:
   - Call `_evaluate_image(image_url, msg_idx, part_idx, policy, check)`
6. Return `(all_violations, [])`

### _evaluate_image(image_url, msg_idx, part_idx, policy, check) -> list[Violation]

1. Build prompt using `build_vision_check_prompt(policy, check)`
2. Send multimodal request to vision LLM:
   ```python
   payload = {
       "model": vision_config.model,
       "messages": [
           {"role": "system", "content": "Return only valid JSON."},
           {"role": "user", "content": [
               {"type": "text", "text": prompt},
               {"type": "image_url", "image_url": {"url": image_url}},
           ]},
       ],
       "temperature": 0,
   }
   ```
3. Parse JSON response `{"violates": bool, "message": str}`
4. If violates: return `Violation(policy_id=policy.id, severity=policy.severity, category=policy.category, message=..., source="vision", path=f"messages[{msg_idx}].content[{part_idx}]")`
5. Error handling: same `fail_closed_on_error` pattern as text evaluator, generates violation with `policy_id="vision-evaluator-unavailable"` and `source="vision"`

## Vision Check Prompt

**New function in `rampart/app/llm/prompts.py`:**

```python
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
```

Same response format as the text evaluator.

## PolicyEngine Integration

In `PolicyEngine.evaluate()`:

```python
async def evaluate(self, request: dict) -> EvaluationResponse:
    deterministic_violations, denied_tools = self._evaluate_deterministic(request)

    # Run text and vision LLM evaluators concurrently
    llm_violations, (vision_violations, vision_warnings) = await asyncio.gather(
        self.llm_evaluator.evaluate(request),
        self.vision_evaluator.evaluate(request),
    )

    violations = _dedupe_violations(deterministic_violations + llm_violations + vision_violations)
    ...rest unchanged...
```

The `vision_warnings` list is stored on the response. Add a new optional field to `EvaluationResponse`:

```python
class EvaluationResponse(BaseModel):
    ...existing fields...
    warnings: list[str] = Field(default_factory=list)
```

Warnings are informational only — they do not affect the decision.

## Playground & UI

- The playground results panel shows warnings below the decision banner in an amber notice
- Vision violations appear in the per-policy breakdown with a "vision" source badge
- The violation path shows which image triggered (e.g., `messages[1].content[2]`)

## Implementation Scope

### New Files
1. `rampart/app/llm/vision_evaluator.py` — VisionEvaluator class

### Modified Files
2. `rampart/app/config.py` — Add `VisionEvaluatorConfig`, add to `AppConfig`, add `skip_vision` to `CheckConfig`, env var overrides
3. `rampart/app/models.py` — Extend `Violation.source` to include `"vision"`, add `warnings` to `EvaluationResponse`
4. `rampart/app/llm/prompts.py` — Add `build_vision_check_prompt`
5. `rampart/app/policy/engine.py` — Create `VisionEvaluator`, run concurrently, merge violations and warnings
6. `rampart/app/settings_store.py` — Add `vision_evaluator_*` fields
7. `rampart/app/ui.py` — Add "Vision Evaluator LLM" fieldset to Settings page, handle `vision_evaluator_*` in POST handler
8. `rampart/app/playground.py` — Show warnings in results panel
