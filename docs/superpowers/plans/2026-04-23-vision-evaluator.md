# RAMPART Vision Evaluator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a separate vision/multimodal LLM evaluator that checks image content in requests against policies, running concurrently with the existing text-based LLM evaluator.

**Architecture:** New `VisionEvaluator` class in `rampart/app/llm/vision_evaluator.py` with its own config (`VisionEvaluatorConfig`). Evaluates each image individually against each applicable `type: llm` policy check (unless `skip_vision: true`). Integrated into `PolicyEngine.evaluate()` via `asyncio.gather` for concurrent execution. Returns `(violations, warnings)` where warnings are non-blocking info messages (e.g., "vision evaluator not configured").

**Tech Stack:** Python 3.9 / FastAPI, httpx for async HTTP, existing OpenAI-compatible API format for vision LLM.

**Spec:** `docs/superpowers/specs/2026-04-23-vision-evaluator-design.md`

---

### Task 1: Update config.py — VisionEvaluatorConfig, skip_vision, env vars

**Files:**
- Modify: `rampart/app/config.py`

- [ ] **Step 1: Add VisionEvaluatorConfig class**

Add after the `LlmEvaluatorConfig` class (after line 16):

```python
class VisionEvaluatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://192.168.1.181:8082"
    model: str = ""
    timeout_seconds: float = 30.0
    fail_closed_on_error: bool = True
```

- [ ] **Step 2: Add skip_vision to CheckConfig**

Add to the `CheckConfig` class after `max_chars`:

```python
    skip_vision: Optional[bool] = None
```

- [ ] **Step 3: Add vision_evaluator to AppConfig**

Add after the `llm_evaluator` field in `AppConfig`:

```python
    vision_evaluator: VisionEvaluatorConfig = Field(default_factory=VisionEvaluatorConfig)
```

- [ ] **Step 4: Add env var overrides**

Add at the end of `_apply_env_overrides`, after the `llm` overrides:

```python
    vision = config.vision_evaluator
    vision.base_url = os.getenv("RAMPART_VISION_EVALUATOR_BASE_URL", vision.base_url)
    vision.model = os.getenv("RAMPART_VISION_EVALUATOR_MODEL", vision.model)
```

- [ ] **Step 5: Add local settings application**

Add at the end of `_apply_local_settings`:

```python
    if settings.vision_evaluator_base_url:
        config.vision_evaluator.base_url = settings.vision_evaluator_base_url
    if settings.vision_evaluator_model:
        config.vision_evaluator.model = settings.vision_evaluator_model
    if settings.vision_evaluator_timeout_seconds is not None:
        config.vision_evaluator.timeout_seconds = settings.vision_evaluator_timeout_seconds
```

- [ ] **Step 6: Verify**

Run: `python3 -c "from rampart.app.config import get_config; c = get_config(); print('vision enabled:', c.vision_evaluator.enabled, 'skip_vision field exists:', hasattr(c.policies[0].checks[0], 'skip_vision'))"`

- [ ] **Step 7: Commit**

```bash
git add rampart/app/config.py
git commit -m "feat(vision): add VisionEvaluatorConfig, skip_vision on CheckConfig, env var overrides"
```

---

### Task 2: Update models.py — extend Violation.source, add warnings to EvaluationResponse

**Files:**
- Modify: `rampart/app/models.py`

- [ ] **Step 1: Extend Violation.source to include "vision"**

Change line 17 from:

```python
    source: Literal["deterministic", "llm"] = "deterministic"
```

to:

```python
    source: Literal["deterministic", "llm", "vision"] = "deterministic"
```

- [ ] **Step 2: Add warnings field to EvaluationResponse**

Add after the `sanitized_request` field:

```python
    warnings: list[str] = Field(default_factory=list)
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from rampart.app.models import Violation, EvaluationResponse; v = Violation(policy_id='t', severity='h', category='c', message='m', source='vision'); r = EvaluationResponse(decision='accept', warnings=['test']); print('source:', v.source, 'warnings:', r.warnings)"`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/models.py
git commit -m "feat(vision): extend Violation.source with 'vision', add warnings to EvaluationResponse"
```

---

### Task 3: Update settings_store.py and ui.py — vision evaluator runtime settings and UI

**Files:**
- Modify: `rampart/app/settings_store.py`
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Add vision_evaluator fields to RuntimeSettings**

Add after `llm_evaluator_timeout_seconds` in `RuntimeSettings`:

```python
    vision_evaluator_base_url: str = ""
    vision_evaluator_model: str = ""
    vision_evaluator_timeout_seconds: Optional[float] = None
```

- [ ] **Step 2: Add Vision Evaluator LLM fieldset to the settings form**

In `_settings_form()` in `ui.py`, find the closing `</fieldset>` of the "Context Analysis LLM" fieldset (after the timeout seconds label, around line 639). Add a new fieldset right after it, before the "Default Pass-Through LLM" fieldset:

```python
        <fieldset class="fieldset">
          <legend>Vision Evaluator LLM</legend>
          <div class="hint">Used for evaluating image content against policies. Requires a vision-capable model.</div>
          <label>Base URL<input name="vision_evaluator_base_url" value="{get_value("vision_evaluator_base_url", config.vision_evaluator.base_url)}" placeholder="{escape(config.vision_evaluator.base_url)}"></label>
          <label>Model<input name="vision_evaluator_model" value="{get_value("vision_evaluator_model", config.vision_evaluator.model)}" placeholder="{escape(config.vision_evaluator.model)}"></label>
          <label>Timeout Seconds<input name="vision_evaluator_timeout_seconds" value="{get_value("vision_evaluator_timeout_seconds", config.vision_evaluator.timeout_seconds)}" inputmode="decimal"></label>
        </fieldset>
```

- [ ] **Step 3: Add vision_evaluator fields to the POST handler**

In `update_settings()` in `ui.py`, add to the `RuntimeSettings()` constructor, after `llm_evaluator_timeout_seconds`:

```python
            vision_evaluator_base_url=form.get("vision_evaluator_base_url", "").strip(),
            vision_evaluator_model=form.get("vision_evaluator_model", "").strip(),
            vision_evaluator_timeout_seconds=_optional_float(form.get("vision_evaluator_timeout_seconds", "")),
```

- [ ] **Step 4: Verify**

Run: `python3 -c "from rampart.app.settings_store import RuntimeSettings; s = RuntimeSettings(vision_evaluator_base_url='http://test'); print('OK:', s.vision_evaluator_base_url)"`

- [ ] **Step 5: Commit**

```bash
git add rampart/app/settings_store.py rampart/app/ui.py
git commit -m "feat(vision): add vision evaluator runtime settings and Settings UI fieldset"
```

---

### Task 4: Add build_vision_check_prompt to prompts.py

**Files:**
- Modify: `rampart/app/llm/prompts.py`

- [ ] **Step 1: Add the vision prompt function**

Append to `rampart/app/llm/prompts.py`:

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

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.llm.prompts import build_vision_check_prompt; from rampart.app.config import PolicyConfig, CheckConfig; p = PolicyConfig(id='test'); c = CheckConfig(type='llm', instruction='no PII'); print(build_vision_check_prompt(p, c)[:50])"`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/llm/prompts.py
git commit -m "feat(vision): add build_vision_check_prompt for image evaluation"
```

---

### Task 5: Create vision_evaluator.py

**Files:**
- Create: `rampart/app/llm/vision_evaluator.py`

- [ ] **Step 1: Create the VisionEvaluator class**

Create `rampart/app/llm/vision_evaluator.py`:

```python
from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from rampart.app.config import AppConfig, CheckConfig, PolicyConfig
from rampart.app.llm.prompts import build_vision_check_prompt
from rampart.app.models import Violation


class VisionEvaluator:
    def __init__(self, config: AppConfig, policies: Optional[list[PolicyConfig]] = None):
        self.config = config
        self.policies = policies if policies is not None else config.policies

    async def evaluate(self, request: dict[str, Any]) -> tuple[list[Violation], list[str]]:
        images = _extract_images(request)
        if not images:
            return [], []

        vision_config = self.config.vision_evaluator
        if not vision_config.enabled:
            return [], ["Vision evaluator not configured — images were not evaluated against policies."]

        checks = [
            (policy, check)
            for policy in self.policies
            if policy.enabled
            for check in policy.checks
            if check.type == "llm" and not check.skip_vision
        ]
        if not checks:
            return [], []

        violations: list[Violation] = []
        for policy, check in checks:
            for msg_idx, part_idx, image_url in images:
                result = await self._evaluate_image(image_url, msg_idx, part_idx, policy, check)
                violations.extend(result)
        return violations, []

    async def _evaluate_image(
        self,
        image_url: str,
        msg_idx: int,
        part_idx: int,
        policy: PolicyConfig,
        check: CheckConfig,
    ) -> list[Violation]:
        vision_config = self.config.vision_evaluator
        prompt = build_vision_check_prompt(policy, check)
        payload = {
            "model": vision_config.model,
            "messages": [
                {"role": "system", "content": "Return only valid JSON."},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": image_url}},
                    ],
                },
            ],
            "temperature": 0,
        }

        try:
            async with httpx.AsyncClient(timeout=vision_config.timeout_seconds) as client:
                response = await client.post(
                    f"{vision_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]
            data = json.loads(_strip_json_fence(content))
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            if not vision_config.fail_closed_on_error:
                return []
            return [
                Violation(
                    policy_id="vision-evaluator-unavailable",
                    severity="critical",
                    category="evaluator_error",
                    message=f"Vision evaluator failed: {error.__class__.__name__}",
                    source="vision",
                )
            ]

        if not data.get("violates"):
            return []
        return [
            Violation(
                policy_id=policy.id,
                severity=policy.severity,
                category=policy.category,
                message=data.get("message") or "Vision evaluator reported a policy violation.",
                source="vision",
                path=f"messages[{msg_idx}].content[{part_idx}]",
            )
        ]


def _extract_images(request: dict[str, Any]) -> list[tuple[int, int, str]]:
    """Extract all image URLs from the request. Returns (msg_idx, part_idx, url) tuples."""
    images = []
    for msg_idx, message in enumerate(request.get("messages") or []):
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for part_idx, part in enumerate(content):
            if not isinstance(part, dict):
                continue
            if part.get("type") == "image_url":
                image_url = part.get("image_url")
                if isinstance(image_url, dict) and isinstance(image_url.get("url"), str):
                    images.append((msg_idx, part_idx, image_url["url"]))
    return images


def _strip_json_fence(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```json"):
        stripped = stripped.removeprefix("```json").strip()
    if stripped.startswith("```"):
        stripped = stripped.removeprefix("```").strip()
    if stripped.endswith("```"):
        stripped = stripped.removesuffix("```").strip()
    return stripped
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.llm.vision_evaluator import VisionEvaluator, _extract_images; imgs = _extract_images({'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': 'hi'}, {'type': 'image_url', 'image_url': {'url': 'data:image/png;base64,abc'}}]}]}); print(f'{len(imgs)} images found:', imgs)"`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/llm/vision_evaluator.py
git commit -m "feat(vision): create VisionEvaluator class with per-image evaluation"
```

---

### Task 6: Integrate VisionEvaluator into PolicyEngine

**Files:**
- Modify: `rampart/app/policy/engine.py`

- [ ] **Step 1: Add imports and VisionEvaluator to constructor**

Add the import after the `LlmEvaluator` import:

```python
from rampart.app.llm.vision_evaluator import VisionEvaluator
```

Add `asyncio` import at the top:

```python
import asyncio
```

In the `__init__` method, add after `self.llm_evaluator`:

```python
        self.vision_evaluator = VisionEvaluator(config, self.policies)
```

- [ ] **Step 2: Update evaluate() to run both evaluators concurrently**

Replace the `evaluate` method:

```python
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
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from rampart.app.policy.engine import PolicyEngine; from rampart.app.config import get_config; e = PolicyEngine(get_config()); print('Engine has vision_evaluator:', hasattr(e, 'vision_evaluator'))"`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/policy/engine.py
git commit -m "feat(vision): integrate VisionEvaluator into PolicyEngine with asyncio.gather"
```

---

### Task 7: Show warnings in playground results

**Files:**
- Modify: `rampart/app/playground.py`

- [ ] **Step 1: Update _render_results to show warnings**

In `_render_results()`, find the line that builds the decision banner:

```python
          <div class="pg-decision {decision_class}">{decision_label}</div>
```

Add warnings display right after it:

```python
          {"".join(f'<div style="padding:8px 12px;border-radius:6px;background:var(--warning-bg);border:1px solid var(--warning-border);color:var(--warning);font-size:12px;margin-bottom:8px">{escape(w)}</div>' for w in (response.warnings or []))}
```

So the full line becomes:

```python
          <div class="pg-decision {decision_class}">{decision_label}</div>
          {"".join(f'<div style="padding:8px 12px;border-radius:6px;background:var(--warning-bg);border:1px solid var(--warning-border);color:var(--warning);font-size:12px;margin-bottom:8px">{escape(w)}</div>' for w in (response.warnings or []))}
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.playground import _render_results; from rampart.app.models import EvaluationResponse; r = EvaluationResponse(decision='accept', warnings=['Vision evaluator not configured']); html = _render_results(r, [], 10, '<div>test</div>'); assert 'Vision evaluator not configured' in html; print('Warnings rendered OK')"`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/playground.py
git commit -m "feat(vision): show evaluation warnings in playground results"
```

---

### Task 8: Run tests and verify

**Files:**
- Read: `tests/`

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All previously-passing tests still pass (36 pass, 1 pre-existing failure). The new `warnings` field on `EvaluationResponse` has a default so existing code is unaffected. The `source="vision"` literal extends the union so existing `"deterministic"` and `"llm"` values still work.

- [ ] **Step 2: Quick functional test**

Run: `python3 -c "
import asyncio
from rampart.app.policy.engine import PolicyEngine
from rampart.app.config import get_config

async def test():
    config = get_config()
    engine = PolicyEngine(config)
    # Request with an image
    request = {
        'messages': [{
            'role': 'user',
            'content': [
                {'type': 'text', 'text': 'What is this?'},
                {'type': 'image_url', 'image_url': {'url': 'data:image/png;base64,iVBOR'}},
            ]
        }]
    }
    response = await engine.evaluate(request)
    print('Decision:', response.decision)
    print('Warnings:', response.warnings)
    print('Violations:', len(response.violations))

asyncio.run(test())
"`

Expected: Decision is based on text policies only. Warnings list should contain "Vision evaluator not configured" since vision_evaluator.enabled defaults to False and the request contains an image.

- [ ] **Step 3: Commit (if fixes needed)**

```bash
git add -A
git commit -m "fix: resolve vision evaluator integration issues"
```
