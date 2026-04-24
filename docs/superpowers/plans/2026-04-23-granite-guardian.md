# Granite Guardian + Post-LLM Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add IBM Granite Guardian evaluation mode (logprobs-based) and post-LLM response evaluation with sanitization to the RAMPART policy engine.

**Architecture:** The LLM evaluator gains a `mode` setting ("standard" vs "granite-guardian") that switches request/response format. A new `stage` field on checks controls pre/post timing. `PolicyEngine` gets a `post_evaluate()` method. `main.py` calls post-evaluation after upstream LLM response, sanitizing harmful content.

**Tech Stack:** Python 3.9+ / FastAPI, httpx async, existing policy engine.

**Spec:** `docs/superpowers/specs/2026-04-23-granite-guardian-design.md`

---

### Task 1: Config changes — mode, confidence_threshold, post_llm_enabled, stage

**Files:**
- Modify: `rampart/app/config.py`
- Modify: `rampart/app/settings_store.py`

- [ ] **Step 1: Add new fields to LlmEvaluatorConfig**

In `rampart/app/config.py`, add three fields to `LlmEvaluatorConfig` after `fail_closed_on_error`:

```python
class LlmEvaluatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://192.168.1.181:8080/v1"
    model: str = "gemma4-e2b"
    timeout_seconds: float = 20.0
    fail_closed_on_error: bool = True
    mode: str = "standard"
    confidence_threshold: float = 0.75
    post_llm_enabled: bool = False
```

- [ ] **Step 2: Add `stage` to CheckConfig**

Add after `skip_vision`:

```python
    stage: Optional[str] = None  # "pre", "post", "both", or None (defaults to "both")
```

- [ ] **Step 3: Add runtime settings fields**

In `rampart/app/settings_store.py`, add after `llm_evaluator_timeout_seconds`:

```python
    llm_evaluator_mode: str = ""
    llm_evaluator_confidence_threshold: Optional[float] = None
    llm_evaluator_post_llm_enabled: Optional[bool] = None
```

- [ ] **Step 4: Wire through `_apply_local_settings`**

In `rampart/app/config.py`, in `_apply_local_settings`, add after the `llm_evaluator_timeout_seconds` block:

```python
    if settings.llm_evaluator_mode:
        config.llm_evaluator.mode = settings.llm_evaluator_mode
    if settings.llm_evaluator_confidence_threshold is not None:
        config.llm_evaluator.confidence_threshold = settings.llm_evaluator_confidence_threshold
    if settings.llm_evaluator_post_llm_enabled is not None:
        config.llm_evaluator.post_llm_enabled = settings.llm_evaluator_post_llm_enabled
```

- [ ] **Step 5: Verify**

Run: `python3 -c "from rampart.app.config import get_config; c = get_config(); print('mode:', c.llm_evaluator.mode, 'threshold:', c.llm_evaluator.confidence_threshold, 'post:', c.llm_evaluator.post_llm_enabled)"`

- [ ] **Step 6: Commit**

```bash
git add rampart/app/config.py rampart/app/settings_store.py
git commit -m "feat(granite): add mode, confidence_threshold, post_llm_enabled config + stage on CheckConfig"
```

---

### Task 2: Refactor evaluator.py — standard mode extraction + stage filtering

**Files:**
- Modify: `rampart/app/llm/evaluator.py`

This task refactors the evaluate method to support stage filtering and extracts the standard mode logic into its own method, preparing for granite guardian mode in Task 3.

- [ ] **Step 1: Refactor evaluate() with stage parameter and standard mode method**

Replace the entire `LlmEvaluator` class in `rampart/app/llm/evaluator.py`:

```python
class LlmEvaluator:
    def __init__(self, config: AppConfig, policies: Optional[list[PolicyConfig]] = None):
        self.config = config
        self.policies = policies if policies is not None else config.policies

    async def evaluate(self, request: dict[str, Any], stage: str = "pre") -> list[Violation]:
        llm_config = self.config.llm_evaluator
        if not llm_config.enabled:
            return []

        policies_with_llm_checks = [
            (policy, check)
            for policy in self.policies
            if policy.enabled
            for check in policy.checks
            if check.type == "llm" and _check_matches_stage(check, stage)
        ]
        if not policies_with_llm_checks:
            return []

        if llm_config.mode == "granite-guardian":
            return await self._evaluate_guardian(request, policies_with_llm_checks)
        return await self._evaluate_standard(request, policies_with_llm_checks)

    async def evaluate_response(self, response_text: str) -> list[Violation]:
        """Evaluate an LLM response against post-stage policies."""
        if not self.config.llm_evaluator.post_llm_enabled:
            return []
        request = {"messages": [{"role": "assistant", "content": response_text}]}
        return await self.evaluate(request, stage="post")

    async def _evaluate_standard(self, request: dict[str, Any], checks: list) -> list[Violation]:
        import asyncio
        request_json = json.dumps(_strip_image_data(request), sort_keys=True, ensure_ascii=True)
        results = await asyncio.gather(*(
            self._evaluate_standard_check(request_json, policy, check)
            for policy, check in checks
        ))
        violations: list[Violation] = []
        for result in results:
            violations.extend(result)
        return violations

    async def _evaluate_standard_check(self, request_json: str, policy: PolicyConfig, check: CheckConfig) -> list[Violation]:
        llm_config = self.config.llm_evaluator
        prompt = build_policy_check_prompt(request_json, policy, check)
        payload = {
            "model": llm_config.model,
            "messages": [
                {"role": "system", "content": "Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }

        try:
            async with httpx.AsyncClient(timeout=llm_config.timeout_seconds) as client:
                response = await client.post(
                    f"{llm_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]
            data = json.loads(_strip_json_fence(content))
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            if not llm_config.fail_closed_on_error:
                return []
            return [
                Violation(
                    policy_id="llm-evaluator-unavailable",
                    severity="critical",
                    category="evaluator_error",
                    message=f"LLM evaluator failed: {error.__class__.__name__}",
                    source="llm",
                )
            ]

        if not data.get("violates"):
            return []
        return [
            Violation(
                policy_id=policy.id,
                severity=policy.severity,
                category=policy.category,
                message=data.get("message") or "LLM evaluator reported a policy violation.",
                source="llm",
            )
        ]

    async def _evaluate_guardian(self, request: dict[str, Any], checks: list) -> list[Violation]:
        """Placeholder — implemented in Task 3."""
        return []
```

Add the stage matching helper after the class, before `_strip_image_data`:

```python
def _check_matches_stage(check: CheckConfig, stage: str) -> bool:
    check_stage = check.stage or "both"
    if check_stage == "both":
        return True
    return check_stage == stage
```

- [ ] **Step 2: Verify existing tests still pass**

Run: `python3 -m pytest tests/ -v`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/llm/evaluator.py
git commit -m "refactor(llm): extract standard mode, add stage filtering and evaluate_response"
```

---

### Task 3: Implement Granite Guardian evaluation mode

**Files:**
- Modify: `rampart/app/llm/evaluator.py`

- [ ] **Step 1: Replace the guardian placeholder with the full implementation**

Replace the `_evaluate_guardian` method and add `_evaluate_guardian_check` and `_parse_guardian_response`:

```python
    async def _evaluate_guardian(self, request: dict[str, Any], checks: list) -> list[Violation]:
        import asyncio
        # Extract text from all messages
        text_parts = []
        for message in request.get("messages") or []:
            content = message.get("content")
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        text_parts.append(part["text"])
        user_text = "\n".join(text_parts)
        if not user_text.strip():
            return []

        results = await asyncio.gather(*(
            self._evaluate_guardian_check(user_text, policy, check)
            for policy, check in checks
        ))
        violations: list[Violation] = []
        for result in results:
            violations.extend(result)
        return violations

    async def _evaluate_guardian_check(self, text: str, policy: PolicyConfig, check: CheckConfig) -> list[Violation]:
        llm_config = self.config.llm_evaluator
        risk_definition = check.instruction or policy.description
        payload = {
            "model": llm_config.model,
            "messages": [
                {"role": "user", "content": text},
            ],
            "chat_template_kwargs": {
                "guardian_config": {
                    "risk_name": policy.id,
                    "risk_definition": risk_definition,
                }
            },
            "logprobs": True,
            "top_logprobs": 5,
            "max_tokens": 20,
            "temperature": 0,
        }

        try:
            async with httpx.AsyncClient(timeout=llm_config.timeout_seconds) as client:
                response = await client.post(
                    f"{llm_config.base_url.rstrip('/')}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

            body = response.json()
            violates, confidence, raw_output = _parse_guardian_response(body, llm_config.confidence_threshold)
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as error:
            if not llm_config.fail_closed_on_error:
                return []
            return [
                Violation(
                    policy_id="llm-evaluator-unavailable",
                    severity="critical",
                    category="evaluator_error",
                    message=f"Granite Guardian failed: {error.__class__.__name__}",
                    source="llm",
                )
            ]

        if not violates:
            return []
        return [
            Violation(
                policy_id=policy.id,
                severity=policy.severity,
                category=policy.category,
                message=f"Guardian: {raw_output.strip()} (confidence: {confidence:.2f})",
                source="llm",
            )
        ]
```

Add the response parser as a module-level function, after `_check_matches_stage`:

```python
def _parse_guardian_response(body: dict, threshold: float) -> tuple[bool, float, str]:
    """Parse Granite Guardian response. Returns (violates, confidence, raw_output)."""
    import math

    choices = body.get("choices", [])
    if not choices:
        return False, 0.0, ""

    choice = choices[0]
    content = (choice.get("message") or {}).get("content", "").strip()

    logprobs_data = choice.get("logprobs")
    if logprobs_data and isinstance(logprobs_data, dict):
        token_logprobs = logprobs_data.get("content", [])
        if token_logprobs and isinstance(token_logprobs[0], dict):
            top = token_logprobs[0].get("top_logprobs", [])
            for entry in top:
                token = entry.get("token", "").strip().lower()
                if token == "yes":
                    yes_prob = math.exp(entry.get("logprob", -100))
                    return yes_prob > threshold, yes_prob, content

    # Fallback: check text content if no logprobs
    violates = content.lower().startswith("yes")
    return violates, 1.0 if violates else 0.0, content
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.llm.evaluator import _parse_guardian_response; v, c, t = _parse_guardian_response({'choices': [{'message': {'content': 'Yes'}, 'logprobs': {'content': [{'token': 'Yes', 'logprob': -0.02, 'top_logprobs': [{'token': 'Yes', 'logprob': -0.02}]}]}}]}, 0.75); print('violates:', v, 'confidence:', round(c, 3))"`

Expected: `violates: True confidence: 0.98`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/llm/evaluator.py
git commit -m "feat(granite): implement Granite Guardian evaluation mode with logprobs parsing"
```

---

### Task 4: Add post_evaluate to PolicyEngine

**Files:**
- Modify: `rampart/app/policy/engine.py`

- [ ] **Step 1: Add `post_evaluate()` method to PolicyEngine**

Add after the `evaluate()` method:

```python
    async def post_evaluate(self, response_text: str) -> list[Violation]:
        """Evaluate an upstream LLM response against post-stage policies."""
        return await self.llm_evaluator.evaluate_response(response_text)
```

- [ ] **Step 2: Export `_is_blocking` for use by main.py**

The `_is_blocking` function is already module-level and accessible. No change needed — `main.py` can import it or call it via engine. Actually, main.py already has its own `_blocking_violations` function. We just need the engine's `post_evaluate`.

- [ ] **Step 3: Verify**

Run: `python3 -c "from rampart.app.policy.engine import PolicyEngine; print('post_evaluate:', hasattr(PolicyEngine, 'post_evaluate'))"`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/policy/engine.py
git commit -m "feat(granite): add post_evaluate method to PolicyEngine"
```

---

### Task 5: Integrate post-LLM evaluation in main.py

**Files:**
- Modify: `rampart/app/main.py`

- [ ] **Step 1: Add post-LLM evaluation and response sanitization**

In `evaluate_chat_completions`, replace the section after `proxy_chat_completion` (from the `upstream_body, upstream_status` line through the return):

```python
    upstream_body, upstream_status = await proxy_chat_completion(upstream, upstream_payload)
    if client_record and isinstance(upstream_body, dict):
        usage = upstream_body.get("usage")
        if isinstance(usage, dict):
            record_token_usage(
                client_record.id,
                usage.get("prompt_tokens", 0),
                usage.get("completion_tokens", 0),
                config.clients.path,
            )
    # Post-LLM evaluation
    if upstream_status < 400 and config.llm_evaluator.post_llm_enabled and isinstance(upstream_body, dict):
        response_text = _extract_response_text(upstream_body)
        if response_text:
            post_violations = await engine.post_evaluate(response_text)
            if post_violations:
                blocking = [v for v in post_violations if _is_post_blocking(v, policies)]
                if blocking:
                    upstream_body = _sanitize_llm_response(upstream_body)
                    upstream_body["rampart_post_violations"] = [v.model_dump() for v in post_violations]
    return JSONResponse(upstream_body, status_code=upstream_status)
```

Add these helper functions at the bottom of main.py:

```python
def _extract_response_text(body: dict[str, Any]) -> Optional[str]:
    choices = body.get("choices", [])
    if not choices or not isinstance(choices[0], dict):
        return None
    msg = choices[0].get("message")
    if not isinstance(msg, dict):
        return None
    content = msg.get("content")
    return content if isinstance(content, str) else None


def _is_post_blocking(violation, policies: list[PolicyConfig]) -> bool:
    for policy in policies:
        if policy.id == violation.policy_id:
            return policy.action == "block"
    return True


def _sanitize_llm_response(body: dict[str, Any]) -> dict[str, Any]:
    from copy import deepcopy
    sanitized = deepcopy(body)
    choices = sanitized.get("choices", [])
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message")
        if isinstance(msg, dict):
            msg["content"] = "[Response blocked by RAMPART policy]"
    return sanitized
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.main import _extract_response_text, _sanitize_llm_response; body = {'choices': [{'message': {'content': 'hello'}}]}; print('extract:', _extract_response_text(body)); s = _sanitize_llm_response(body); print('sanitized:', s['choices'][0]['message']['content'])"`

Expected:
```
extract: hello
sanitized: [Response blocked by RAMPART policy]
```

- [ ] **Step 3: Commit**

```bash
git add rampart/app/main.py
git commit -m "feat(granite): integrate post-LLM evaluation with response sanitization in chat completions"
```

---

### Task 6: Settings UI — mode dropdown, threshold, post-LLM toggle

**Files:**
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Add mode, threshold, and post-LLM fields to the Settings form**

In `_settings_form()`, find the Context Analysis LLM fieldset. After the "Enabled" checkbox div and before the Base URL label, add:

```python
          <label>Mode
            <select name="llm_evaluator_mode">
              <option value="standard" {"selected" if config.llm_evaluator.mode == "standard" else ""}>Standard (JSON prompt/response)</option>
              <option value="granite-guardian" {"selected" if config.llm_evaluator.mode == "granite-guardian" else ""}>Granite Guardian (logprobs)</option>
            </select>
          </label>
          <label>Confidence Threshold<input name="llm_evaluator_confidence_threshold" value="{get_value("llm_evaluator_confidence_threshold", config.llm_evaluator.confidence_threshold)}" placeholder="0.75" inputmode="decimal">
            <div class="hint">For Granite Guardian mode: probability threshold for violation detection (0.0-1.0). Higher = fewer false positives.</div>
          </label>
          <div>
            <label style="display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px;color:var(--text-secondary)">Post-LLM Evaluation <input type="checkbox" name="llm_evaluator_post_llm_enabled" {"checked" if config.llm_evaluator.post_llm_enabled else ""} style="width:auto"></label>
            <div class="hint" style="margin-top:4px">When enabled, the upstream LLM response is also evaluated against policies. Harmful content is sanitized before reaching the client.</div>
          </div>
```

- [ ] **Step 2: Update the POST handler to read the new fields**

In `update_settings()`, add after `llm_evaluator_timeout_seconds`:

```python
            llm_evaluator_mode=form.get("llm_evaluator_mode", "").strip(),
            llm_evaluator_confidence_threshold=_optional_float(form.get("llm_evaluator_confidence_threshold", "")),
            llm_evaluator_post_llm_enabled=form.get("llm_evaluator_post_llm_enabled") == "on",
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from rampart.app.config import get_config; print('OK')"`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(granite): add mode dropdown, confidence threshold, and post-LLM toggle to Settings UI"
```

---

### Task 7: Run tests and verify

**Files:**
- Read: `tests/`

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All 37 tests pass. No regressions — the new config fields have defaults, standard mode is unchanged, post-LLM is disabled by default.

- [ ] **Step 2: Functional test — standard mode still works**

Run: `python3 -c "
import asyncio
from rampart.app.llm.evaluator import LlmEvaluator, _check_matches_stage, _parse_guardian_response
from rampart.app.config import get_config, CheckConfig

# Stage filtering
c1 = CheckConfig(type='llm', instruction='test')
c2 = CheckConfig(type='llm', instruction='test', stage='pre')
c3 = CheckConfig(type='llm', instruction='test', stage='post')
c4 = CheckConfig(type='llm', instruction='test', stage='both')
print('none/pre:', _check_matches_stage(c1, 'pre'))   # True
print('pre/pre:', _check_matches_stage(c2, 'pre'))    # True
print('post/pre:', _check_matches_stage(c3, 'pre'))   # False
print('both/pre:', _check_matches_stage(c4, 'pre'))   # True
print('pre/post:', _check_matches_stage(c2, 'post'))  # False
print('post/post:', _check_matches_stage(c3, 'post')) # True

# Guardian response parsing
v, c, t = _parse_guardian_response({'choices': [{'message': {'content': 'No'}, 'logprobs': {'content': [{'token': 'No', 'logprob': -0.01, 'top_logprobs': [{'token': 'No', 'logprob': -0.01}, {'token': 'Yes', 'logprob': -5.0}]}]}}]}, 0.75)
print('no_violation:', not v, 'conf:', round(c, 4))
"`

- [ ] **Step 3: Commit (if fixes needed)**

```bash
git add -A
git commit -m "fix: resolve granite guardian integration issues"
```
