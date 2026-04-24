# Granite Guardian Mode + Post-LLM Response Evaluation

## Overview

Add IBM Granite Guardian support to the LLM evaluator and introduce post-LLM response evaluation. Granite Guardian is a specialized safety model that uses logprobs-based thresholding instead of JSON generation, making it significantly faster for policy evaluation. Post-LLM evaluation checks the upstream LLM's response against policies after it's generated, sanitizing harmful content before it reaches the client.

## Goals

1. **Granite Guardian mode** — Alternative evaluation mode using `chat_template_kwargs` + logprobs instead of JSON prompt/response. Faster, purpose-built for safety.
2. **Post-LLM evaluation** — Evaluate upstream LLM responses against policies after generation. Catches harmful outputs the model produced.
3. **Response sanitization** — When post-LLM checks find violations, redact the flagged content from the response before returning it.
4. **Backward compatible** — Standard mode (current JSON-based) remains the default. Granite Guardian is opt-in via config.

## Constraints

- Standard mode unchanged — existing deployments unaffected
- Granite Guardian mode is text-only (context LLM evaluator only, not vision)
- Post-LLM evaluation reuses the same evaluator config and policies
- `stage` field on checks controls when they run (pre, post, or both)

## Config Changes

### LlmEvaluatorConfig

Three new fields:

```python
class LlmEvaluatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://192.168.1.181:8080/v1"
    model: str = "gemma4-e2b"
    timeout_seconds: float = 20.0
    fail_closed_on_error: bool = True
    mode: str = "standard"                # "standard" or "granite-guardian"
    confidence_threshold: float = 0.75    # For granite-guardian: P("Yes") > threshold = violation
    post_llm_enabled: bool = False        # Enable post-LLM response evaluation
```

### CheckConfig

New optional field:

```python
class CheckConfig(BaseModel):
    ...existing fields...
    stage: Optional[str] = None  # "pre", "post", "both", or None (defaults to "both")
```

- `"pre"` — only evaluate the incoming request (before upstream LLM)
- `"post"` — only evaluate the LLM response (after upstream LLM)
- `"both"` or `None` — evaluate at both stages
- Only applies to `type: llm` checks. Deterministic checks always run pre-LLM.

## Granite Guardian Request Format

When `mode: "granite-guardian"`, the evaluator sends:

```json
{
  "model": "granite-guardian-3.1-8b",
  "messages": [
    {"role": "user", "content": "<the user message text>"}
  ],
  "chat_template_kwargs": {
    "guardian_config": {
      "risk_name": "<policy.id>",
      "risk_definition": "<check.instruction or policy.description>"
    }
  },
  "logprobs": true,
  "top_logprobs": 5,
  "max_tokens": 20
}
```

For post-LLM evaluation, the message content is the LLM's response text instead of the user's request.

## Granite Guardian Response Parsing

The model outputs "Yes" (violation) or "No" (safe). Parse the logprobs:

```python
def _parse_guardian_response(response_body: dict, threshold: float) -> tuple[bool, float, str]:
    """Returns (violates, confidence, message)."""
    choices = response_body.get("choices", [])
    if not choices:
        return False, 0.0, ""
    
    choice = choices[0]
    content = (choice.get("message") or {}).get("content", "").strip()
    
    # Check logprobs for confidence
    logprobs = choice.get("logprobs", {})
    if logprobs and logprobs.get("content"):
        first_token = logprobs["content"][0]
        top = first_token.get("top_logprobs", [])
        yes_prob = 0.0
        for entry in top:
            if entry.get("token", "").strip().lower() == "yes":
                import math
                yes_prob = math.exp(entry.get("logprob", -100))
                break
        return yes_prob > threshold, yes_prob, content
    
    # Fallback: just check text content
    violates = content.lower().startswith("yes")
    return violates, 1.0 if violates else 0.0, content
```

## LLM Evaluator Changes

### evaluate() method — pre-LLM (existing, enhanced)

The existing `evaluate(request)` method gains stage filtering:

```python
async def evaluate(self, request: dict, stage: str = "pre") -> list[Violation]:
    # Filter checks by stage
    checks = [
        (policy, check) for policy, check in all_llm_checks
        if check.stage in (None, stage, "both")
    ]
    # Route to standard or granite-guardian based on mode
    if mode == "granite-guardian":
        return await self._evaluate_guardian(request_text, checks)
    else:
        return await self._evaluate_standard(request_json, checks)
```

### New: evaluate_response() — post-LLM

New method for evaluating the LLM's response:

```python
async def evaluate_response(self, response_text: str) -> list[Violation]:
    """Evaluate an LLM response against post-stage policies."""
    if not self.config.llm_evaluator.post_llm_enabled:
        return []
    return await self.evaluate({"messages": [{"role": "assistant", "content": response_text}]}, stage="post")
```

### Granite Guardian evaluation

```python
async def _evaluate_guardian(self, text: str, checks) -> list[Violation]:
    """Evaluate using Granite Guardian format — parallel, one call per check."""
    results = await asyncio.gather(*(
        self._evaluate_guardian_check(text, policy, check)
        for policy, check in checks
    ))
    ...
```

Each `_evaluate_guardian_check` builds the guardian-format request and parses logprobs.

## Post-LLM Flow in main.py

```python
@app.post("/v1/chat/completions")
async def evaluate_chat_completions(payload, request):
    # ... existing pre-LLM evaluation ...
    
    # Send to upstream
    upstream_body, upstream_status = await proxy_chat_completion(upstream, upstream_payload)
    
    # Post-LLM evaluation (if enabled and response is successful)
    if upstream_status < 400 and config.llm_evaluator.post_llm_enabled:
        response_text = _extract_response_text(upstream_body)
        if response_text:
            post_violations = await engine.evaluate_response(response_text)
            if post_violations:
                blocking = [v for v in post_violations if _is_post_blocking(v, engine.policies)]
                if blocking:
                    upstream_body = _sanitize_llm_response(upstream_body, response_text)
                    # Add violation metadata to response
                    upstream_body["rampart_violations"] = [v.model_dump() for v in post_violations]
    
    # Track token usage...
    return JSONResponse(upstream_body, ...)
```

## Response Sanitization

When post-LLM checks find a blocking violation, the LLM's response content is redacted:

```python
def _sanitize_llm_response(body: dict, original_text: str) -> dict:
    """Replace the LLM response content with a sanitized message."""
    sanitized = deepcopy(body)
    choices = sanitized.get("choices", [])
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message", {})
        if isinstance(msg, dict):
            msg["content"] = "[Response blocked by RAMPART policy]"
    return sanitized
```

The full original response is replaced — partial redaction of LLM output is unreliable since harmful content could be woven throughout.

## Settings UI Changes

Add to the "Context Analysis LLM" fieldset:

- **Mode** dropdown: "Standard" / "Granite Guardian"
- **Confidence Threshold** number input (shown only when mode is granite-guardian)
- **Post-LLM Evaluation** checkbox with hint: "When enabled, the upstream LLM's response is also evaluated against policies. Harmful content is sanitized before reaching the client."

## RuntimeSettings Changes

```python
llm_evaluator_mode: str = ""
llm_evaluator_confidence_threshold: Optional[float] = None
llm_evaluator_post_llm_enabled: Optional[bool] = None
```

## Implementation Scope

### Modified Files

1. `rampart/app/config.py` — Add `mode`, `confidence_threshold`, `post_llm_enabled` to `LlmEvaluatorConfig`. Add `stage` to `CheckConfig`.
2. `rampart/app/llm/evaluator.py` — Add granite guardian request/response handling, stage filtering, `evaluate_response()` method. Refactor `evaluate()` to support both modes.
3. `rampart/app/policy/engine.py` — Add `post_evaluate()` method that calls `llm_evaluator.evaluate_response()`.
4. `rampart/app/main.py` — Call `engine.post_evaluate()` after upstream response, sanitize if violations found.
5. `rampart/app/settings_store.py` — Add `llm_evaluator_mode`, `llm_evaluator_confidence_threshold`, `llm_evaluator_post_llm_enabled`.
6. `rampart/app/ui.py` — Add mode dropdown, threshold, post-LLM toggle to Settings form + POST handler.

### Not Modified

- Vision evaluator (stays standard mode only)
- Policy YAML format (existing policies work in both modes)
- MCP tools, playground (they call `engine.evaluate()` which handles mode internally)
