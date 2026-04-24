from copy import deepcopy
from hashlib import sha256
from time import time
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from rampart.app.client_store import ClientRecord, client_context_from_record, record_evaluation, record_token_usage, resolve_client_from_api_key
from rampart.app.config import AppConfig, PolicyConfig, UpstreamConfig, get_config
from rampart.app.models import EvaluationRequest, EvaluationResponse, HealthResponse
from rampart.app.openai.proxy import openai_policy_error, proxy_chat_completion, proxy_chat_completion_stream

# Evaluation cache: hash(prompt + policy_ids) -> (EvaluationResponse, timestamp)
_eval_cache: dict[str, tuple[EvaluationResponse, float]] = {}
CACHE_TTL = 300  # 5 minutes
CACHE_MAX_SIZE = 1000
from rampart.app.policy.engine import PolicyEngine
from rampart.app.tracking import ClientContext, write_evaluation_event
from rampart.app.enrollment import router as enrollment_router
from rampart.app.extension import router as extension_router
from rampart.app.mcp_server import router as mcp_router
from rampart.app.playground import router as playground_router
from rampart.app.ui import router as ui_router

app = FastAPI(
    title="RAMPART",
    description="Request And Model Prompt Analysis & Routing Tool",
    version="0.1.0",
)

# Start mTLS identity server if certs are available
from rampart.app.identity import start_identity_server
start_identity_server()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ui_router)
app.include_router(playground_router)
app.include_router(extension_router)
app.include_router(enrollment_router)
app.include_router(mcp_router)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/v1/rampart/evaluate", response_model=EvaluationResponse)
async def evaluate(payload: EvaluationRequest, request: Request) -> EvaluationResponse:
    config = get_config()
    client_record = _resolve_client_record(config, request)
    policies = _resolve_policies(config, client_record)
    engine = PolicyEngine(config, policies)
    response = await engine.evaluate(payload.request)
    _track_evaluation(config, request, response, client_record, policies)
    if client_record:
        record_evaluation(client_record.id, len(response.violations), config.clients.path)
    return response


@app.post("/v1/chat/completions")
async def evaluate_chat_completions(payload: dict[str, Any], request: Request):
    config = get_config()
    client_record = _resolve_client_record(config, request)
    policies = _resolve_policies(config, client_record)
    is_streaming = payload.get("stream", False)

    # Check evaluation cache
    cache_key = _eval_cache_key(payload, policies)
    response = _get_cached_eval(cache_key)

    if response is None:
        engine = PolicyEngine(config, policies)
        response = await engine.evaluate(payload)
        _set_cached_eval(cache_key, response)

    _track_evaluation(config, request, response, client_record, policies)
    if client_record:
        record_evaluation(client_record.id, len(response.violations), config.clients.path)
    blocking_violations = _blocking_violations(response, policies)
    if blocking_violations:
        return JSONResponse(
            openai_policy_error("RAMPART policy violation", [violation.model_dump() for violation in blocking_violations]),
            status_code=400,
        )
    if not config.upstream.enabled:
        return response
    upstream = _effective_upstream(config, client_record)
    upstream_payload = response.sanitized_request if response.violations and response.sanitized_request else payload
    upstream_payload = _apply_model_override(upstream_payload, upstream.model)

    # Streaming response — pass through SSE chunks directly
    if is_streaming:
        return StreamingResponse(
            proxy_chat_completion_stream(upstream, upstream_payload),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

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


def _resolve_client_record(config: AppConfig, request: Request) -> Optional[ClientRecord]:
    api_key = request.headers.get("authorization") or request.headers.get("x-rampart-api-key")
    return resolve_client_from_api_key(api_key, config.clients.path)


def _resolve_policies(config: AppConfig, client: Optional[ClientRecord]) -> list[PolicyConfig]:
    enabled_policies = [policy for policy in config.policies if policy.enabled]
    if client is None:
        return enabled_policies
    # Group-enrolled clients: resolve policies from the group (always dynamic)
    if client.group_id:
        from rampart.app.group_store import get_group
        group = get_group(client.group_id)
        if group and group.policy_ids:
            assigned = set(group.policy_ids)
            return [policy for policy in enabled_policies if policy.id in assigned]
        return enabled_policies
    # Non-group clients: use direct policy assignment
    if not client.policy_ids:
        return enabled_policies
    assigned = set(client.policy_ids)
    return [policy for policy in enabled_policies if policy.id in assigned]


def _blocking_violations(response: EvaluationResponse, policies: list[PolicyConfig]):
    blocking_policy_ids = {policy.id for policy in policies if policy.action == "block"}
    return [violation for violation in response.violations if violation.policy_id in blocking_policy_ids]


def _effective_upstream(config: AppConfig, client: Optional[ClientRecord]) -> UpstreamConfig:
    upstream = config.upstream.model_copy()
    if client is None:
        return upstream
    if client.upstream_base_url:
        upstream.base_url = client.upstream_base_url
    if client.upstream_model:
        upstream.model = client.upstream_model
    if client.upstream_api_key:
        upstream.api_key = client.upstream_api_key
    if client.upstream_timeout_seconds is not None:
        upstream.timeout_seconds = client.upstream_timeout_seconds
    return upstream


def _apply_model_override(payload: dict[str, Any], model: str) -> dict[str, Any]:
    if not model:
        return payload
    updated = deepcopy(payload)
    updated["model"] = model
    return updated


def _track_evaluation(config, request: Request, response: EvaluationResponse, client_record: Optional[ClientRecord], policies: list[PolicyConfig]) -> None:
    fallback = ClientContext(
        customer=request.headers.get("x-rampart-customer", "default"),
        client_id=request.headers.get("x-rampart-client-id", "default-client"),
        owner=request.headers.get("x-rampart-owner"),
        request_id=request.headers.get("x-request-id"),
    )
    client = client_context_from_record(client_record, fallback)
    applied_policies = [policy.id for policy in policies if policy.enabled]
    write_evaluation_event(config.tracking, client, response, applied_policies)


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
    sanitized = deepcopy(body)
    choices = sanitized.get("choices", [])
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message")
        if isinstance(msg, dict):
            msg["content"] = "[Response blocked by RAMPART policy]"
    return sanitized


def _eval_cache_key(payload: dict[str, Any], policies: list[PolicyConfig]) -> str:
    import json
    messages = payload.get("messages", [])
    policy_ids = sorted(p.id for p in policies)
    raw = json.dumps(messages, sort_keys=True) + "|" + ",".join(policy_ids)
    return sha256(raw.encode()).hexdigest()


def _get_cached_eval(key: str) -> Optional[EvaluationResponse]:
    entry = _eval_cache.get(key)
    if entry is None:
        return None
    response, ts = entry
    if time() - ts > CACHE_TTL:
        del _eval_cache[key]
        return None
    return response


def _set_cached_eval(key: str, response: EvaluationResponse) -> None:
    # Evict oldest entries if cache is full
    if len(_eval_cache) >= CACHE_MAX_SIZE:
        oldest = min(_eval_cache, key=lambda k: _eval_cache[k][1])
        del _eval_cache[oldest]
    _eval_cache[key] = (response, time())
