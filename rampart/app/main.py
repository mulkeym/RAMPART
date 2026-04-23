from copy import deepcopy
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from rampart.app.client_store import ClientRecord, client_context_from_record, resolve_client_from_api_key
from rampart.app.config import AppConfig, PolicyConfig, UpstreamConfig, get_config
from rampart.app.models import EvaluationRequest, EvaluationResponse, HealthResponse
from rampart.app.openai.proxy import openai_policy_error, proxy_chat_completion
from rampart.app.policy.engine import PolicyEngine
from rampart.app.tracking import ClientContext, write_evaluation_event
from rampart.app.ui import router as ui_router

app = FastAPI(
    title="RAMPART",
    description="Request And Model Prompt Analysis & Routing Tool",
    version="0.1.0",
)
app.include_router(ui_router)


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
    return response


@app.post("/v1/chat/completions")
async def evaluate_chat_completions(payload: dict[str, Any], request: Request):
    config = get_config()
    client_record = _resolve_client_record(config, request)
    policies = _resolve_policies(config, client_record)
    engine = PolicyEngine(config, policies)
    response = await engine.evaluate(payload)
    _track_evaluation(config, request, response, client_record, policies)
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
    upstream_body, upstream_status = await proxy_chat_completion(upstream, upstream_payload)
    return JSONResponse(upstream_body, status_code=upstream_status)


def _resolve_client_record(config: AppConfig, request: Request) -> Optional[ClientRecord]:
    api_key = request.headers.get("authorization") or request.headers.get("x-rampart-api-key")
    return resolve_client_from_api_key(api_key, config.clients.path)


def _resolve_policies(config: AppConfig, client: Optional[ClientRecord]) -> list[PolicyConfig]:
    enabled_policies = [policy for policy in config.policies if policy.enabled]
    if client is None or not client.policy_ids:
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
