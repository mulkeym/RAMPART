import asyncio
from copy import deepcopy
from hashlib import sha256
import logging
from time import time
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from rampart.app.client_store import ClientRecord, client_context_from_record, record_evaluation, record_token_usage, resolve_client_from_api_key
from rampart.app.config import AppConfig, PolicyConfig, UpstreamConfig, UserGroupResolverConfig, get_config
from rampart.app.models import EvaluationRequest, EvaluationResponse, HealthResponse
from rampart.app.openai.compat import extract_user
from rampart.app.openai.proxy import openai_policy_error, proxy_chat_completion, proxy_chat_completion_stream

# Evaluation cache: hash(prompt + policy_ids) -> (EvaluationResponse, timestamp)
_eval_cache: dict[str, tuple[EvaluationResponse, float]] = {}
CACHE_TTL = 300  # 5 minutes
CACHE_MAX_SIZE = 1000
from rampart.app.policy.engine import PolicyEngine
from rampart.app.prompt_log import PromptLogEntry, PolicyResult, build_policy_results, log_prompt
from rampart.app.tracking import ClientContext, write_evaluation_event

logger = logging.getLogger(__name__)

# Singleton state for UserGroupResolver
_resolver_instance: Optional[Any] = None
_resolver_config_snapshot: Optional[UserGroupResolverConfig] = None
from rampart.app.discovery import router as discovery_router
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
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ui_router)
app.include_router(playground_router)
app.include_router(extension_router)
app.include_router(enrollment_router)
app.include_router(discovery_router)
app.include_router(mcp_router)


@app.on_event("startup")
async def _start_cache_persistence():
    config = get_config()
    if not config.user_group_resolver.enabled:
        return
    interval = config.user_group_resolver.cache_persist_interval_seconds

    async def _persist_loop():
        while True:
            await asyncio.sleep(interval)
            if _resolver_instance is not None:
                _resolver_instance.persist()

    asyncio.create_task(_persist_loop())


@app.on_event("startup")
async def _start_syslog_forwarder():
    config = get_config()
    if not config.syslog.enabled:
        return
    from rampart.app.syslog_forwarder import SyslogSender, format_cef, init_shared_sender
    from rampart.app.prompt_log import get_entries_since

    init_shared_sender(config.syslog.host, config.syslog.port, config.syslog.protocol)
    sender = SyslogSender(config.syslog.host, config.syslog.port, config.syslog.protocol)
    interval = config.syslog.send_interval_seconds

    async def _forward_loop():
        cursor = 0
        while True:
            await asyncio.sleep(interval)
            try:
                entries, cursor = get_entries_since(cursor)
                for entry in entries:
                    try:
                        sender.send(format_cef(entry))
                    except OSError:
                        logger.warning("Syslog send failed to %s:%d, skipping batch", config.syslog.host, config.syslog.port)
                        break
            except Exception:
                logger.exception("Syslog forwarder error")

    asyncio.create_task(_forward_loop())


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/v1/rampart/evaluate", response_model=EvaluationResponse)
async def evaluate(payload: EvaluationRequest, request: Request) -> EvaluationResponse:
    config = get_config()
    client_record = _resolve_client_record(config, request)
    user = extract_user(payload.request)
    policies = await _resolve_policies(config, client_record, user=user)
    engine = PolicyEngine(config, policies)
    start = time()
    response = await engine.evaluate(payload.request)
    eval_ms = int((time() - start) * 1000)
    _track_evaluation(config, request, response, client_record, policies, user=user)
    _log_prompt(request, payload.request, response, policies, client_record, user, eval_ms, source="api")
    if client_record:
        record_evaluation(client_record.id, len(response.violations), config.clients.path)
    return response


@app.post("/v1/chat/completions")
async def evaluate_chat_completions(payload: dict[str, Any], request: Request):
    config = get_config()
    client_record = _resolve_client_record(config, request)
    user = extract_user(payload)
    policies = await _resolve_policies(config, client_record, user=user)
    is_streaming = payload.get("stream", False)

    # Check evaluation cache
    cache_key = _eval_cache_key(payload, policies)
    response = _get_cached_eval(cache_key)

    if response is None:
        engine = PolicyEngine(config, policies)
        start = time()
        response = await engine.evaluate(payload)
        eval_ms = int((time() - start) * 1000)
        _set_cached_eval(cache_key, response)
    else:
        eval_ms = 0  # cached

    _track_evaluation(config, request, response, client_record, policies, user=user)
    _log_prompt(request, payload, response, policies, client_record, user, eval_ms, source="gateway")
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


def _get_or_create_resolver(resolver_config: UserGroupResolverConfig):
    """Return a cached UserGroupResolver, recreating if config changed."""
    global _resolver_instance, _resolver_config_snapshot
    from rampart.app.user_group_resolver import UserGroupResolver

    if _resolver_instance is not None and _resolver_config_snapshot == resolver_config:
        return _resolver_instance

    if resolver_config.provider == "keycloak":
        from rampart.app.group_providers.keycloak import KeycloakGroupProvider
        kc = resolver_config.keycloak
        provider = KeycloakGroupProvider(
            base_url=kc.base_url,
            realm=kc.realm,
            client_id=kc.client_id,
            client_secret=kc.client_secret,
        )
    else:
        raise ValueError(f"Unknown group provider: {resolver_config.provider}")

    resolver = UserGroupResolver(
        provider=provider,
        cache_path=resolver_config.cache_path,
        cache_ttl_seconds=resolver_config.cache_ttl_seconds,
        cache_max_size=resolver_config.cache_max_size,
    )
    resolver.load()
    _resolver_instance = resolver
    _resolver_config_snapshot = resolver_config.model_copy(deep=True)
    return resolver


class _UserGroupResult:
    """Holds resolved group info for prompt logging."""
    __slots__ = ("external_groups", "rampart_group_ids", "policies")

    def __init__(self, external_groups: list[str], rampart_group_ids: list[str], policies: list[PolicyConfig]):
        self.external_groups = external_groups
        self.rampart_group_ids = rampart_group_ids
        self.policies = policies


async def resolve_policies_for_user(config: AppConfig, user: str) -> Optional[_UserGroupResult]:
    """Resolve policies for a user via external group provider and mapping store."""
    resolver_config = config.user_group_resolver
    resolver = _get_or_create_resolver(resolver_config)

    external_groups = await resolver.resolve(user)
    if not external_groups:
        return None

    from rampart.app.group_mapping_store import list_mappings
    from rampart.app.group_store import get_group

    mappings = list_mappings(resolver_config.mappings_path)
    external_set = set(external_groups)

    matched_policy_ids: set[str] = set()
    rampart_group_ids: list[str] = []
    enabled_policies = [p for p in config.policies if p.enabled]

    for mapping in mappings:
        if not mapping.enabled:
            continue
        if mapping.external_group in external_set:
            group = get_group(mapping.rampart_group_id)
            if group:
                rampart_group_ids.append(group.id)
                if group.policy_ids:
                    matched_policy_ids.update(group.policy_ids)

    if not matched_policy_ids:
        return _UserGroupResult(external_groups, rampart_group_ids, [])

    policies = [p for p in enabled_policies if p.id in matched_policy_ids]
    return _UserGroupResult(external_groups, rampart_group_ids, policies)


# Stashed group resolution result for current request (used by _log_prompt)
_last_user_group_result: Optional[_UserGroupResult] = None


async def _resolve_policies(config: AppConfig, client: Optional[ClientRecord], user: Optional[str] = None) -> list[PolicyConfig]:
    global _last_user_group_result
    _last_user_group_result = None
    enabled_policies = [policy for policy in config.policies if policy.enabled]

    # If user is present and resolver is enabled, try user-based resolution first
    if user and config.user_group_resolver.enabled:
        try:
            result = await resolve_policies_for_user(config, user)
            if result and result.policies:
                _last_user_group_result = result
                return result.policies
            elif result:
                _last_user_group_result = result  # groups resolved but no policy match
        except Exception:
            logger.exception("User group resolver failed for user=%s, falling back", user)

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


def _track_evaluation(config, request: Request, response: EvaluationResponse, client_record: Optional[ClientRecord], policies: list[PolicyConfig], user: Optional[str] = None) -> None:
    fallback = ClientContext(
        customer=request.headers.get("x-rampart-customer", "default"),
        client_id=request.headers.get("x-rampart-client-id", "default-client"),
        owner=request.headers.get("x-rampart-owner"),
        request_id=request.headers.get("x-request-id"),
        user=user,
    )
    client = client_context_from_record(client_record, fallback)
    applied_policies = [policy.id for policy in policies if policy.enabled]
    write_evaluation_event(config.tracking, client, response, applied_policies)


def _log_prompt(
    request: Request,
    openai_request: dict[str, Any],
    response: EvaluationResponse,
    policies: list[PolicyConfig],
    client_record: Optional[ClientRecord],
    user: Optional[str],
    eval_ms: int,
    source: str,
) -> None:
    grp = _last_user_group_result
    log_prompt(PromptLogEntry(
        source=source,
        user=user,
        client_id=client_record.id if client_record else None,
        owner=(client_record.owner_email or client_record.owner_name) if client_record else None,
        source_ip=request.client.host if request.client else None,
        model=openai_request.get("model"),
        messages=openai_request.get("messages", []),
        resolved_groups=grp.external_groups if grp else [],
        mapped_rampart_groups=grp.rampart_group_ids if grp else [],
        decision=response.decision,
        policy_results=build_policy_results(policies, response.violations),
        violations=[v.model_dump() for v in response.violations],
        applied_policies=[p.id for p in policies if p.enabled],
        eval_ms=eval_ms,
        warnings=response.warnings or [],
    ))


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
