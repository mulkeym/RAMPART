from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

import yaml
from pydantic import BaseModel, Field


class LlmEvaluatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://192.168.1.181:8080/v1"
    model: str = "gemma4-e2b"
    timeout_seconds: float = 20.0
    fail_closed_on_error: bool = True
    mode: str = "standard"
    confidence_threshold: float = 0.75
    post_llm_enabled: bool = False


class VisionEvaluatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://192.168.1.181:8081/v1"
    model: str = ""
    timeout_seconds: float = 30.0
    fail_closed_on_error: bool = True


class FailureResponseConfig(BaseModel):
    include_sanitized_request: bool = False


class KeycloakAdminAuthConfig(BaseModel):
    enabled: bool = False
    base_url: str = ""
    realm: str = ""
    client_id: str = ""
    client_secret: str = ""
    verify_ssl: bool = True


class AuthConfig(BaseModel):
    admin_username: str = "admin"
    admin_password: str = ""
    admin_password_hash: str = ""
    local_auth_enabled: bool = True
    auth_state_path: str = "data/auth.json"
    session_secret: str = ""
    session_cookie_name: str = "rampart_session"
    session_max_age_seconds: int = 28800
    secure_cookies: bool = False
    audit_log_path: str = "logs/audit.jsonl"
    mcp_enabled: bool = False
    mcp_admin_key: str = ""
    mcp_admin_write: bool = False
    keycloak_admin: KeycloakAdminAuthConfig = Field(default_factory=KeycloakAdminAuthConfig)


class ClientStoreConfig(BaseModel):
    path: str = "data/clients.json"


class SettingsStoreConfig(BaseModel):
    path: str = "data/settings.json"


class TrackingConfig(BaseModel):
    enabled: bool = True
    log_path: str = "logs/evaluations.jsonl"
    log_accepted_requests: bool = False
    include_sanitized_prompt: bool = False


class UpstreamConfig(BaseModel):
    enabled: bool = True
    base_url: str = "http://192.168.1.181:8000/v1"
    model: str = ""
    api_key: str = ""
    timeout_seconds: float = 120.0


class CheckConfig(BaseModel):
    type: str
    pattern: Optional[str] = None
    instruction: Optional[str] = None
    allowed_tools: Optional[list[str]] = None
    denied_tools: Optional[list[str]] = None
    allowed_models: Optional[list[str]] = None
    max_chars: Optional[int] = None
    skip_vision: Optional[bool] = None
    stage: Optional[str] = None


class PolicyConfig(BaseModel):
    id: str
    enabled: bool = True
    severity: str = "medium"
    category: str = "policy"
    description: str = ""
    action: str = "block"
    checks: list[CheckConfig] = Field(default_factory=list)


class KeycloakConfig(BaseModel):
    base_url: str = ""
    realm: str = ""
    client_id: str = ""
    client_secret: str = ""
    verify_ssl: bool = True


class UserGroupResolverConfig(BaseModel):
    enabled: bool = False
    provider: str = "keycloak"
    cache_ttl_seconds: int = 900
    cache_max_size: int = 20000
    cache_persist_interval_seconds: int = 60
    cache_path: str = "data/user_group_cache.json"
    mappings_path: str = "data/group_mappings.json"
    keycloak: KeycloakConfig = Field(default_factory=KeycloakConfig)


class SyslogConfig(BaseModel):
    enabled: bool = False
    protocol: str = "udp"
    host: str = "127.0.0.1"
    port: int = 514
    send_interval_seconds: int = 5


class AppConfig(BaseModel):
    version: int = 1
    llm_evaluator: LlmEvaluatorConfig = Field(default_factory=LlmEvaluatorConfig)
    vision_evaluator: VisionEvaluatorConfig = Field(default_factory=VisionEvaluatorConfig)
    failure_response: FailureResponseConfig = Field(default_factory=FailureResponseConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    clients: ClientStoreConfig = Field(default_factory=ClientStoreConfig)
    settings: SettingsStoreConfig = Field(default_factory=SettingsStoreConfig)
    tracking: TrackingConfig = Field(default_factory=TrackingConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    policies: list[PolicyConfig] = Field(default_factory=list)
    user_group_resolver: UserGroupResolverConfig = Field(default_factory=UserGroupResolverConfig)
    syslog: SyslogConfig = Field(default_factory=SyslogConfig)


def default_policy_path() -> Path:
    return Path(__file__).resolve().parents[2] / "policies" / "default.yaml"


def load_config(path: Optional[Union[str, Path]] = None) -> AppConfig:
    policy_path = get_policy_path(path)
    with policy_path.open("r", encoding="utf-8") as policy_file:
        data = yaml.safe_load(policy_file) or {}
    config = AppConfig.model_validate(data)
    _apply_local_settings(config)
    _apply_env_overrides(config)
    return config


def get_policy_path(path: Optional[Union[str, Path]] = None) -> Path:
    return Path(path or os.getenv("RAMPART_POLICY_FILE") or default_policy_path())


def save_config(config: AppConfig, path: Optional[Union[str, Path]] = None) -> None:
    policy_path = get_policy_path(path)
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    data = config.model_dump(exclude_none=True, exclude={"auth"})
    with policy_path.open("w", encoding="utf-8") as policy_file:
        yaml.safe_dump(data, policy_file, sort_keys=False, allow_unicode=False)


def get_config() -> AppConfig:
    return load_config()


def _apply_env_overrides(config: AppConfig) -> None:
    auth = config.auth
    auth.admin_username = os.getenv("RAMPART_ADMIN_USERNAME", auth.admin_username)
    auth.admin_password = os.getenv("RAMPART_ADMIN_PASSWORD", auth.admin_password)
    auth.admin_password_hash = os.getenv("RAMPART_ADMIN_PASSWORD_HASH", auth.admin_password_hash)
    auth.auth_state_path = os.getenv("RAMPART_AUTH_STATE", auth.auth_state_path)
    auth.session_secret = os.getenv("RAMPART_SESSION_SECRET", auth.session_secret)
    auth.audit_log_path = os.getenv("RAMPART_AUDIT_LOG", auth.audit_log_path)
    auth.secure_cookies = _env_bool("RAMPART_SECURE_COOKIES", auth.secure_cookies)
    auth.mcp_admin_key = os.getenv("RAMPART_MCP_ADMIN_KEY", auth.mcp_admin_key)
    kca = auth.keycloak_admin
    kca.base_url = os.getenv("RAMPART_KC_ADMIN_BASE_URL", kca.base_url)
    kca.realm = os.getenv("RAMPART_KC_ADMIN_REALM", kca.realm)
    kca.client_id = os.getenv("RAMPART_KC_ADMIN_CLIENT_ID", kca.client_id)
    kca.client_secret = os.getenv("RAMPART_KC_ADMIN_CLIENT_SECRET", kca.client_secret)
    kca.verify_ssl = _env_bool("RAMPART_KC_ADMIN_VERIFY_SSL", kca.verify_ssl)
    tracking = config.tracking
    tracking.enabled = _env_bool("RAMPART_TRACKING_ENABLED", tracking.enabled)
    tracking.log_path = os.getenv("RAMPART_EVALUATION_LOG", tracking.log_path)
    tracking.log_accepted_requests = _env_bool("RAMPART_LOG_ACCEPTED_REQUESTS", tracking.log_accepted_requests)
    tracking.include_sanitized_prompt = _env_bool("RAMPART_TRACKING_INCLUDE_SANITIZED_PROMPT", tracking.include_sanitized_prompt)
    config.clients.path = os.getenv("RAMPART_CLIENT_STORE", config.clients.path)
    config.settings.path = os.getenv("RAMPART_SETTINGS_FILE", config.settings.path)
    upstream = config.upstream
    upstream.enabled = _env_bool("RAMPART_UPSTREAM_ENABLED", upstream.enabled)
    upstream.base_url = os.getenv("RAMPART_UPSTREAM_BASE_URL", upstream.base_url)
    upstream.model = os.getenv("RAMPART_UPSTREAM_MODEL", upstream.model)
    upstream.api_key = os.getenv("RAMPART_UPSTREAM_API_KEY", upstream.api_key)
    llm = config.llm_evaluator
    llm.base_url = os.getenv("RAMPART_LLM_EVALUATOR_BASE_URL", llm.base_url)
    llm.model = os.getenv("RAMPART_LLM_EVALUATOR_MODEL", llm.model)
    vision = config.vision_evaluator
    vision.base_url = os.getenv("RAMPART_VISION_EVALUATOR_BASE_URL", vision.base_url)
    vision.model = os.getenv("RAMPART_VISION_EVALUATOR_MODEL", vision.model)
    resolver = config.user_group_resolver
    resolver.keycloak.base_url = os.getenv("RAMPART_KEYCLOAK_BASE_URL", resolver.keycloak.base_url)
    resolver.keycloak.realm = os.getenv("RAMPART_KEYCLOAK_REALM", resolver.keycloak.realm)
    resolver.keycloak.client_id = os.getenv("RAMPART_KEYCLOAK_CLIENT_ID", resolver.keycloak.client_id)
    resolver.keycloak.client_secret = os.getenv("RAMPART_KEYCLOAK_CLIENT_SECRET", resolver.keycloak.client_secret)
    resolver.keycloak.verify_ssl = _env_bool("RAMPART_KEYCLOAK_VERIFY_SSL", resolver.keycloak.verify_ssl)
    syslog = config.syslog
    syslog.enabled = _env_bool("RAMPART_SYSLOG_ENABLED", syslog.enabled)
    syslog.protocol = os.getenv("RAMPART_SYSLOG_PROTOCOL", syslog.protocol)
    syslog.host = os.getenv("RAMPART_SYSLOG_HOST", syslog.host)
    if os.getenv("RAMPART_SYSLOG_PORT"):
        syslog.port = int(os.getenv("RAMPART_SYSLOG_PORT"))


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _apply_local_settings(config: AppConfig) -> None:
    from rampart.app.settings_store import load_settings

    settings = load_settings(config.settings.path)
    if settings.llm_evaluator_enabled is not None:
        config.llm_evaluator.enabled = settings.llm_evaluator_enabled
    if settings.llm_evaluator_base_url:
        config.llm_evaluator.base_url = settings.llm_evaluator_base_url
    if settings.llm_evaluator_model:
        config.llm_evaluator.model = settings.llm_evaluator_model
    if settings.llm_evaluator_timeout_seconds is not None:
        config.llm_evaluator.timeout_seconds = settings.llm_evaluator_timeout_seconds
    if settings.llm_evaluator_mode:
        config.llm_evaluator.mode = settings.llm_evaluator_mode
    if settings.llm_evaluator_confidence_threshold is not None:
        config.llm_evaluator.confidence_threshold = settings.llm_evaluator_confidence_threshold
    if settings.llm_evaluator_post_llm_enabled is not None:
        config.llm_evaluator.post_llm_enabled = settings.llm_evaluator_post_llm_enabled
    if settings.upstream_enabled is not None:
        config.upstream.enabled = settings.upstream_enabled
    if settings.upstream_base_url:
        config.upstream.base_url = settings.upstream_base_url
    if settings.upstream_model:
        config.upstream.model = settings.upstream_model
    if settings.upstream_api_key:
        config.upstream.api_key = settings.upstream_api_key
    if settings.upstream_timeout_seconds is not None:
        config.upstream.timeout_seconds = settings.upstream_timeout_seconds
    if settings.vision_evaluator_enabled is not None:
        config.vision_evaluator.enabled = settings.vision_evaluator_enabled
    if settings.mcp_enabled is not None:
        config.auth.mcp_enabled = settings.mcp_enabled
    if settings.mcp_admin_key:
        config.auth.mcp_admin_key = settings.mcp_admin_key
    if settings.mcp_admin_write is not None:
        config.auth.mcp_admin_write = settings.mcp_admin_write
    if settings.vision_evaluator_base_url:
        config.vision_evaluator.base_url = settings.vision_evaluator_base_url
    if settings.vision_evaluator_model:
        config.vision_evaluator.model = settings.vision_evaluator_model
    if settings.vision_evaluator_timeout_seconds is not None:
        config.vision_evaluator.timeout_seconds = settings.vision_evaluator_timeout_seconds
    if settings.user_group_resolver_enabled is not None:
        config.user_group_resolver.enabled = settings.user_group_resolver_enabled
    if settings.user_group_resolver_provider:
        config.user_group_resolver.provider = settings.user_group_resolver_provider
    if settings.user_group_resolver_cache_ttl_seconds is not None:
        config.user_group_resolver.cache_ttl_seconds = settings.user_group_resolver_cache_ttl_seconds
    if settings.user_group_resolver_keycloak_base_url:
        config.user_group_resolver.keycloak.base_url = settings.user_group_resolver_keycloak_base_url
    if settings.user_group_resolver_keycloak_realm:
        config.user_group_resolver.keycloak.realm = settings.user_group_resolver_keycloak_realm
    if settings.user_group_resolver_keycloak_client_id:
        config.user_group_resolver.keycloak.client_id = settings.user_group_resolver_keycloak_client_id
    if settings.user_group_resolver_keycloak_client_secret:
        config.user_group_resolver.keycloak.client_secret = settings.user_group_resolver_keycloak_client_secret
    if settings.user_group_resolver_keycloak_verify_ssl is not None:
        config.user_group_resolver.keycloak.verify_ssl = settings.user_group_resolver_keycloak_verify_ssl
    if settings.syslog_enabled is not None:
        config.syslog.enabled = settings.syslog_enabled
    if settings.syslog_protocol:
        config.syslog.protocol = settings.syslog_protocol
    if settings.syslog_host:
        config.syslog.host = settings.syslog_host
    if settings.syslog_port is not None:
        config.syslog.port = settings.syslog_port
    if settings.syslog_send_interval_seconds is not None:
        config.syslog.send_interval_seconds = settings.syslog_send_interval_seconds
    if settings.local_auth_enabled is not None:
        config.auth.local_auth_enabled = settings.local_auth_enabled
    if settings.keycloak_admin_enabled is not None:
        config.auth.keycloak_admin.enabled = settings.keycloak_admin_enabled
    if settings.keycloak_admin_base_url:
        config.auth.keycloak_admin.base_url = settings.keycloak_admin_base_url
    if settings.keycloak_admin_realm:
        config.auth.keycloak_admin.realm = settings.keycloak_admin_realm
    if settings.keycloak_admin_client_id:
        config.auth.keycloak_admin.client_id = settings.keycloak_admin_client_id
    if settings.keycloak_admin_client_secret:
        config.auth.keycloak_admin.client_secret = settings.keycloak_admin_client_secret
    if settings.keycloak_admin_verify_ssl is not None:
        config.auth.keycloak_admin.verify_ssl = settings.keycloak_admin_verify_ssl
