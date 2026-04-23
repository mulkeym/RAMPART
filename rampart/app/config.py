from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

import yaml
from pydantic import BaseModel, Field


class LlmEvaluatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://192.168.1.181:8081"
    model: str = "gemma4-e2b"
    timeout_seconds: float = 20.0
    fail_closed_on_error: bool = True


class FailureResponseConfig(BaseModel):
    include_sanitized_request: bool = True


class AuthConfig(BaseModel):
    admin_username: str = "admin"
    admin_password_hash: str = ""
    auth_state_path: str = "data/auth.json"
    session_secret: str = "change-me"
    session_cookie_name: str = "rampart_session"
    session_max_age_seconds: int = 28800
    secure_cookies: bool = False
    audit_log_path: str = "logs/audit.jsonl"


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
    base_url: str = "http://192.168.1.181:8081"
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


class PolicyConfig(BaseModel):
    id: str
    enabled: bool = True
    severity: str = "medium"
    category: str = "policy"
    description: str = ""
    action: str = "block"
    checks: list[CheckConfig] = Field(default_factory=list)


class AppConfig(BaseModel):
    version: int = 1
    llm_evaluator: LlmEvaluatorConfig = Field(default_factory=LlmEvaluatorConfig)
    failure_response: FailureResponseConfig = Field(default_factory=FailureResponseConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    clients: ClientStoreConfig = Field(default_factory=ClientStoreConfig)
    settings: SettingsStoreConfig = Field(default_factory=SettingsStoreConfig)
    tracking: TrackingConfig = Field(default_factory=TrackingConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    policies: list[PolicyConfig] = Field(default_factory=list)


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
    auth.admin_password_hash = os.getenv("RAMPART_ADMIN_PASSWORD_HASH", auth.admin_password_hash)
    auth.auth_state_path = os.getenv("RAMPART_AUTH_STATE", auth.auth_state_path)
    auth.session_secret = os.getenv("RAMPART_SESSION_SECRET", auth.session_secret)
    auth.audit_log_path = os.getenv("RAMPART_AUDIT_LOG", auth.audit_log_path)
    auth.secure_cookies = _env_bool("RAMPART_SECURE_COOKIES", auth.secure_cookies)
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


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _apply_local_settings(config: AppConfig) -> None:
    from rampart.app.settings_store import load_settings

    settings = load_settings(config.settings.path)
    if settings.llm_evaluator_base_url:
        config.llm_evaluator.base_url = settings.llm_evaluator_base_url
    if settings.llm_evaluator_model:
        config.llm_evaluator.model = settings.llm_evaluator_model
    if settings.llm_evaluator_timeout_seconds is not None:
        config.llm_evaluator.timeout_seconds = settings.llm_evaluator_timeout_seconds
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
