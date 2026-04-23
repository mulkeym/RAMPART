from __future__ import annotations

import secrets
from typing import Optional

from fastapi import Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from rampart.app.config import AuthConfig, get_config
from rampart.app.security.credentials import password_change_required, verify_credentials


def authenticate(username: str, password: str, auth_config: Optional[AuthConfig] = None) -> bool:
    config = auth_config or get_config().auth
    if not secrets.compare_digest(username, config.admin_username):
        return False
    return verify_credentials(username, password, config)


def create_session_token(username: str, auth_config: Optional[AuthConfig] = None, password_change_pending: bool = False) -> str:
    config = auth_config or get_config().auth
    serializer = _serializer(config)
    return serializer.dumps({"username": username, "password_change_pending": password_change_pending})


def read_session_user(request: Request, auth_config: Optional[AuthConfig] = None) -> Optional[str]:
    config = auth_config or get_config().auth
    token = request.cookies.get(config.session_cookie_name)
    if not token:
        return None
    serializer = _serializer(config)
    try:
        data = serializer.loads(token, max_age=config.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    username = data.get("username") if isinstance(data, dict) else None
    if username == config.admin_username:
        return username
    return None


def session_password_change_pending(request: Request, auth_config: Optional[AuthConfig] = None) -> bool:
    config = auth_config or get_config().auth
    token = request.cookies.get(config.session_cookie_name)
    if not token:
        return False
    serializer = _serializer(config)
    try:
        data = serializer.loads(token, max_age=config.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return False
    return bool(data.get("password_change_pending")) if isinstance(data, dict) else False


def require_ui_user(request: Request) -> Optional[RedirectResponse]:
    username = read_session_user(request)
    if username and not session_password_change_pending(request):
        return None
    if username and session_password_change_pending(request):
        return RedirectResponse("/change-password", status_code=303)
    return RedirectResponse(f"/login?next={request.url.path}", status_code=303)


def set_session_cookie(response: RedirectResponse, username: str, password_change_pending: Optional[bool] = None) -> None:
    config = get_config().auth
    pending = password_change_required(username, config) if password_change_pending is None else password_change_pending
    response.set_cookie(
        config.session_cookie_name,
        create_session_token(username, config, password_change_pending=pending),
        max_age=config.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=config.secure_cookies,
    )


def clear_session_cookie(response: RedirectResponse) -> None:
    config = get_config().auth
    response.delete_cookie(config.session_cookie_name, httponly=True, samesite="lax", secure=config.secure_cookies)


def _serializer(config: AuthConfig) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.session_secret, salt="rampart-ui-session")
