from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from rampart.app.config import AuthConfig
from rampart.app.security.passwords import hash_password, verify_password

logger = logging.getLogger(__name__)

DEFAULT_PASSWORD = "admin"


class CredentialState(BaseModel):
    username: str
    password_hash: str
    password_change_required: bool = False


def get_credential_state(config: AuthConfig) -> CredentialState:
    """Resolve admin credentials. Priority:

    1. RAMPART_ADMIN_PASSWORD env var (plaintext, hashed at runtime)
    2. RAMPART_ADMIN_PASSWORD_HASH env var (pre-hashed)
    3. auth.json file (persisted from UI password change)
    4. Default: admin / admin
    """
    if config.admin_password:
        return CredentialState(
            username=config.admin_username,
            password_hash=hash_password(config.admin_password),
        )
    if config.admin_password_hash:
        return CredentialState(
            username=config.admin_username,
            password_hash=config.admin_password_hash,
        )
    return _load_or_seed_state(config)


def verify_credentials(username: str, password: str, config: AuthConfig) -> bool:
    state = get_credential_state(config)
    if username != state.username:
        return False
    return verify_password(password, state.password_hash)


def password_change_required(username: str, config: AuthConfig) -> bool:
    state = get_credential_state(config)
    return username == state.username and state.password_change_required


def change_password(username: str, current_password: str, new_password: str, config: AuthConfig) -> Optional[str]:
    if config.admin_password or config.admin_password_hash:
        return "Password changes are disabled when RAMPART_ADMIN_PASSWORD or RAMPART_ADMIN_PASSWORD_HASH is set."
    if len(new_password) < 8:
        return "New password must be at least 8 characters."
    if new_password == current_password:
        return "New password must be different from the current password."
    state = get_credential_state(config)
    if username != state.username or not verify_password(current_password, state.password_hash):
        return "Current password is incorrect."
    state.password_hash = hash_password(new_password)
    state.password_change_required = False
    _save_state(config, state)
    return None


def _load_or_seed_state(config: AuthConfig) -> CredentialState:
    path = Path(config.auth_state_path)
    if path.exists():
        try:
            with path.open("r", encoding="utf-8") as state_file:
                return CredentialState.model_validate(json.load(state_file))
        except (json.JSONDecodeError, OSError):
            logger.warning("Corrupt auth state at %s, reseeding", path)
    state = CredentialState(
        username=config.admin_username,
        password_hash=hash_password(DEFAULT_PASSWORD),
    )
    _save_state(config, state)
    return state


def _save_state(config: AuthConfig, state: CredentialState) -> None:
    from rampart.app.file_utils import atomic_write_json
    try:
        atomic_write_json(config.auth_state_path, state.model_dump())
    except OSError as exc:
        logger.error("Failed to save auth state to %s: %s", config.auth_state_path, exc)
        raise
