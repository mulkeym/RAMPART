from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from rampart.app.config import AuthConfig
from rampart.app.security.passwords import hash_password, verify_password

INITIAL_PASSWORD = "password123"


class CredentialState(BaseModel):
    username: str
    password_hash: str
    password_change_required: bool = True


def get_credential_state(config: AuthConfig) -> CredentialState:
    if config.admin_password_hash:
        return CredentialState(
            username=config.admin_username,
            password_hash=config.admin_password_hash,
            password_change_required=False,
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
    if config.admin_password_hash:
        return "Password changes are disabled when RAMPART_ADMIN_PASSWORD_HASH is configured."
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
        with path.open("r", encoding="utf-8") as state_file:
            return CredentialState.model_validate(json.load(state_file))
    state = CredentialState(
        username=config.admin_username,
        password_hash=hash_password(INITIAL_PASSWORD),
        password_change_required=True,
    )
    _save_state(config, state)
    return state


def _save_state(config: AuthConfig, state: CredentialState) -> None:
    path = Path(config.auth_state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as state_file:
        json.dump(state.model_dump(), state_file, indent=2, sort_keys=True)
        state_file.write("\n")
