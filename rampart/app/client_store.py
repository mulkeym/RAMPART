from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from rampart.app.config import get_config
from rampart.app.security.passwords import hash_password, verify_password
from rampart.app.tracking import ClientContext

KEY_PREFIX = "rmp_live_"


class ClientRecord(BaseModel):
    id: str
    customer: str
    app_name: str
    owner_name: str = ""
    owner_email: str = ""
    team: str = ""
    environment: str = "production"
    upstream_base_url: str = ""
    upstream_model: str = ""
    upstream_api_key: str = ""
    upstream_timeout_seconds: Optional[float] = None
    notes: str = ""
    policy_ids: list[str] = Field(default_factory=list)
    enabled: bool = True
    key_hash: str
    created_at: str
    last_used_at: Optional[str] = None


class ClientStore(BaseModel):
    clients: list[ClientRecord] = Field(default_factory=list)


class CreatedClient(BaseModel):
    client: ClientRecord
    api_key: str


def generate_api_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def load_client_store(path: Optional[str] = None) -> ClientStore:
    store_path = Path(path or get_config().clients.path)
    if not store_path.exists():
        return ClientStore()
    with store_path.open("r", encoding="utf-8") as store_file:
        return ClientStore.model_validate(json.load(store_file))


def save_client_store(store: ClientStore, path: Optional[str] = None) -> None:
    store_path = Path(path or get_config().clients.path)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("w", encoding="utf-8") as store_file:
        json.dump(store.model_dump(), store_file, indent=2, sort_keys=True)
        store_file.write("\n")


def list_clients(path: Optional[str] = None) -> list[ClientRecord]:
    return load_client_store(path).clients


def get_client(client_id: str, path: Optional[str] = None) -> Optional[ClientRecord]:
    for client in list_clients(path):
        if client.id == client_id:
            return client
    return None


def create_client(
    client_id: str,
    customer: str,
    app_name: str,
    owner_name: str = "",
    owner_email: str = "",
    team: str = "",
    environment: str = "production",
    upstream_base_url: str = "",
    upstream_model: str = "",
    upstream_api_key: str = "",
    upstream_timeout_seconds: Optional[float] = None,
    notes: str = "",
    policy_ids: Optional[list[str]] = None,
    path: Optional[str] = None,
) -> CreatedClient:
    if get_client(client_id, path):
        raise ValueError(f"Client '{client_id}' already exists.")
    api_key = generate_api_key()
    client = ClientRecord(
        id=client_id,
        customer=customer,
        app_name=app_name,
        owner_name=owner_name,
        owner_email=owner_email,
        team=team,
        environment=environment,
        upstream_base_url=upstream_base_url,
        upstream_model=upstream_model,
        upstream_api_key=upstream_api_key,
        upstream_timeout_seconds=upstream_timeout_seconds,
        notes=notes,
        policy_ids=policy_ids or [],
        key_hash=hash_password(api_key),
        created_at=_now(),
    )
    store = load_client_store(path)
    store.clients.append(client)
    save_client_store(store, path)
    return CreatedClient(client=client, api_key=api_key)


def update_client(client: ClientRecord, path: Optional[str] = None) -> None:
    store = load_client_store(path)
    updated = []
    found = False
    for existing in store.clients:
        if existing.id == client.id:
            updated.append(client)
            found = True
        else:
            updated.append(existing)
    if not found:
        raise ValueError(f"Client '{client.id}' was not found.")
    store.clients = updated
    save_client_store(store, path)


def delete_client(client_id: str, path: Optional[str] = None) -> None:
    store = load_client_store(path)
    original_count = len(store.clients)
    store.clients = [c for c in store.clients if c.id != client_id]
    if len(store.clients) == original_count:
        raise ValueError(f"Client '{client_id}' was not found.")
    save_client_store(store, path)


def set_client_enabled(client_id: str, enabled: bool, path: Optional[str] = None) -> None:
    client = get_client(client_id, path)
    if not client:
        raise ValueError(f"Client '{client_id}' was not found.")
    client.enabled = enabled
    update_client(client, path)


def rotate_client_key(client_id: str, path: Optional[str] = None) -> CreatedClient:
    client = get_client(client_id, path)
    if not client:
        raise ValueError(f"Client '{client_id}' was not found.")
    api_key = generate_api_key()
    client.key_hash = hash_password(api_key)
    update_client(client, path)
    return CreatedClient(client=client, api_key=api_key)


def resolve_client_from_api_key(api_key: Optional[str], path: Optional[str] = None) -> Optional[ClientRecord]:
    if not api_key:
        return None
    token = _strip_bearer(api_key)
    for client in list_clients(path):
        if client.enabled and verify_password(token, client.key_hash):
            client.last_used_at = _now()
            update_client(client, path)
            return client
    return None


def client_context_from_record(client: Optional[ClientRecord], fallback: ClientContext) -> ClientContext:
    if client is None:
        return fallback
    owner = client.owner_email or client.owner_name or None
    return ClientContext(customer=client.customer, client_id=client.id, owner=owner, request_id=fallback.request_id)


def _strip_bearer(value: str) -> str:
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return value.strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
