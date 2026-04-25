from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


SITE_STORE_PATH = "data/sites.json"

DEFAULT_SITES: list[dict] = [
    {
        "id": "chatgpt",
        "name": "ChatGPT",
        "url_pattern": "chatgpt.com",
        "endpoint_contains": "/conversation",
        "body_format": "json",
        "prompt_extraction": "chatgpt_parts",
        "prompt_field": "messages",
        "prompt_user_key": "",
        "prompt_message_key": "",
        "enabled": True,
    },
    {
        "id": "asksage",
        "name": "Ask Sage",
        "url_pattern": "asksage.ai",
        "endpoint_contains": "/server/query",
        "body_format": "formdata",
        "prompt_extraction": "json_array_last_user",
        "prompt_field": "message",
        "prompt_user_key": "me",
        "prompt_message_key": "message",
        "enabled": True,
    },
    {
        "id": "gemini",
        "name": "Google Gemini",
        "url_pattern": "gemini.google.com",
        "endpoint_contains": "StreamGenerate",
        "body_format": "formdata",
        "prompt_extraction": "json_array_last_user",
        "prompt_field": "f.req",
        "prompt_user_key": "user",
        "prompt_message_key": "text",
        "enabled": True,
    },
    {
        "id": "claude",
        "name": "Claude",
        "url_pattern": "claude.ai",
        "endpoint_contains": "/completion",
        "body_format": "json",
        "prompt_extraction": "direct",
        "prompt_field": "prompt",
        "prompt_user_key": "",
        "prompt_message_key": "",
        "enabled": True,
    },
]


class SiteConfig(BaseModel):
    id: str
    name: str
    url_pattern: str
    endpoint_contains: str
    body_format: str = "json"
    prompt_extraction: str = "direct"
    prompt_field: str = "message"
    prompt_user_key: str = "me"
    prompt_message_key: str = "message"
    enabled: bool = True


class SiteStore(BaseModel):
    sites: list[SiteConfig] = Field(default_factory=list)


def _ensure_defaults(store: SiteStore) -> bool:
    """Merge default sites into the store if not already present. Returns True if any were added."""
    existing_ids = {s.id for s in store.sites}
    added = False
    for default in DEFAULT_SITES:
        if default["id"] not in existing_ids:
            store.sites.append(SiteConfig(**default))
            added = True
    return added


def load_site_store(path: Optional[str] = None) -> SiteStore:
    store_path = Path(path or SITE_STORE_PATH)
    if not store_path.exists():
        store = SiteStore()
        _ensure_defaults(store)
        save_site_store(store, path)
        return store
    with store_path.open("r", encoding="utf-8") as f:
        store = SiteStore.model_validate(json.load(f))
    if _ensure_defaults(store):
        save_site_store(store, path)
    return store


def save_site_store(store: SiteStore, path: Optional[str] = None) -> None:
    store_path = Path(path or SITE_STORE_PATH)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("w", encoding="utf-8") as f:
        json.dump(store.model_dump(), f, indent=2, sort_keys=True)
        f.write("\n")


def list_sites(path: Optional[str] = None) -> list[SiteConfig]:
    return load_site_store(path).sites


def get_site(site_id: str, path: Optional[str] = None) -> Optional[SiteConfig]:
    for site in list_sites(path):
        if site.id == site_id:
            return site
    return None


def create_site(site: SiteConfig, path: Optional[str] = None) -> SiteConfig:
    if get_site(site.id, path):
        raise ValueError(f"Site '{site.id}' already exists.")
    store = load_site_store(path)
    store.sites.append(site)
    save_site_store(store, path)
    return site


def update_site(site: SiteConfig, path: Optional[str] = None) -> None:
    store = load_site_store(path)
    updated = []
    found = False
    for existing in store.sites:
        if existing.id == site.id:
            updated.append(site)
            found = True
        else:
            updated.append(existing)
    if not found:
        raise ValueError(f"Site '{site.id}' not found.")
    store.sites = updated
    save_site_store(store, path)


def delete_site(site_id: str, path: Optional[str] = None) -> None:
    store = load_site_store(path)
    original = len(store.sites)
    store.sites = [s for s in store.sites if s.id != site_id]
    if len(store.sites) == original:
        raise ValueError(f"Site '{site_id}' not found.")
    save_site_store(store, path)
