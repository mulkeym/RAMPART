from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


SITE_STORE_PATH = "data/sites.json"


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


def load_site_store(path: Optional[str] = None) -> SiteStore:
    store_path = Path(path or SITE_STORE_PATH)
    if not store_path.exists():
        return SiteStore()
    with store_path.open("r", encoding="utf-8") as f:
        return SiteStore.model_validate(json.load(f))


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
