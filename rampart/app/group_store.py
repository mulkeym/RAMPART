from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


GROUP_STORE_PATH = "data/groups.json"


class GroupRecord(BaseModel):
    id: str
    name: str
    enrollment_key: str
    policy_ids: list[str] = Field(default_factory=list)
    enabled: bool = True
    created_at: str = ""


class GroupStore(BaseModel):
    groups: list[GroupRecord] = Field(default_factory=list)


def generate_enrollment_key() -> str:
    return "grp_" + secrets.token_urlsafe(24)


def load_group_store(path: Optional[str] = None) -> GroupStore:
    store_path = Path(path or GROUP_STORE_PATH)
    if not store_path.exists():
        return GroupStore()
    with store_path.open("r", encoding="utf-8") as f:
        return GroupStore.model_validate(json.load(f))


def save_group_store(store: GroupStore, path: Optional[str] = None) -> None:
    store_path = Path(path or GROUP_STORE_PATH)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("w", encoding="utf-8") as f:
        json.dump(store.model_dump(), f, indent=2, sort_keys=True)
        f.write("\n")


def list_groups(path: Optional[str] = None) -> list[GroupRecord]:
    return load_group_store(path).groups


def get_group(group_id: str, path: Optional[str] = None) -> Optional[GroupRecord]:
    for group in list_groups(path):
        if group.id == group_id:
            return group
    return None


def get_group_by_enrollment_key(key: str, path: Optional[str] = None) -> Optional[GroupRecord]:
    for group in list_groups(path):
        if group.enrollment_key == key and group.enabled:
            return group
    return None


def create_group(
    group_id: str,
    name: str,
    policy_ids: Optional[list[str]] = None,
    path: Optional[str] = None,
) -> GroupRecord:
    if get_group(group_id, path):
        raise ValueError(f"Group '{group_id}' already exists.")
    group = GroupRecord(
        id=group_id,
        name=name,
        enrollment_key=generate_enrollment_key(),
        policy_ids=policy_ids or [],
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    store = load_group_store(path)
    store.groups.append(group)
    save_group_store(store, path)
    return group


def update_group(group: GroupRecord, path: Optional[str] = None) -> None:
    store = load_group_store(path)
    updated = []
    found = False
    for existing in store.groups:
        if existing.id == group.id:
            updated.append(group)
            found = True
        else:
            updated.append(existing)
    if not found:
        raise ValueError(f"Group '{group.id}' not found.")
    store.groups = updated
    save_group_store(store, path)


def delete_group(group_id: str, path: Optional[str] = None) -> None:
    store = load_group_store(path)
    original = len(store.groups)
    store.groups = [g for g in store.groups if g.id != group_id]
    if len(store.groups) == original:
        raise ValueError(f"Group '{group_id}' not found.")
    save_group_store(store, path)


def regenerate_enrollment_key(group_id: str, path: Optional[str] = None) -> GroupRecord:
    group = get_group(group_id, path)
    if not group:
        raise ValueError(f"Group '{group_id}' not found.")
    group.enrollment_key = generate_enrollment_key()
    update_group(group, path)
    return group
