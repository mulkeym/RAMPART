from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


MAPPING_STORE_PATH = "data/group_mappings.json"


class GroupMapping(BaseModel):
    id: str = ""
    external_group: str = ""
    rampart_group_id: str = ""
    enabled: bool = True


class MappingStore(BaseModel):
    mappings: list[GroupMapping] = Field(default_factory=list)


def _generate_id() -> str:
    return "map-" + secrets.token_hex(6)


def _load(path: Optional[str] = None) -> MappingStore:
    store_path = Path(path or MAPPING_STORE_PATH)
    if not store_path.exists():
        return MappingStore()
    with store_path.open("r", encoding="utf-8") as f:
        return MappingStore.model_validate(json.load(f))


def _save(store: MappingStore, path: Optional[str] = None) -> None:
    from rampart.app.file_utils import locked_atomic_write_json
    store_path = Path(path or MAPPING_STORE_PATH)
    locked_atomic_write_json(store_path, store.model_dump())


def list_mappings(path: Optional[str] = None) -> list[GroupMapping]:
    return _load(path).mappings


def get_mapping(mapping_id: str, path: Optional[str] = None) -> Optional[GroupMapping]:
    for m in list_mappings(path):
        if m.id == mapping_id:
            return m
    return None


def create_mapping(external_group: str, rampart_group_id: str, enabled: bool = True, path: Optional[str] = None) -> GroupMapping:
    mapping = GroupMapping(id=_generate_id(), external_group=external_group, rampart_group_id=rampart_group_id, enabled=enabled)
    store = _load(path)
    store.mappings.append(mapping)
    _save(store, path)
    return mapping


def update_mapping(mapping: GroupMapping, path: Optional[str] = None) -> None:
    store = _load(path)
    found = False
    updated = []
    for existing in store.mappings:
        if existing.id == mapping.id:
            updated.append(mapping)
            found = True
        else:
            updated.append(existing)
    if not found:
        raise ValueError(f"Mapping '{mapping.id}' not found.")
    store.mappings = updated
    _save(store, path)


def delete_mapping(mapping_id: str, path: Optional[str] = None) -> None:
    store = _load(path)
    original = len(store.mappings)
    store.mappings = [m for m in store.mappings if m.id != mapping_id]
    if len(store.mappings) == original:
        raise ValueError(f"Mapping '{mapping_id}' not found.")
    _save(store, path)
