from __future__ import annotations

import json
from pathlib import Path
from time import time
from typing import Any, Optional

from rampart.app.group_providers import GroupProvider


class UserGroupResolver:
    def __init__(self, provider: GroupProvider, cache_path: str, cache_ttl_seconds: int = 900, cache_max_size: int = 20000):
        self.provider = provider
        self.cache_path = cache_path
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_max_size = cache_max_size
        self._cache: dict[str, dict[str, Any]] = {}
        self._dirty = False

    def check_cache(self, user_id: str) -> Optional[dict[str, Any]]:
        """Check cache without triggering a lookup. Returns dict with
        'groups', 'fetched_at', 'ttl_remaining', 'expired' or None if not cached."""
        entry = self._cache.get(user_id)
        if entry is None:
            return None
        age = time() - entry["fetched_at"]
        remaining = self.cache_ttl_seconds - age
        return {
            "groups": entry["groups"],
            "fetched_at": entry["fetched_at"],
            "age_seconds": int(age),
            "ttl_remaining": int(max(0, remaining)),
            "expired": remaining <= 0,
        }

    async def resolve(self, user_id: str) -> list[str]:
        entry = self._cache.get(user_id)
        if entry is not None and (time() - entry["fetched_at"]) < self.cache_ttl_seconds:
            return entry["groups"]
        groups = await self.provider.lookup_groups(user_id)
        self._cache[user_id] = {"groups": groups, "fetched_at": time()}
        self._dirty = True
        self._evict_if_needed()
        return groups

    def persist(self) -> None:
        if not self._dirty:
            return
        from rampart.app.file_utils import atomic_write_json
        atomic_write_json(self.cache_path, self._cache)
        self._dirty = False

    def load(self) -> None:
        path = Path(self.cache_path)
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8") as f:
                self._cache = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._cache = {}

    def _evict_if_needed(self) -> None:
        while len(self._cache) > self.cache_max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k]["fetched_at"])
            del self._cache[oldest_key]
