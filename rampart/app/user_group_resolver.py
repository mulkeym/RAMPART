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
        path = Path(self.cache_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self._cache, f, sort_keys=True)
            f.write("\n")
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
