from __future__ import annotations

from abc import ABC, abstractmethod


class GroupProvider(ABC):
    @abstractmethod
    async def lookup_groups(self, user_id: str) -> list[str]:
        """Return external group names for a user identifier (e.g. email)."""
