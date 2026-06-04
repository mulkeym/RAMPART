from __future__ import annotations

import httpx

from rampart.app.group_providers import GroupProvider


class KeycloakGroupProvider(GroupProvider):
    def __init__(self, base_url: str, realm: str, client_id: str, client_secret: str, verify_ssl: bool = True, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    async def lookup_groups(self, user_id: str) -> list[str]:
        token = await self._get_service_token()
        admin_base = f"{self.base_url}/admin/realms/{self.realm}"
        headers = {"Authorization": f"Bearer {token}"}
        client = self._get_client()
        # Try email first, then username
        kc_user = await self._find_user(client, admin_base, headers, user_id)
        if not kc_user:
            return []
        kc_user_id = kc_user["id"]
        resp = await client.get(f"{admin_base}/users/{kc_user_id}/groups", headers=headers)
        resp.raise_for_status()
        return [g["name"] for g in resp.json() if isinstance(g, dict) and "name" in g]

    async def _find_user(self, client: httpx.AsyncClient, admin_base: str, headers: dict, user_id: str):
        """Find a Keycloak user by email or username."""
        # Try email match first (most common — OpenAI user field is typically email)
        resp = await client.get(f"{admin_base}/users", params={"email": user_id, "exact": "true"}, headers=headers)
        resp.raise_for_status()
        users = resp.json()
        if users:
            return users[0]
        # Fall back to username match
        resp = await client.get(f"{admin_base}/users", params={"username": user_id, "exact": "true"}, headers=headers)
        resp.raise_for_status()
        users = resp.json()
        if users:
            return users[0]
        # Try general search as last resort (partial match)
        resp = await client.get(f"{admin_base}/users", params={"search": user_id}, headers=headers)
        resp.raise_for_status()
        users = resp.json()
        return users[0] if users else None

    async def list_realm_groups(self) -> list[str]:
        """Fetch all groups defined in the Keycloak realm."""
        token = await self._get_service_token()
        admin_base = f"{self.base_url}/admin/realms/{self.realm}"
        headers = {"Authorization": f"Bearer {token}"}
        client = self._get_client()
        resp = await client.get(f"{admin_base}/groups", params={"max": 1000}, headers=headers)
        resp.raise_for_status()
        groups = []
        for g in resp.json():
            if isinstance(g, dict) and "name" in g:
                groups.append(g["name"])
                # Include subgroups
                for sub in g.get("subGroups", []):
                    if isinstance(sub, dict) and "name" in sub:
                        groups.append(sub["name"])
        return sorted(groups)

    async def _get_service_token(self) -> str:
        token_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        client = self._get_client()
        resp = await client.post(token_url, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        })
        resp.raise_for_status()
        return resp.json()["access_token"]
