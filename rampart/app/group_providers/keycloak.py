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

    async def lookup_groups(self, user_id: str) -> list[str]:
        token = await self._get_service_token()
        admin_base = f"{self.base_url}/admin/realms/{self.realm}"
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            resp = await client.get(f"{admin_base}/users", params={"email": user_id, "exact": "true"}, headers=headers)
            resp.raise_for_status()
            users = resp.json()
            if not users:
                return []
            kc_user_id = users[0]["id"]
            resp = await client.get(f"{admin_base}/users/{kc_user_id}/groups", headers=headers)
            resp.raise_for_status()
            return [g["name"] for g in resp.json() if isinstance(g, dict) and "name" in g]

    async def _get_service_token(self) -> str:
        token_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            resp = await client.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            })
            resp.raise_for_status()
            return resp.json()["access_token"]
