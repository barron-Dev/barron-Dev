from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urljoin
import httpx
from cyclothone.storage.supabase_client import supabase

class ProviderUnavailable(RuntimeError):
    pass

class MobileProvider:
    def __init__(self, account: dict[str, Any]) -> None:
        self.account = account
        self.http = httpx.AsyncClient(timeout=httpx.Timeout(25.0, connect=6.0))
        self._token: tuple[str, datetime] | None = None

    async def close(self) -> None:
        await self.http.aclose()

    async def token(self) -> str:
        if self._token and self._token[1] > datetime.now(UTC) + timedelta(seconds=30):
            return self._token[0]
        ref = str(self.account.get("client_secret_ref") or "").strip()
        token_url = str(self.account.get("token_url") or "").strip()
        client_id = str(self.account.get("client_id") or "").strip()
        if not ref or not token_url or not client_id:
            raise ProviderUnavailable("provider_oauth_configuration_missing")
        secret = await self._vault(ref)
        if not secret:
            raise ProviderUnavailable("provider_credential_unavailable")
        response = await self.http.post(token_url, data={"grant_type":"client_credentials","client_id":client_id,"client_secret":secret,"scope":" ".join(self.account.get("scopes") or [])}, headers={"content-type":"application/x-www-form-urlencoded"})
        if response.status_code >= 400:
            raise ProviderUnavailable(f"provider_token_http_{response.status_code}")
        data = response.json()
        access = str(data.get("access_token") or "")
        if not access:
            raise ProviderUnavailable("provider_token_missing")
        expires = datetime.now(UTC) + timedelta(seconds=max(30, int(data.get("expires_in", 300))))
        self._token = (access, expires)
        return access

    async def call(self, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        endpoints = self.account.get("capabilities") or {}
        path = str(endpoints.get(capability) or "").strip()
        if not path:
            raise ProviderUnavailable(f"provider_capability_not_configured:{capability}")
        base = str(self.account.get("base_url") or "").strip()
        if not base:
            raise ProviderUnavailable("provider_base_url_missing")
        token = await self.token()
        url = path if path.startswith(("http://", "https://")) else urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        response = await self.http.post(url, json=payload, headers={"Authorization":f"Bearer {token}","Content-Type":"application/json","Accept":"application/json"})
        try:
            body: Any = response.json()
        except ValueError:
            body = {"raw": response.text[:2000]}
        if response.status_code >= 400:
            raise ProviderUnavailable(f"provider_http_{response.status_code}")
        return body if isinstance(body, dict) else {"data": body}

    async def _vault(self, ref: str) -> str:
        name = ref.removeprefix("vault://")
        async def load():
            client = await supabase._ensure()
            return await client.rpc("get_vault_secret", {"p_name": name}).execute()
        try:
            result = await supabase._retry(load, attempts=2)
            return result.data if isinstance(result.data, str) else ""
        except Exception:
            return ""
