from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable

from fastapi import Header, HTTPException

from sentinel.developer.api_keys import authenticate_api_key
from sentinel.developer.crypto import hash_secret
from sentinel.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class DeveloperPrincipal:
    tenant_id: str
    app_id: str
    scopes: frozenset[str]
    auth_type: str

    def require(self, required: Iterable[str]) -> None:
        missing = [scope for scope in required if scope not in self.scopes]
        if missing:
            raise HTTPException(403, {"error": "insufficient_scope", "missing": missing})


async def authenticate_request(authorization: str | None = Header(None), x_api_key: str | None = Header(None)) -> DeveloperPrincipal:
    if x_api_key:
        identity = await authenticate_api_key(x_api_key)
        if identity:
            return DeveloperPrincipal(identity["tenant_id"], identity["app_id"], frozenset(identity["scopes"]), "api_key")
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        row = await supabase.select_one("oauth_access_tokens", "app_id,scope,expires_at,revoked_at", token_hash=hash_secret(token))
        if row and not row.get("revoked_at") and datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00")) > datetime.now(UTC):
            app = await supabase.select_one("developer_apps", "tenant_id,active", id=row["app_id"])
            if app and app["active"]:
                return DeveloperPrincipal(str(app["tenant_id"]), str(row["app_id"]), frozenset(row.get("scope") or []), "oauth")
    raise HTTPException(401, {"error": "invalid_token"}, headers={"WWW-Authenticate": "Bearer"})
