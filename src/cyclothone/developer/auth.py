from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable

from fastapi import Header, HTTPException

from cyclothone.developer.api_keys import authenticate_api_key
from cyclothone.developer.crypto import hash_secret
from cyclothone.storage.supabase_client import supabase


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
        identity = await authenticate_api_key(x_api_key.strip())
        if identity:
            return DeveloperPrincipal(identity["tenant_id"], identity["app_id"], frozenset(identity["scopes"]), "api_key")

    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() == "bearer" and credentials.strip():
            token = credentials.strip()
            row = await supabase.select_one("oauth_access_tokens", "app_id,scope,expires_at,revoked_at", token_hash=hash_secret(token))
            if row and not row.get("revoked_at"):
                try:
                    expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
                except (TypeError, ValueError):
                    expires_at = datetime.min.replace(tzinfo=UTC)
                if expires_at > datetime.now(UTC):
                    app = await supabase.select_one("developer_apps", "tenant_id,active", id=row["app_id"])
                    if app and app["active"]:
                        return DeveloperPrincipal(str(app["tenant_id"]), str(row["app_id"]), frozenset(row.get("scope") or []), "oauth")

    raise HTTPException(401, {"error": "invalid_token"}, headers={"WWW-Authenticate": "Bearer"})
