from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any

from cyclothone.developer.crypto import hash_secret
from cyclothone.storage.supabase_client import supabase


async def create_api_key(app_id: str, scopes: list[str], expires_at: str | None = None) -> dict[str, str]:
    app = await supabase.select_one("developer_apps", "id,allowed_scopes,active", id=app_id)
    allowed = set(app.get("allowed_scopes") or []) if app else set()
    if not app or not app["active"] or not set(scopes).issubset(allowed):
        raise ValueError("invalid_scope")
    secret = "snk_" + secrets.token_urlsafe(36)
    prefix = secret[:12]
    row = await supabase.insert_one("developer_api_keys", {"app_id": app_id, "key_prefix": prefix, "key_hash": hash_secret(secret), "scopes": sorted(set(scopes)), "expires_at": expires_at})
    return {"id": str(row["id"]), "key": secret, "key_prefix": prefix}


async def authenticate_api_key(raw_key: str) -> dict[str, Any] | None:
    raw_key = raw_key.strip()
    if not raw_key.startswith("snk_") or len(raw_key) < 16:
        return None
    row = await supabase.select_one("developer_api_keys", "id,app_id,scopes,active,expires_at,revoked_at", key_hash=hash_secret(raw_key))
    if not row or not row["active"] or row.get("revoked_at"):
        return None
    if row.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        if expires_at <= datetime.now(UTC):
            return None
    app = await supabase.select_one("developer_apps", "tenant_id,active", id=row["app_id"])
    if not app or not app["active"]:
        return None
    return {"app_id": str(row["app_id"]), "tenant_id": str(app["tenant_id"]), "scopes": tuple(row.get("scopes") or [])}
