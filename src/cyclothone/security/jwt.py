from __future__ import annotations

from dataclasses import dataclass
from fastapi import Header, HTTPException

from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: str
    tenant_id: str
    role: str = "member"


async def authenticate_user(authorization: str | None) -> Principal:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "bearer token required", headers={"WWW-Authenticate": "Bearer"})

    client = await supabase._ensure()
    try:
        response = await client.auth.get_user(token.strip())
    except Exception as exc:
        raise HTTPException(401, "invalid bearer token", headers={"WWW-Authenticate": "Bearer"}) from exc

    user = getattr(response, "user", None)
    user_id = getattr(user, "id", None)
    if not user_id:
        raise HTTPException(401, "invalid user identity", headers={"WWW-Authenticate": "Bearer"})

    try:
        row_response = await (
            client.table("developers")
            .select("tenant_id")
            .eq("user_id", str(user_id))
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(503, "identity lookup unavailable") from exc

    rows = row_response.data or []
    if not rows:
        raise HTTPException(403, "tenant identity is not provisioned")

    return Principal(user_id=str(user_id), tenant_id=str(rows[0]["tenant_id"]))
