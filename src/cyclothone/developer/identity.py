from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class DeveloperIdentity:
    user_id: str
    tenant_id: str


async def resolve_developer(user_id: str) -> DeveloperIdentity | None:
    row = await supabase.select_one("developers", "user_id,tenant_id", user_id=user_id)
    if not row:
        return None
    return DeveloperIdentity(str(row["user_id"]), str(row["tenant_id"]))


async def app_owned_by_user(app_id: str, user_id: str) -> dict[str, Any] | None:
    return await supabase.select_one("developer_apps", "id,tenant_id,owner_user_id,name,allowed_scopes,active", id=app_id, owner_user_id=user_id)
