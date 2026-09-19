from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Header, HTTPException, status

from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class WorkforcePrincipal:
    user_id: str
    employee_id: str
    tenant_id: str | None
    department_id: str | None

    def require_active(self) -> None:
        if not self.employee_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="workforce identity is not active")


async def authenticate_workforce_request(
    authorization: str | None = Header(None),
) -> WorkforcePrincipal:
    """
    Authenticate a workforce request using Supabase Auth's server-side
    get_user validation. Never treats a JWT payload as trusted by itself.
    """
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="workforce bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client = await supabase._ensure()
    try:
        response = await client.auth.get_user(token.strip())
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid workforce token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = getattr(response, "user", None)
    user_id = getattr(user, "id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid workforce identity",
            headers={"WWW-Authenticate": "Bearer"},
        )

    row = await supabase.select_one(
        "employees",
        "id,user_id,status,tenant_id,department_id",
        user_id=str(user_id),
    )

    if not row or row.get("status") != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce identity is not active",
        )

    return WorkforcePrincipal(
        user_id=str(user_id),
        employee_id=str(row["id"]),
        tenant_id=str(row["tenant_id"]) if row.get("tenant_id") else None,
        department_id=str(row["department_id"]) if row.get("department_id") else None,
    )
