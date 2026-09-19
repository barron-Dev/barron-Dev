from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class WorkforcePrincipal:
    user_id: str
    employee_id: str
    department_id: str | None

    def require_active(self) -> None:
        if not self.employee_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="workforce identity is not active")


async def authenticate_workforce_request(
    authorization: str | None = Header(None),
) -> WorkforcePrincipal:
    """Authenticate Supabase Auth identity, then resolve private workforce authority."""
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

    try:
        response = await (
            client.schema("workforce")
            .table("employees")
            .select("id,user_id,status,department_id")
            .eq("user_id", str(user_id))
            .eq("status", "active")
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce identity lookup unavailable",
        ) from exc

    rows = response.data or []
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce identity is not active",
        )

    row = rows[0]
    return WorkforcePrincipal(
        user_id=str(user_id),
        employee_id=str(row["id"]),
        department_id=str(row["department_id"]) if row.get("department_id") else None,
    )
