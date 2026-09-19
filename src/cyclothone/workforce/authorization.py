from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from fastapi import HTTPException, status

from cyclothone.storage.supabase_client import supabase
from cyclothone.workforce.auth import WorkforcePrincipal


@dataclass(frozen=True, slots=True)
class WorkforceAuthorization:
    allowed: bool
    employee_id: str
    reason: str


def _uuid_or_none(value: str | UUID | None) -> str | None:
    if value is None:
        return None
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid workforce authorization scope",
        ) from exc


async def authorize_workforce(
    principal: WorkforcePrincipal,
    permission_key: str,
    *,
    tenant_id: str | UUID | None = None,
    project_id: str | UUID | None = None,
    resource_id: str | UUID | None = None,
) -> WorkforceAuthorization:
    """Single application bridge to the canonical workforce.authorize boundary."""
    if not permission_key or not permission_key.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="permission_key is required",
        )

    tenant = _uuid_or_none(tenant_id)
    project = _uuid_or_none(project_id)
    resource = _uuid_or_none(resource_id)

    client = await supabase._ensure()
    try:
        result = await client.schema("workforce").rpc(
            "authorize",
            {
                "p_user_id": principal.user_id,
                "p_permission_key": permission_key.strip(),
                "p_tenant_id": tenant,
                "p_project_id": project,
                "p_resource_id": resource,
            },
        ).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="workforce authorization unavailable",
        ) from exc

    rows = result.data or []
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce authorization denied",
        )

    row = rows[0]
    employee_id = str(row.get("employee_id") or "")
    reason = str(row.get("reason") or "authorization_denied")
    allowed = bool(row.get("allowed"))

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "workforce_authorization_denied", "reason": reason},
        )

    if employee_id != principal.employee_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="workforce principal mismatch",
        )

    return WorkforceAuthorization(
        allowed=True,
        employee_id=employee_id,
        reason=reason,
    )
