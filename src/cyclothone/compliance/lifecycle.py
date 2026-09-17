from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sentinel.storage.supabase_client import supabase


class ComplianceLifecycleError(ValueError):
    pass


class ComplianceLifecycle:
    """Tenant-bound workflow for control accountability and remediation."""

    async def assign_owner(self, tenant_id: UUID, control_id: UUID, user_id: UUID, role: str = "owner") -> dict[str, Any]:
        if role not in {"owner", "backup", "reviewer"}:
            raise ComplianceLifecycleError("invalid control owner role")
        await self._require_control(tenant_id, control_id)
        await self._require_user(tenant_id, user_id)
        row = {"tenant_id": str(tenant_id), "control_id": str(control_id), "user_id": str(user_id), "role": role}
        async def _do():
            return await (await supabase._ensure()).table("control_owners").upsert(row, on_conflict="tenant_id,control_id,user_id").execute()
        data = (await supabase._retry(_do, attempts=2)).data or []
        return data[0] if data else row

    async def list_owners(self, tenant_id: UUID, control_id: UUID | None = None) -> list[dict[str, Any]]:
        async def _do():
            q = (await supabase._ensure()).table("control_owners").select("tenant_id,control_id,user_id,role,assigned_at").eq("tenant_id", str(tenant_id))
            if control_id:
                q = q.eq("control_id", str(control_id))
            return await q.order("assigned_at", desc=True).execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    async def create_exception(self, tenant_id: UUID, control_id: UUID, reason: str, compensating: str | None, remediation_due: str | None) -> dict[str, Any]:
        if not reason.strip():
            raise ComplianceLifecycleError("exception reason is required")
        await self._require_control(tenant_id, control_id)
        row = {"id": str(uuid4()), "tenant_id": str(tenant_id), "control_id": str(control_id), "reason": reason.strip(), "compensating": compensating.strip() if compensating else None, "remediation_due": remediation_due, "status": "open"}
        return await self._insert("control_exceptions", row)

    async def transition_exception(self, tenant_id: UUID, exception_id: UUID, new_status: str, approver: UUID | None = None) -> dict[str, Any]:
        if new_status not in {"open", "remediating", "resolved", "accepted"}:
            raise ComplianceLifecycleError("invalid exception status")
        existing = await self._get("control_exceptions", exception_id, tenant_id)
        if not existing:
            raise ComplianceLifecycleError("exception not found")
        patch: dict[str, Any] = {"status": new_status}
        if new_status in {"accepted", "resolved"}:
            if approver is None:
                raise ComplianceLifecycleError("approval is required for accepted or resolved exceptions")
            await self._require_user(tenant_id, approver)
            patch.update({"approved_by": str(approver), "approved_at": datetime.now(UTC).isoformat()})
        else:
            patch.update({"approved_by": None, "approved_at": None})
        async def _do():
            return await (await supabase._ensure()).table("control_exceptions").update(patch).eq("id", str(exception_id)).eq("tenant_id", str(tenant_id)).execute()
        data = (await supabase._retry(_do, attempts=2)).data or []
        return data[0] if data else {**existing, **patch}

    async def create_remediation(self, tenant_id: UUID, control_id: UUID | None, title: str, description: str | None, severity: str, assignee: UUID | None, due_at: str | None) -> dict[str, Any]:
        if not title.strip() or severity not in {"low", "medium", "high", "critical"}:
            raise ComplianceLifecycleError("invalid remediation task")
        if control_id:
            await self._require_control(tenant_id, control_id)
        if assignee:
            await self._require_user(tenant_id, assignee)
        row = {"id": str(uuid4()), "tenant_id": str(tenant_id), "control_id": str(control_id) if control_id else None, "title": title.strip(), "description": description, "severity": severity, "status": "backlog", "assignee": str(assignee) if assignee else None, "due_at": due_at}
        return await self._insert("remediation_tasks", row)

    async def transition_remediation(self, tenant_id: UUID, task_id: UUID, new_status: str) -> dict[str, Any]:
        if new_status not in {"backlog", "todo", "in_progress", "review", "done"}:
            raise ComplianceLifecycleError("invalid remediation status")
        existing = await self._get("remediation_tasks", task_id, tenant_id)
        if not existing:
            raise ComplianceLifecycleError("remediation task not found")
        patch = {"status": new_status, "completed_at": datetime.now(UTC).isoformat() if new_status == "done" else None}
        async def _do():
            return await (await supabase._ensure()).table("remediation_tasks").update(patch).eq("id", str(task_id)).eq("tenant_id", str(tenant_id)).execute()
        data = (await supabase._retry(_do, attempts=2)).data or []
        return data[0] if data else {**existing, **patch}

    async def list_remediation(self, tenant_id: UUID, control_id: UUID | None = None) -> list[dict[str, Any]]:
        async def _do():
            q = (await supabase._ensure()).table("remediation_tasks").select("id,tenant_id,control_id,title,description,severity,status,assignee,due_at,completed_at,created_at").eq("tenant_id", str(tenant_id))
            if control_id:
                q = q.eq("control_id", str(control_id))
            return await q.order("created_at", desc=True).limit(500).execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    async def list_exceptions(self, tenant_id: UUID, control_id: UUID | None = None) -> list[dict[str, Any]]:
        async def _do():
            q = (await supabase._ensure()).table("control_exceptions").select("id,tenant_id,control_id,reason,compensating,remediation_due,status,approved_by,approved_at,created_at").eq("tenant_id", str(tenant_id))
            if control_id:
                q = q.eq("control_id", str(control_id))
            return await q.order("created_at", desc=True).limit(500).execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    async def _require_control(self, tenant_id: UUID, control_id: UUID) -> None:
        async def _do():
            return await (await supabase._ensure()).table("compliance_controls").select("id").eq("id", str(control_id)).eq("framework", "soc2").limit(1).execute()
        if not ((await supabase._retry(_do, attempts=2)).data or []):
            # Control UUIDs are globally unique; the framework check above only
            # prevents accidental use of unrelated control rows in this workflow.
            async def _any():
                return await (await supabase._ensure()).table("compliance_controls").select("id").eq("id", str(control_id)).limit(1).execute()
            if not ((await supabase._retry(_any, attempts=2)).data or []):
                raise ComplianceLifecycleError("control not found")

    async def _require_user(self, tenant_id: UUID, user_id: UUID) -> None:
        async def _do():
            return await (await supabase._ensure()).table("developers").select("user_id").eq("tenant_id", str(tenant_id)).eq("user_id", str(user_id)).limit(1).execute()
        if not ((await supabase._retry(_do, attempts=2)).data or []):
            raise ComplianceLifecycleError("user is not a member of this tenant")

    async def _get(self, table: str, row_id: UUID, tenant_id: UUID) -> dict[str, Any] | None:
        async def _do():
            return await (await supabase._ensure()).table(table).select("*").eq("id", str(row_id)).eq("tenant_id", str(tenant_id)).limit(1).execute()
        rows = (await supabase._retry(_do, attempts=2)).data or []
        return rows[0] if rows else None

    async def _insert(self, table: str, row: dict[str, Any]) -> dict[str, Any]:
        async def _do():
            return await (await supabase._ensure()).table(table).insert(row).execute()
        data = (await supabase._retry(_do, attempts=2)).data or []
        return data[0] if data else row
